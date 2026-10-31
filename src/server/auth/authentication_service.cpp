#include "authentication_service.h"

#include "session_token.h"

#include <QDateTime>
#include <QMetaObject>
#include <QRunnable>

#include <sodium.h>

#include <limits>
#include <utility>

namespace tcp_chat::auth {

/// Executes one password operation away from the server event loop.
class PasswordTask : public QRunnable {
public:
    /// Identifies the cryptographic operation to perform.
    enum class Mode {
        Hash,
        Verify,
    };

    /// Creates an auto-deleting task with an owned, wipeable password buffer.
    PasswordTask(AuthenticationService* service, quint64 operation_id, Mode mode, QByteArray password,
        QString encoded_hash, Argon2idParameters parameters)
        : service_(service)
        , operation_id_(operation_id)
        , mode_(mode)
        , password_(std::move(password))
        , encoded_hash_(std::move(encoded_hash))
        , parameters_(parameters)
    {
    }

    /// Wipes the task's password copy after the worker finishes.
    ~PasswordTask() override
    {
        if (!password_.isEmpty()) {
            sodium_memzero(password_.data(), static_cast<size_t>(password_.size()));
        }
    }

    /// Runs the hash or verification and queues only its non-password result.
    void run() override
    {
        PasswordHasher hasher(parameters_);
        if (mode_ == Mode::Hash) {
            const auto result = hasher.hash(password_);
            QMetaObject::invokeMethod(service_, [service = service_, id = operation_id_, result] { service->password_hash_finished(id, result); }, Qt::QueuedConnection);
        } else {
            const auto result = hasher.verify(password_, encoded_hash_);
            QMetaObject::invokeMethod(service_, [service = service_, id = operation_id_, result] { service->password_verify_finished(id, result); }, Qt::QueuedConnection);
        }
    }

private:
    AuthenticationService* service_;
    quint64 operation_id_;
    Mode mode_;
    QByteArray password_;
    QString encoded_hash_;
    Argon2idParameters parameters_;
};

AuthenticationService::Operation::~Operation()
{
    if (!password.isEmpty()) {
        sodium_memzero(password.data(), static_cast<size_t>(password.size()));
    }
    if (!issued_token.isEmpty()) {
        QByteArray token = issued_token.toUtf8();
        sodium_memzero(token.data(), static_cast<size_t>(token.size()));
        issued_token.fill(QChar('\0'));
    }
}

AuthenticationService::AuthenticationService(server::TlsServer* server, AuthenticationServiceOptions options, QObject* parent)
    : QObject(parent)
    , server_(server)
    , options_(std::move(options))
    , hasher_(options_.hash_parameters)
{
    hash_pool_.setMaxThreadCount(qMax(1, options_.hash_thread_count));
    worker_ = new storage::DatabaseWorker;
    worker_->moveToThread(&database_thread_);
    connect(&database_thread_, &QThread::finished, worker_, &QObject::deleteLater);
    connect(worker_, &storage::DatabaseWorker::opened, this, &AuthenticationService::database_opened);
    connect(worker_, &storage::DatabaseWorker::local_user_created, this, &AuthenticationService::local_user_created);
    connect(worker_, &storage::DatabaseWorker::local_user_found, this, &AuthenticationService::local_user_found);
    connect(worker_, &storage::DatabaseWorker::user_found, this, &AuthenticationService::user_found);
    connect(worker_, &storage::DatabaseWorker::session_created, this, &AuthenticationService::session_created);
    connect(worker_, &storage::DatabaseWorker::active_session_found, this, &AuthenticationService::active_session_found);
    connect(worker_, &storage::DatabaseWorker::session_revoked, this, &AuthenticationService::session_revoked);
    database_thread_.start();

    deadline_timer_.setSingleShot(false);
    deadline_timer_.setInterval(1000);
    connect(&deadline_timer_, &QTimer::timeout, this, &AuthenticationService::check_authentication_deadlines);
    connect(server_, &server::TlsServer::client_connected, this, &AuthenticationService::client_connected);
    connect(server_, &server::TlsServer::client_disconnected, this, &AuthenticationService::client_disconnected);
    connect(server_, &server::TlsServer::message_received, this, &AuthenticationService::message_received);
}

AuthenticationService::~AuthenticationService()
{
    shutdown();
}

std::optional<QString> AuthenticationService::start(const QString& database_path, const QString& migrations_path)
{
    if (started_) {
        return QStringLiteral("The authentication service has already been started");
    }
    if (server_ == nullptr || database_path.isEmpty() || migrations_path.isEmpty()) {
        return QStringLiteral("A server, database path, and migrations path are required");
    }
    if (options_.hash_thread_count <= 0 || options_.maximum_pending_operations <= 0
        || options_.maximum_pending_per_connection <= 0 || options_.maximum_attempts_per_connection <= 0
        || options_.maximum_attempts_per_ip <= 0 || options_.attempt_window_ms <= 0
        || options_.session_lifetime_ms <= 0 || options_.authentication_timeout_ms <= 0) {
        return QStringLiteral("Authentication limits and timeouts must be positive");
    }

    started_ = true;
    deadline_timer_.start();
    QMetaObject::invokeMethod(worker_, "open", Qt::QueuedConnection, Q_ARG(QString, database_path),
        Q_ARG(QString, migrations_path), Q_ARG(qint64, now()));
    hash_pool_.start(new PasswordTask(this, 0, PasswordTask::Mode::Hash,
        QByteArrayLiteral("tcp-chat-offline-verifier"), QString(), options_.hash_parameters));
    return std::nullopt;
}

bool AuthenticationService::is_ready() const
{
    return ready_;
}

void AuthenticationService::check_authentication_deadlines()
{
    if (shutting_down_) {
        return;
    }
    QList<quint64> expired;
    QList<quint64> expired_sessions;
    const qint64 current = now();
    for (auto it = connections_.cbegin(); it != connections_.cend(); ++it) {
        if (it->authenticated && it->session_expires_at > 0 && current >= it->session_expires_at) {
            expired_sessions.append(it.key());
        } else if (!it->authenticated && current >= it->connected_at
            && current - it->connected_at >= options_.authentication_timeout_ms) {
            expired.append(it.key());
        }
    }
    for (const quint64 id : expired_sessions) {
        cancel_connection(id);
        server_->disconnect_client(id);
        emit logged_out(id);
    }
    for (const quint64 id : expired) {
        cancel_connection(id);
        server_->disconnect_client(id);
    }
}

void AuthenticationService::database_opened(qint64 version, const storage::StorageError& error)
{
    if (error.code != storage::StorageErrorCode::None || version < 0) {
        startup_failed(error.message.isEmpty() ? QStringLiteral("Database initialization failed") : error.message);
        return;
    }
    database_ready_ = true;
    maybe_ready();
}

void AuthenticationService::local_user_created(quint64 request_id, const storage::UserRecord& user,
    const storage::StorageError& error)
{
    const auto operation = operations_.value(request_id);
    if (!operation || operation->kind != OperationKind::SignUp) {
        return;
    }
    if (error.code == storage::StorageErrorCode::Conflict) {
        fail(request_id, protocol::ErrorCode::UsernameTaken, QStringLiteral("That username is already registered"));
        return;
    }
    if (error.code != storage::StorageErrorCode::None) {
        fail(request_id, protocol::ErrorCode::Unavailable, QStringLiteral("Account storage is unavailable"));
        return;
    }
    operation->user = user;
    issue_session(operation);
}

void AuthenticationService::local_user_found(quint64 request_id, const storage::UserRecord& user,
    const storage::StorageError& error)
{
    const auto operation = operations_.value(request_id);
    if (!operation || operation->kind != OperationKind::LogIn) {
        return;
    }
    if (error.code == storage::StorageErrorCode::NotFound) {
        operation->password_hash = dummy_hash_;
    } else if (error.code != storage::StorageErrorCode::None) {
        fail(request_id, protocol::ErrorCode::Unavailable, QStringLiteral("Account storage is unavailable"));
        return;
    } else {
        operation->user          = user;
        operation->password_hash = user.password_hash.value_or(dummy_hash_);
    }
    start_verify(operation, std::move(operation->password));
}

void AuthenticationService::user_found(quint64 request_id, const storage::UserRecord& user,
    const storage::StorageError& error)
{
    const auto operation = operations_.value(request_id);
    if (!operation || operation->kind != OperationKind::Session) {
        return;
    }
    if (error.code == storage::StorageErrorCode::NotFound) {
        fail(request_id, protocol::ErrorCode::Unauthenticated, QStringLiteral("The session is no longer valid"));
        return;
    }
    if (error.code != storage::StorageErrorCode::None) {
        fail(request_id, protocol::ErrorCode::Unavailable, QStringLiteral("Account storage is unavailable"));
        return;
    }

    operation->user = user;
    protocol::AuthenticationResult result;
    result.user       = public_user(user);
    result.expires_at = operation->expires_at;
    if (const auto connection = connections_.find(operation->connection_id); connection != connections_.end()) {
        connection->authenticated      = true;
        connection->user_id            = user.id;
        connection->session_id         = operation->session_id;
        connection->session_expires_at = operation->expires_at;
    }
    const quint64 connection_id = operation->connection_id;
    const auto identity         = *result.user;
    succeed(request_id, result);
    if (connections_.contains(connection_id)) {
        emit authenticated(connection_id, identity);
    }
}

void AuthenticationService::session_created(quint64 request_id, const storage::SessionRecord& session,
    const storage::StorageError& error)
{
    const auto operation = operations_.value(request_id);
    if (!operation || (operation->kind != OperationKind::SignUp && operation->kind != OperationKind::LogIn)) {
        return;
    }
    if (error.code != storage::StorageErrorCode::None) {
        fail(request_id, protocol::ErrorCode::Unavailable, QStringLiteral("Session storage is unavailable"));
        return;
    }

    protocol::AuthenticationResult result;
    result.user          = public_user(operation->user);
    result.session_token = operation->issued_token;
    result.expires_at    = session.expires_at;
    if (const auto connection = connections_.find(operation->connection_id); connection != connections_.end()) {
        connection->authenticated      = true;
        connection->user_id            = operation->user.id;
        connection->session_id         = session.id;
        connection->session_expires_at = session.expires_at;
    }
    const quint64 connection_id = operation->connection_id;
    const auto identity         = *result.user;
    succeed(request_id, result);
    if (connections_.contains(connection_id)) {
        emit authenticated(connection_id, identity);
    }
}

void AuthenticationService::active_session_found(quint64 request_id, const storage::SessionRecord& session,
    const storage::StorageError& error)
{
    const auto operation = operations_.value(request_id);
    if (!operation) {
        return;
    }
    if (operation->kind == OperationKind::LogOut) {
        if (error.code == storage::StorageErrorCode::NotFound) {
            protocol::AuthenticationResult result;
            result.revoked = true;
            succeed(request_id, result);
        } else if (error.code != storage::StorageErrorCode::None) {
            fail(request_id, protocol::ErrorCode::Unavailable, QStringLiteral("Session storage is unavailable"));
        } else {
            operation->session_id = session.id;
            QMetaObject::invokeMethod(worker_, "revoke_session", Qt::QueuedConnection, Q_ARG(quint64, request_id),
                Q_ARG(qint64, session.id), Q_ARG(qint64, now()));
        }
        return;
    }
    if (operation->kind != OperationKind::Session) {
        return;
    }
    if (error.code == storage::StorageErrorCode::NotFound) {
        fail(request_id, protocol::ErrorCode::Unauthenticated, QStringLiteral("The session is no longer valid"));
        return;
    }
    if (error.code != storage::StorageErrorCode::None) {
        fail(request_id, protocol::ErrorCode::Unavailable, QStringLiteral("Session storage is unavailable"));
        return;
    }
    operation->session_id = session.id;
    operation->expires_at = session.expires_at;
    QMetaObject::invokeMethod(worker_, "find_user", Qt::QueuedConnection, Q_ARG(quint64, request_id),
        Q_ARG(qint64, session.user_id));
}

void AuthenticationService::session_revoked(quint64 request_id, const storage::SessionRecord& session,
    const storage::StorageError& error)
{
    const auto operation = operations_.value(request_id);
    if (!operation || operation->kind != OperationKind::LogOut) {
        return;
    }
    if (error.code != storage::StorageErrorCode::None) {
        fail(request_id, protocol::ErrorCode::Unavailable, QStringLiteral("Session storage is unavailable"));
        return;
    }

    QList<quint64> other_connections;
    for (auto it = connections_.begin(); it != connections_.end(); ++it) {
        if (it->session_id != session.id) {
            continue;
        }
        if (it.key() == operation->connection_id) {
            it->authenticated      = false;
            it->user_id            = 0;
            it->session_id         = 0;
            it->session_expires_at = 0;
        } else {
            other_connections.append(it.key());
        }
    }

    const quint64 connection_id = operation->connection_id;
    protocol::AuthenticationResult result;
    result.revoked = true;
    succeed(request_id, result);
    if (connections_.contains(connection_id)) {
        emit logged_out(connection_id);
    }
    for (const quint64 id : other_connections) {
        cancel_connection(id);
        server_->disconnect_client(id);
        emit logged_out(id);
    }
}

void AuthenticationService::client_connected(quint64 connection_id, const QHostAddress& address, quint16 port)
{
    Q_UNUSED(port);
    connections_.insert(connection_id,
        Connection { address, now(), AttemptLimiter(options_.maximum_attempts_per_connection, options_.attempt_window_ms) });
}

void AuthenticationService::client_disconnected(quint64 connection_id)
{
    cancel_connection(connection_id);
}

void AuthenticationService::message_received(quint64 connection_id, const protocol::Envelope& envelope)
{
    const auto connection = connections_.find(connection_id);
    if (connection == connections_.end()) {
        return;
    }
    const bool is_authentication = envelope.type == protocol::MessageType::AuthSignUp
        || envelope.type == protocol::MessageType::AuthLogIn || envelope.type == protocol::MessageType::AuthLogOut
        || envelope.type == protocol::MessageType::AuthSession;
    if (!is_authentication) {
        return;
    }
    if (connection->authenticated && envelope.type != protocol::MessageType::AuthLogOut) {
        send_error(connection_id, envelope.request_id, protocol::ErrorCode::InvalidRequest,
            QStringLiteral("The connection is already authenticated"));
        return;
    }
    if (envelope.type != protocol::MessageType::AuthLogOut && !allow_attempt(*connection)) {
        send_error(connection_id, envelope.request_id, protocol::ErrorCode::RateLimited,
            QStringLiteral("Too many authentication attempts; try again later"));
        return;
    }

    protocol::ErrorCode error = protocol::ErrorCode::None;
    QString message;
    switch (envelope.type) {
    case protocol::MessageType::AuthSignUp: {
        const auto data       = protocol::sign_up_from_envelope(envelope);
        const auto normalized = data.has_value() ? protocol::normalize_username(data->username) : std::nullopt;
        if (!data.has_value() || !normalized.has_value()) {
            send_error(connection_id, envelope.request_id, protocol::ErrorCode::InvalidRequest,
                QStringLiteral("Signup credentials are invalid"));
            return;
        }
        const auto operation = new_operation(OperationKind::SignUp, connection_id, envelope.request_id, &error, &message);
        if (!operation) {
            send_error(connection_id, envelope.request_id, error, message);
            return;
        }
        operation->new_user.username            = data->username.trimmed();
        operation->new_user.normalized_username = *normalized;
        operation->new_user.display_name        = data->display_name.value_or(operation->new_user.username);
        operation->new_user.now                 = now();
        operation->password                     = data->password.toUtf8();
        start_hash(operation, std::move(operation->password));
        return;
    }
    case protocol::MessageType::AuthLogIn: {
        const auto data = protocol::log_in_from_envelope(envelope);
        if (!data.has_value()) {
            send_error(connection_id, envelope.request_id, protocol::ErrorCode::InvalidRequest,
                QStringLiteral("Login fields are invalid"));
            return;
        }
        const auto operation = new_operation(OperationKind::LogIn, connection_id, envelope.request_id, &error, &message);
        if (!operation) {
            send_error(connection_id, envelope.request_id, error, message);
            return;
        }
        operation->new_user.normalized_username = protocol::normalize_username(data->username).value_or(QString());
        operation->password                     = data->password.toUtf8();
        if (operation->new_user.normalized_username.isEmpty()) {
            operation->password_hash = dummy_hash_;
            start_verify(operation, std::move(operation->password));
        } else {
            QMetaObject::invokeMethod(worker_, "find_local_user", Qt::QueuedConnection, Q_ARG(quint64, operation->id),
                Q_ARG(QString, operation->new_user.normalized_username));
        }
        return;
    }
    case protocol::MessageType::AuthLogOut:
    case protocol::MessageType::AuthSession: {
        const auto token = protocol::session_token_from_envelope(envelope);
        if (!token.has_value()) {
            send_error(connection_id, envelope.request_id, protocol::ErrorCode::InvalidRequest,
                QStringLiteral("A session token is required"));
            return;
        }
        const auto digest = digest_session_token(*token);
        if (!digest.has_value()) {
            send_error(connection_id, envelope.request_id,
                envelope.type == protocol::MessageType::AuthSession ? protocol::ErrorCode::Unauthenticated
                                                                    : protocol::ErrorCode::InvalidRequest,
                QStringLiteral("The session token is invalid"));
            return;
        }
        const auto kind      = envelope.type == protocol::MessageType::AuthSession ? OperationKind::Session : OperationKind::LogOut;
        const auto operation = new_operation(kind, connection_id, envelope.request_id, &error, &message);
        if (!operation) {
            send_error(connection_id, envelope.request_id, error, message);
            return;
        }
        operation->token_digest = *digest;
        QMetaObject::invokeMethod(worker_, "find_active_session", Qt::QueuedConnection, Q_ARG(quint64, operation->id),
            Q_ARG(QByteArray, operation->token_digest), Q_ARG(qint64, now()));
        return;
    }
    default:
        return;
    }
}

void AuthenticationService::password_hash_finished(quint64 operation_id, const std::optional<QString>& hash)
{
    if (operation_id == 0) {
        if (!hash.has_value()) {
            startup_failed(QStringLiteral("Password verification could not be initialized"));
            return;
        }
        dummy_hash_  = *hash;
        dummy_ready_ = true;
        maybe_ready();
        return;
    }
    const auto operation = operations_.value(operation_id);
    if (!operation || operation->kind != OperationKind::SignUp) {
        return;
    }
    if (!hash.has_value()) {
        fail(operation_id, protocol::ErrorCode::Unavailable, QStringLiteral("Password hashing is unavailable"));
        return;
    }
    operation->new_user.password_hash = *hash;
    QMetaObject::invokeMethod(worker_, "create_local_user", Qt::QueuedConnection, Q_ARG(quint64, operation_id),
        Q_ARG(tcp_chat::storage::NewLocalUser, operation->new_user));
}

void AuthenticationService::password_verify_finished(quint64 operation_id, PasswordVerification result)
{
    const auto operation = operations_.value(operation_id);
    if (!operation || operation->kind != OperationKind::LogIn) {
        return;
    }
    if (result != PasswordVerification::Match || operation->user.id <= 0 || !operation->user.password_hash.has_value()) {
        fail(operation_id, protocol::ErrorCode::InvalidCredentials, QStringLiteral("The username or password is incorrect"));
        return;
    }
    issue_session(operation);
}

void AuthenticationService::start_hash(const std::shared_ptr<Operation>& operation, QByteArray password)
{
    hash_pool_.start(new PasswordTask(this, operation->id, PasswordTask::Mode::Hash, std::move(password), QString(),
        options_.hash_parameters));
}

void AuthenticationService::start_verify(const std::shared_ptr<Operation>& operation, QByteArray password)
{
    hash_pool_.start(new PasswordTask(this, operation->id, PasswordTask::Mode::Verify, std::move(password),
        operation->password_hash, options_.hash_parameters));
}

void AuthenticationService::issue_session(const std::shared_ptr<Operation>& operation)
{
    const auto token     = generate_session_token();
    const qint64 current = now();
    if (!token.has_value() || operation->user.id <= 0 || current > std::numeric_limits<qint64>::max() - options_.session_lifetime_ms) {
        fail(operation->id, protocol::ErrorCode::Unavailable, QStringLiteral("Session creation is unavailable"));
        return;
    }
    operation->issued_token = token->value;
    operation->expires_at   = current + options_.session_lifetime_ms;
    storage::NewSession input;
    input.user_id      = operation->user.id;
    input.token_digest = token->digest;
    input.created_at   = current;
    input.expires_at   = operation->expires_at;
    input.last_seen_at = current;
    QMetaObject::invokeMethod(worker_, "create_session", Qt::QueuedConnection, Q_ARG(quint64, operation->id),
        Q_ARG(tcp_chat::storage::NewSession, input));
}

std::shared_ptr<AuthenticationService::Operation> AuthenticationService::new_operation(OperationKind kind,
    quint64 connection_id, const std::optional<QString>& request_id, protocol::ErrorCode* error, QString* message)
{
    const auto connection = connections_.find(connection_id);
    if (!ready_) {
        *error   = protocol::ErrorCode::Unavailable;
        *message = QStringLiteral("Authentication is not ready");
        return nullptr;
    }
    if (connection == connections_.end()) {
        *error   = protocol::ErrorCode::InvalidRequest;
        *message = QStringLiteral("The connection is no longer available");
        return nullptr;
    }
    if (connection->pending >= options_.maximum_pending_per_connection
        || operations_.size() >= options_.maximum_pending_operations) {
        *error   = protocol::ErrorCode::RateLimited;
        *message = QStringLiteral("Too many pending authentication requests");
        return nullptr;
    }

    auto operation           = std::make_shared<Operation>();
    operation->kind          = kind;
    operation->id            = next_operation_id_++;
    operation->connection_id = connection_id;
    operation->request_id    = request_id;
    operations_.insert(operation->id, operation);
    ++connection->pending;
    return operation;
}

void AuthenticationService::succeed(quint64 operation_id, const protocol::AuthenticationResult& result)
{
    const auto operation = operations_.take(operation_id);
    if (!operation) {
        return;
    }
    const auto connection = connections_.find(operation->connection_id);
    if (connection != connections_.end()) {
        if (connection->pending > 0) {
            --connection->pending;
        }
        send_result(*operation, result);
    }
}

void AuthenticationService::fail(quint64 operation_id, protocol::ErrorCode code, const QString& message)
{
    const auto operation = operations_.take(operation_id);
    if (!operation) {
        return;
    }
    const auto connection = connections_.find(operation->connection_id);
    if (connection != connections_.end()) {
        if (connection->pending > 0) {
            --connection->pending;
        }
        send_error(operation->connection_id, operation->request_id, code, message);
    }
}

void AuthenticationService::send_result(const Operation& operation, const protocol::AuthenticationResult& result)
{
    protocol::ProtocolError error;
    const auto payload = protocol::authentication_result_to_json(result, &error);
    if (!payload.has_value()) {
        send_error(operation.connection_id, operation.request_id, protocol::ErrorCode::InternalError,
            QStringLiteral("Authentication result could not be encoded"));
        return;
    }
    protocol::Envelope envelope;
    envelope.type       = protocol::MessageType::AuthResult;
    envelope.request_id = operation.request_id;
    envelope.payload    = *payload;
    server_->send(operation.connection_id, envelope);
}

void AuthenticationService::send_error(quint64 connection_id, const std::optional<QString>& request_id,
    protocol::ErrorCode code, const QString& message)
{
    const auto name = protocol::error_code_name(code);
    if (!name.has_value()) {
        return;
    }
    protocol::Envelope envelope;
    envelope.type       = protocol::MessageType::Error;
    envelope.request_id = request_id;
    envelope.payload    = QJsonObject {
        { QStringLiteral("code"), QString::fromLatin1(name->data(), name->size()) },
        { QStringLiteral("message"), message },
    };
    server_->send(connection_id, envelope);
}

bool AuthenticationService::allow_attempt(Connection& connection)
{
    const qint64 current = now();
    for (auto it = ip_limiters_.begin(); it != ip_limiters_.end();) {
        if (it->expired(current)) {
            it = ip_limiters_.erase(it);
        } else {
            ++it;
        }
    }
    const QString ip = connection.address.toString();
    auto limiter     = ip_limiters_.find(ip);
    if (limiter == ip_limiters_.end()) {
        limiter = ip_limiters_.insert(ip, AttemptLimiter(options_.maximum_attempts_per_ip, options_.attempt_window_ms));
    }
    return connection.limiter.allow(current) && limiter->allow(current);
}

void AuthenticationService::cancel_connection(quint64 connection_id)
{
    connections_.remove(connection_id);
    for (auto it = operations_.begin(); it != operations_.end();) {
        if (it.value()->connection_id == connection_id) {
            it = operations_.erase(it);
        } else {
            ++it;
        }
    }
}

void AuthenticationService::maybe_ready()
{
    if (ready_emitted_ || !database_ready_ || !dummy_ready_) {
        return;
    }
    ready_emitted_ = true;
    ready_         = true;
    emit ready(true, QString());
}

void AuthenticationService::startup_failed(const QString& message)
{
    if (ready_emitted_) {
        return;
    }
    ready_emitted_ = true;
    ready_         = false;
    deadline_timer_.stop();
    emit ready(false, message);
}

qint64 AuthenticationService::now() const
{
    const qint64 value = options_.clock ? options_.clock() : QDateTime::currentMSecsSinceEpoch();
    return qMax<qint64>(0, value);
}

protocol::UserIdentity AuthenticationService::public_user(const storage::UserRecord& user)
{
    return protocol::UserIdentity { user.id, user.username, user.display_name };
}

void AuthenticationService::shutdown()
{
    if (shutting_down_) {
        return;
    }
    shutting_down_ = true;
    deadline_timer_.stop();
    operations_.clear();
    hash_pool_.clear();
    hash_pool_.waitForDone();
    if (worker_ != nullptr) {
        QObject::disconnect(worker_, nullptr, this, nullptr);
        if (database_thread_.isRunning()) {
            QMetaObject::invokeMethod(worker_, "close", Qt::BlockingQueuedConnection);
        }
    }
    if (database_thread_.isRunning()) {
        database_thread_.quit();
        database_thread_.wait();
    }
    worker_ = nullptr;
}

} // namespace tcp_chat::auth

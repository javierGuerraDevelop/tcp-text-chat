#include "message_service.h"

#include "tcp_chat/frame.h"

#include <QDateTime>
#include <QMetaObject>

namespace tcp_chat::chat {

MessageService::MessageService(server::TlsServer* server, auth::AuthenticationService* authentication,
    MessageServiceOptions options, QObject* parent)
    : QObject(parent)
    , server_(server)
    , authentication_(authentication)
    , options_(std::move(options))
{
    worker_ = new storage::DatabaseWorker;
    worker_->moveToThread(&database_thread_);
    connect(&database_thread_, &QThread::finished, worker_, &QObject::deleteLater);
    connect(worker_, &storage::DatabaseWorker::opened, this, &MessageService::database_opened);
    connect(worker_, &storage::DatabaseWorker::message_appended, this, &MessageService::message_appended);
    connect(worker_, &storage::DatabaseWorker::message_history_loaded, this, &MessageService::message_history_loaded);
    database_thread_.start();

    if (server_ != nullptr) {
        connect(server_, &server::TlsServer::client_disconnected, this, &MessageService::client_disconnected);
        connect(server_, &server::TlsServer::message_received, this, &MessageService::message_received);
    }
    if (authentication_ != nullptr) {
        connect(authentication_, &auth::AuthenticationService::authenticated, this, &MessageService::authenticated);
        connect(authentication_, &auth::AuthenticationService::logged_out, this, &MessageService::logged_out);
    }
}

MessageService::~MessageService()
{
    shutdown();
}

std::optional<QString> MessageService::start(const QString& database_path, const QString& migrations_path)
{
    if (started_) {
        return QStringLiteral("The message service has already been started");
    }
    if (server_ == nullptr || authentication_ == nullptr || database_path.isEmpty() || migrations_path.isEmpty()) {
        return QStringLiteral("Server dependencies, a database path, and migrations path are required");
    }
    if (options_.maximum_pending_operations <= 0 || options_.maximum_pending_per_connection <= 0
        || options_.maximum_messages_per_connection <= 0 || options_.maximum_messages_per_user <= 0
        || options_.message_window_ms <= 0) {
        return QStringLiteral("Message limits and windows must be positive");
    }

    started_ = true;
    QMetaObject::invokeMethod(worker_, "open", Qt::QueuedConnection, Q_ARG(QString, database_path),
        Q_ARG(QString, migrations_path), Q_ARG(qint64, now()));
    return std::nullopt;
}

bool MessageService::is_ready() const
{
    return ready_;
}

void MessageService::database_opened(qint64 version, const storage::StorageError& error)
{
    if (shutting_down_ || ready_emitted_) {
        return;
    }
    ready_emitted_ = true;
    if (error.code != storage::StorageErrorCode::None || version < 0) {
        ready_ = false;
        emit ready(false, error.message.isEmpty() ? QStringLiteral("Message database initialization failed") : error.message);
        return;
    }
    ready_ = true;
    emit ready(true, QString());
}

void MessageService::authenticated(quint64 connection_id, const protocol::UserIdentity& user)
{
    connections_.insert(connection_id,
        Connection { user, next_authorization_id_++,
            auth::AttemptLimiter(options_.maximum_messages_per_connection, options_.message_window_ms), 0 });
}

void MessageService::logged_out(quint64 connection_id)
{
    connections_.remove(connection_id);
}

void MessageService::client_disconnected(quint64 connection_id)
{
    connections_.remove(connection_id);
}

void MessageService::message_received(quint64 connection_id, const protocol::Envelope& envelope)
{
    if (envelope.type != protocol::MessageType::ChatSend && envelope.type != protocol::MessageType::ChatHistory) {
        return;
    }
    auto connection = connections_.find(connection_id);
    if (connection == connections_.end()) {
        send_error(connection_id, envelope.request_id, protocol::ErrorCode::Unauthenticated,
            QStringLiteral("Authentication is required for chat"));
        return;
    }
    if (!ready_) {
        send_error(connection_id, envelope.request_id, protocol::ErrorCode::Unavailable,
            QStringLiteral("Message storage is unavailable"));
        return;
    }

    protocol::ErrorCode error = protocol::ErrorCode::None;
    QString message;
    if (envelope.type == protocol::MessageType::ChatHistory) {
        const auto history = protocol::chat_history_from_envelope(envelope);
        if (!history.has_value()) {
            send_error(connection_id, envelope.request_id, protocol::ErrorCode::InvalidRequest,
                QStringLiteral("Chat history fields are invalid"));
            return;
        }
        const auto operation = new_operation(OperationKind::History, connection_id, envelope.request_id, &error, &message);
        if (!operation) {
            send_error(connection_id, envelope.request_id, error, message);
            return;
        }
        operation->before_id = history->before_id;
        operation->after_id  = history->after_id;
        operation->limit     = history->limit;
        if (history->after_id.has_value()) {
            QMetaObject::invokeMethod(worker_, "history_after", Qt::QueuedConnection,
                Q_ARG(quint64, operation->id), Q_ARG(qint64, *history->after_id), Q_ARG(int, history->limit));
        } else {
            QMetaObject::invokeMethod(worker_, "history_before", Qt::QueuedConnection,
                Q_ARG(quint64, operation->id), Q_ARG(qint64, history->before_id.value_or(0)), Q_ARG(int, history->limit));
        }
        return;
    }

    const auto send = protocol::chat_send_from_envelope(envelope);
    if (!send.has_value()) {
        send_error(connection_id, envelope.request_id, protocol::ErrorCode::InvalidRequest,
            QStringLiteral("Message fields are invalid"));
        return;
    }
    if (!allow_message(*connection)) {
        send_error(connection_id, envelope.request_id, protocol::ErrorCode::RateLimited,
            QStringLiteral("Too many messages; try again later"));
        return;
    }
    const auto operation = new_operation(OperationKind::Send, connection_id, envelope.request_id, &error, &message);
    if (!operation) {
        send_error(connection_id, envelope.request_id, error, message);
        return;
    }
    operation->message.sender_id         = connection->user.id;
    operation->message.client_message_id = send->client_message_id;
    operation->message.body              = send->body;
    operation->message.created_at        = now();
    QMetaObject::invokeMethod(worker_, "append_message", Qt::QueuedConnection,
        Q_ARG(quint64, operation->id), Q_ARG(tcp_chat::storage::NewMessage, operation->message));
}

std::shared_ptr<MessageService::Operation> MessageService::new_operation(OperationKind kind, quint64 connection_id,
    const std::optional<QString>& request_id, protocol::ErrorCode* error, QString* message)
{
    auto connection = connections_.find(connection_id);
    if (connection == connections_.end()) {
        *error   = protocol::ErrorCode::Unauthenticated;
        *message = QStringLiteral("Authentication is required for chat");
        return nullptr;
    }
    if (connection->pending >= options_.maximum_pending_per_connection
        || operations_.size() >= options_.maximum_pending_operations) {
        *error   = protocol::ErrorCode::RateLimited;
        *message = QStringLiteral("Too many pending chat requests");
        return nullptr;
    }

    auto operation              = std::make_shared<Operation>();
    operation->kind             = kind;
    operation->id               = next_operation_id_++;
    operation->connection_id    = connection_id;
    operation->authorization_id = connection->authorization_id;
    operation->request_id       = request_id;
    operation->user             = connection->user;
    operations_.insert(operation->id, operation);
    ++connection->pending;
    return operation;
}

void MessageService::message_appended(quint64 request_id, const storage::MessageAppendResult& result,
    const storage::StorageError& error)
{
    const auto operation = operations_.take(request_id);
    if (!operation || operation->kind != OperationKind::Send) {
        return;
    }
    const bool current = finish_operation(*operation);
    if (error.code != storage::StorageErrorCode::None) {
        if (current) {
            send_error(operation->connection_id, operation->request_id,
                error.code == storage::StorageErrorCode::Conflict ? protocol::ErrorCode::InvalidRequest
                                                                  : protocol::ErrorCode::Unavailable,
                error.code == storage::StorageErrorCode::Conflict
                    ? QStringLiteral("Client message ID was already used for different content")
                    : QStringLiteral("Message storage is unavailable"));
        }
        return;
    }

    const protocol::ChatMessage message = public_message(result.message);
    if (current) {
        send_message(operation->connection_id, operation->request_id, message);
    }
    if (result.inserted) {
        broadcast(message);
    }
}

void MessageService::message_history_loaded(quint64 request_id, const QList<storage::MessageRecord>& messages,
    bool has_more, const storage::StorageError& error)
{
    const auto operation = operations_.take(request_id);
    if (!operation || operation->kind != OperationKind::History) {
        return;
    }
    if (!finish_operation(*operation)) {
        return;
    }
    if (error.code != storage::StorageErrorCode::None) {
        send_error(operation->connection_id, operation->request_id, protocol::ErrorCode::Unavailable,
            QStringLiteral("Message history is unavailable"));
        return;
    }

    protocol::ChatHistoryResult result;
    result.has_more = has_more;
    for (const storage::MessageRecord& record : messages) {
        result.messages.append(public_message(record));
    }

    std::optional<QJsonObject> payload;
    while (true) {
        payload = protocol::chat_history_result_to_json(result);
        if (!payload.has_value()) {
            send_error(operation->connection_id, operation->request_id, protocol::ErrorCode::InternalError,
                QStringLiteral("Message history could not be encoded"));
            return;
        }
        protocol::Envelope envelope;
        envelope.type       = protocol::MessageType::ChatHistoryResult;
        envelope.request_id = operation->request_id;
        envelope.payload    = *payload;
        if (protocol::encode_envelope(envelope).has_value()) {
            send_envelope(operation->connection_id, envelope);
            return;
        }
        if (result.messages.isEmpty()) {
            send_error(operation->connection_id, operation->request_id, protocol::ErrorCode::InternalError,
                QStringLiteral("Message history exceeds the frame limit"));
            return;
        }
        if (operation->after_id.has_value()) {
            result.messages.removeLast();
        } else {
            result.messages.removeFirst();
        }
        result.has_more = true;
    }
}

bool MessageService::finish_operation(const Operation& operation)
{
    const auto connection = connections_.find(operation.connection_id);
    if (connection == connections_.end() || connection->authorization_id != operation.authorization_id) {
        return false;
    }
    if (connection->pending > 0) {
        --connection->pending;
    }
    return true;
}

bool MessageService::allow_message(Connection& connection)
{
    const qint64 current = now();
    for (auto it = user_limiters_.begin(); it != user_limiters_.end();) {
        if (it->expired(current)) {
            it = user_limiters_.erase(it);
        } else {
            ++it;
        }
    }
    auto limiter = user_limiters_.find(connection.user.id);
    if (limiter == user_limiters_.end()) {
        limiter = user_limiters_.insert(connection.user.id,
            auth::AttemptLimiter(options_.maximum_messages_per_user, options_.message_window_ms));
    }
    return connection.send_limiter.allow(current) && limiter->allow(current);
}

void MessageService::send_message(quint64 connection_id, const std::optional<QString>& request_id,
    const protocol::ChatMessage& message)
{
    const auto payload = protocol::chat_message_to_json(message);
    if (!payload.has_value()) {
        send_error(connection_id, request_id, protocol::ErrorCode::InternalError,
            QStringLiteral("Message could not be encoded"));
        return;
    }
    protocol::Envelope envelope;
    envelope.type       = protocol::MessageType::ChatMessage;
    envelope.request_id = request_id;
    envelope.payload    = *payload;
    send_envelope(connection_id, envelope);
}

void MessageService::broadcast(const protocol::ChatMessage& message)
{
    const QList<quint64> recipients = connections_.keys();
    for (const quint64 connection_id : recipients) {
        if (connections_.contains(connection_id)) {
            send_message(connection_id, std::nullopt, message);
        }
    }
}

void MessageService::send_error(quint64 connection_id, const std::optional<QString>& request_id,
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
    send_envelope(connection_id, envelope);
}

void MessageService::send_envelope(quint64 connection_id, const protocol::Envelope& envelope)
{
    const auto error = server_->send(connection_id, envelope);
    if (error.has_value() && error->code == protocol::ErrorCode::Unavailable) {
        server_->disconnect_client(connection_id);
    }
}

protocol::ChatMessage MessageService::public_message(const storage::MessageRecord& record)
{
    return protocol::ChatMessage {
        record.id,
        protocol::UserIdentity { record.sender_id, record.sender_username, record.sender_display_name },
        record.client_message_id,
        record.body,
        record.created_at,
    };
}

qint64 MessageService::now() const
{
    const qint64 value = options_.clock ? options_.clock() : QDateTime::currentMSecsSinceEpoch();
    return qMax<qint64>(0, value);
}

void MessageService::shutdown()
{
    if (shutting_down_) {
        return;
    }
    shutting_down_ = true;
    operations_.clear();
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

} // namespace tcp_chat::chat

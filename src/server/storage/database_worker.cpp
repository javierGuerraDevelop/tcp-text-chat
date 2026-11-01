#include "database_worker.h"

#include "account_repository.h"
#include "message_repository.h"
#include "migration_runner.h"
#include "session_repository.h"

#include <QAtomicInteger>
#include <QThread>

namespace tcp_chat::storage {

DatabaseWorker::DatabaseWorker(QObject* parent)
    : QObject(parent)
{
    qRegisterMetaType<tcp_chat::storage::StorageError>("tcp_chat::storage::StorageError");
    qRegisterMetaType<tcp_chat::storage::UserRecord>("tcp_chat::storage::UserRecord");
    qRegisterMetaType<tcp_chat::storage::NewLocalUser>("tcp_chat::storage::NewLocalUser");
    qRegisterMetaType<tcp_chat::storage::NewOAuthUser>("tcp_chat::storage::NewOAuthUser");
    qRegisterMetaType<tcp_chat::storage::SessionRecord>("tcp_chat::storage::SessionRecord");
    qRegisterMetaType<tcp_chat::storage::NewSession>("tcp_chat::storage::NewSession");
}

DatabaseWorker::~DatabaseWorker()
{
    close_connection();
}

void DatabaseWorker::open(const QString& database_path, const QString& migrations_path, qint64 now)
{
    StorageError error;
    if (QThread::currentThread() != thread()) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("DatabaseWorker::open must run on the worker thread");
        emit opened(-1, error);
        return;
    }
    if (database_.isValid()) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("Database connection is already open");
        emit opened(-1, error);
        return;
    }
    if (database_path.isEmpty() || migrations_path.isEmpty() || now < 0) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("Database open fields are invalid");
        emit opened(-1, error);
        return;
    }

    static QAtomicInteger<quint64> sequence;
    const QString connection_name = QStringLiteral("tcp_chat_storage_%1").arg(sequence.fetchAndAddRelaxed(1));
    database_                     = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connection_name);
    database_.setDatabaseName(database_path);
    if (!database_.open()) {
        error.code    = StorageErrorCode::OpenFailed;
        error.message = QStringLiteral("Could not open SQLite database");
        close_connection();
        emit opened(-1, error);
        return;
    }

    accounts_         = std::make_unique<AccountRepository>(database_);
    sessions_         = std::make_unique<SessionRepository>(database_);
    messages_         = std::make_unique<MessageRepository>(database_);
    const auto result = MigrationRunner::migrate(database_, migrations_path, now, &error);
    if (!result.has_value()) {
        close_connection();
        emit opened(-1, error);
        return;
    }

    emit opened(result->current_version, StorageError { });
}

void DatabaseWorker::create_local_user(quint64 request_id, const NewLocalUser& input)
{
    StorageError error;
    UserRecord user;
    if (QThread::currentThread() != thread() || !accounts_) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("Local user creation requires an open worker connection");
    } else {
        const auto result = accounts_->create_local_user(input, &error);
        if (result.has_value()) {
            user = *result;
        }
    }
    emit local_user_created(request_id, user, error);
}

void DatabaseWorker::find_local_user(quint64 request_id, const QString& normalized_username)
{
    StorageError error;
    UserRecord user;
    if (QThread::currentThread() != thread() || !accounts_) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("Local user lookup requires an open worker connection");
    } else {
        const auto result = accounts_->find_user_by_normalized_username(normalized_username, &error);
        if (result.has_value()) {
            user = *result;
        }
    }
    emit local_user_found(request_id, user, error);
}

void DatabaseWorker::find_or_create_oauth_user(quint64 request_id, const NewOAuthUser& input)
{
    StorageError error;
    UserRecord user;
    if (QThread::currentThread() != thread() || !accounts_) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("OAuth user resolution requires an open worker connection");
    } else {
        const auto result = accounts_->find_or_create_oauth_user(input, &error);
        if (result.has_value()) {
            user = *result;
        }
    }
    emit oauth_user_resolved(request_id, user, error);
}

void DatabaseWorker::find_user(quint64 request_id, qint64 user_id)
{
    StorageError error;
    UserRecord user;
    if (QThread::currentThread() != thread() || !accounts_) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("User lookup requires an open worker connection");
    } else {
        const auto result = accounts_->find_user_by_id(user_id, &error);
        if (result.has_value()) {
            user = *result;
        }
    }
    emit user_found(request_id, user, error);
}

void DatabaseWorker::create_session(quint64 request_id, const NewSession& input)
{
    StorageError error;
    SessionRecord session;
    if (QThread::currentThread() != thread() || !sessions_) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("Session creation requires an open worker connection");
    } else {
        const auto result = sessions_->create_session(input, &error);
        if (result.has_value()) {
            session = *result;
        }
    }
    emit session_created(request_id, session, error);
}

void DatabaseWorker::find_active_session(quint64 request_id, const QByteArray& token_digest, qint64 now)
{
    StorageError error;
    SessionRecord session;
    if (QThread::currentThread() != thread() || !sessions_) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("Session lookup requires an open worker connection");
    } else {
        const auto result = sessions_->find_active_session(token_digest, now, &error);
        if (result.has_value()) {
            session = *result;
        }
    }
    emit active_session_found(request_id, session, error);
}

void DatabaseWorker::revoke_session(quint64 request_id, qint64 session_id, qint64 now)
{
    StorageError error;
    SessionRecord session;
    if (QThread::currentThread() != thread() || !sessions_) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("Session revocation requires an open worker connection");
    } else {
        const auto result = sessions_->revoke_session(session_id, now, &error);
        if (result.has_value()) {
            session = *result;
        }
    }
    emit session_revoked(request_id, session, error);
}

void DatabaseWorker::close()
{
    if (QThread::currentThread() != thread()) {
        return;
    }

    close_connection();
    emit closed();
}

void DatabaseWorker::close_connection()
{
    accounts_.reset();
    sessions_.reset();
    messages_.reset();
    if (!database_.isValid()) {
        return;
    }

    const QString connection_name = database_.connectionName();
    database_.close();
    database_ = QSqlDatabase { };
    QSqlDatabase::removeDatabase(connection_name);
}

} // namespace tcp_chat::storage

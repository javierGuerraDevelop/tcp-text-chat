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
    qRegisterMetaType<tcp_chat::storage::MessageRecord>("tcp_chat::storage::MessageRecord");
    qRegisterMetaType<tcp_chat::storage::NewMessage>("tcp_chat::storage::NewMessage");
    qRegisterMetaType<tcp_chat::storage::MessageAppendResult>("tcp_chat::storage::MessageAppendResult");
    qRegisterMetaType<QList<tcp_chat::storage::MessageRecord>>("QList<tcp_chat::storage::MessageRecord>");
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

void DatabaseWorker::append_message(quint64 request_id, const NewMessage& input)
{
    StorageError error;
    MessageAppendResult appended;
    if (QThread::currentThread() != thread() || !messages_) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("Message append requires an open worker connection");
    } else {
        const auto result = messages_->append_message(input, &error);
        if (result.has_value()) {
            appended = *result;
        }
    }
    emit message_appended(request_id, appended, error);
}

void DatabaseWorker::history_before(quint64 request_id, qint64 before_id, int limit)
{
    StorageError error;
    QList<MessageRecord> page;
    bool has_more = false;
    if (QThread::currentThread() != thread() || !messages_ || before_id < 0 || limit <= 0
        || limit > protocol::maximum_history_limit) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("Message history requires an open worker connection and valid pagination");
    } else {
        const auto result = messages_->history_before(before_id == 0 ? std::nullopt : std::optional<qint64> { before_id }, limit, &error);
        if (result.has_value()) {
            page = *result;
            if (page.size() == limit) {
                const auto older = messages_->history_before(page.first().id, 1, &error);
                if (older.has_value()) {
                    has_more = !older->isEmpty();
                }
            }
        }
    }
    emit message_history_loaded(request_id, page, has_more, error);
}

void DatabaseWorker::history_after(quint64 request_id, qint64 after_id, int limit)
{
    StorageError error;
    QList<MessageRecord> page;
    bool has_more = false;
    if (QThread::currentThread() != thread() || !messages_ || after_id < 0 || limit <= 0
        || limit > protocol::maximum_history_limit) {
        error.code    = StorageErrorCode::InvalidInput;
        error.message = QStringLiteral("Message history requires an open worker connection and valid pagination");
    } else {
        const auto result = messages_->history_after(after_id, limit, &error);
        if (result.has_value()) {
            page = *result;
            if (page.size() == limit) {
                const auto newer = messages_->history_after(page.last().id, 1, &error);
                if (newer.has_value()) {
                    has_more = !newer->isEmpty();
                }
            }
        }
    }
    emit message_history_loaded(request_id, page, has_more, error);
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

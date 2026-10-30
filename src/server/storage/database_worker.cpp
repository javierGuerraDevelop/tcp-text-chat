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

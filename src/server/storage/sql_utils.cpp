#include "sql_utils.h"

#include <QSqlQuery>

namespace tcp_chat::storage::detail {

void clear_error(StorageError* error)
{
    if (error != nullptr) {
        error->code = StorageErrorCode::None;
        error->message.clear();
    }
}

void set_error(StorageError* error, StorageErrorCode code, const QString& message)
{
    if (error != nullptr) {
        error->code    = code;
        error->message = message;
    }
}

void set_query_error(StorageError* error, const QSqlError& sql_error, const QString& context)
{
    const QString native_code = sql_error.nativeErrorCode();
    const bool constraint     = native_code == QStringLiteral("19") || native_code == QStringLiteral("1555")
        || native_code == QStringLiteral("2067")
        || sql_error.text().contains(QStringLiteral("constraint failed"), Qt::CaseInsensitive);
    QString message = context;
    if (!native_code.isEmpty()) {
        message = QStringLiteral("%1 (SQLite %2)").arg(context, native_code);
    }
    set_error(error, constraint ? StorageErrorCode::ConstraintViolation : StorageErrorCode::QueryFailed, message);
}

bool execute(QSqlDatabase& database, const QString& statement, StorageError* error)
{
    QSqlQuery query(database);
    if (!query.exec(statement)) {
        set_query_error(error, query.lastError(), QStringLiteral("SQL statement failed"));
        return false;
    }
    return true;
}

Transaction::Transaction(QSqlDatabase& database)
    : database_(database)
{
}

Transaction::~Transaction()
{
    if (active_) {
        database_.rollback();
    }
}

bool Transaction::begin(StorageError* error)
{
    if (database_.transaction()) {
        active_ = true;
        return true;
    }

    set_query_error(error, database_.lastError(), QStringLiteral("Could not start transaction"));
    return false;
}

bool Transaction::commit(StorageError* error)
{
    if (!active_) {
        set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("Transaction is not active"));
        return false;
    }
    if (!database_.commit()) {
        set_query_error(error, database_.lastError(), QStringLiteral("Could not commit transaction"));
        return false;
    }

    active_ = false;
    return true;
}

} // namespace tcp_chat::storage::detail

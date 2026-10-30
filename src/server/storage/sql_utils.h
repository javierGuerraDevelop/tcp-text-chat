#pragma once

#include "storage_error.h"

#include <QSqlDatabase>
#include <QSqlError>

namespace tcp_chat::storage::detail {

/// Clears any error reported by an earlier storage operation.
void clear_error(StorageError* error);

/// Records a storage error when the caller supplied an error destination.
void set_error(StorageError* error, StorageErrorCode code, const QString& message);

/// Maps a Qt SQL error to a safe storage error category.
void set_query_error(StorageError* error, const QSqlError& sql_error, const QString& context);

/// Executes one SQL statement and reports driver failures.
bool execute(QSqlDatabase& database, const QString& statement, StorageError* error);

/// Rolls back an active SQLite transaction unless it is committed.
class Transaction {
public:
    /// Creates an inactive transaction for an open connection on the current thread.
    explicit Transaction(QSqlDatabase& database);
    /// Rolls back any transaction that remains active.
    ~Transaction();

    Transaction(const Transaction&)            = delete;
    Transaction& operator=(const Transaction&) = delete;

    /// Begins the transaction.
    bool begin(StorageError* error);
    /// Commits the transaction and releases rollback responsibility.
    bool commit(StorageError* error);

private:
    QSqlDatabase& database_;
    bool active_ = false;
};

} // namespace tcp_chat::storage::detail

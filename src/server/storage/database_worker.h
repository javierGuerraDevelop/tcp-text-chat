#pragma once

#include "storage_error.h"

#include <QObject>
#include <QSqlDatabase>

#include <memory>

namespace tcp_chat::storage {

class AccountRepository;
class SessionRepository;
class MessageRepository;

/// Owns a SQLite connection and repositories on one dedicated QObject thread.
class DatabaseWorker : public QObject {
    Q_OBJECT

public:
    /// Creates a closed worker; move it to its owning thread before invoking slots.
    explicit DatabaseWorker(QObject* parent = nullptr);
    /// Closes the connection; the worker must be destroyed on its owning thread.
    ~DatabaseWorker() override;

    DatabaseWorker(const DatabaseWorker&)            = delete;
    DatabaseWorker& operator=(const DatabaseWorker&) = delete;

public slots:
    /// Opens and migrates a database, then emits opened with a version or -1 on failure.
    void open(const QString& database_path, const QString& migrations_path, qint64 now);

    /// Closes the connection and repositories, then emits closed.
    void close();

signals:
    /// Reports migration success or a typed open failure.
    void opened(qint64 current_version, const tcp_chat::storage::StorageError& error);
    /// Reports that the connection has been closed.
    void closed();

private:
    /// Destroys dependent objects before removing the named connection.
    void close_connection();

    QSqlDatabase database_;
    std::unique_ptr<AccountRepository> accounts_;
    std::unique_ptr<SessionRepository> sessions_;
    std::unique_ptr<MessageRepository> messages_;
};

} // namespace tcp_chat::storage

Q_DECLARE_METATYPE(tcp_chat::storage::StorageError)

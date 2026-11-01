#pragma once

#include "records.h"
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

    /// Creates a local user and emits local_user_created with the same request ID.
    void create_local_user(quint64 request_id, const NewLocalUser& input);

    /// Finds a local user and emits local_user_found with the same request ID.
    void find_local_user(quint64 request_id, const QString& normalized_username);

    /// Finds or provisions an OAuth user and emits oauth_user_resolved with the same request ID.
    void find_or_create_oauth_user(quint64 request_id, const NewOAuthUser& input);

    /// Finds a user by ID and emits user_found with the same request ID.
    void find_user(quint64 request_id, qint64 user_id);

    /// Creates a session and emits session_created with the same request ID.
    void create_session(quint64 request_id, const NewSession& input);

    /// Finds an active session and emits active_session_found with the same request ID.
    void find_active_session(quint64 request_id, const QByteArray& token_digest, qint64 now);

    /// Revokes a session and emits session_revoked with the same request ID.
    void revoke_session(quint64 request_id, qint64 session_id, qint64 now);

    /// Closes the connection and repositories, then emits closed.
    void close();

signals:
    /// Reports migration success or a typed open failure.
    void opened(qint64 current_version, const tcp_chat::storage::StorageError& error);
    /// Returns a created user or a typed storage failure.
    void local_user_created(quint64 request_id, const tcp_chat::storage::UserRecord& user,
        const tcp_chat::storage::StorageError& error);
    /// Returns a user lookup or a typed storage failure.
    void local_user_found(quint64 request_id, const tcp_chat::storage::UserRecord& user,
        const tcp_chat::storage::StorageError& error);
    /// Returns an OAuth-linked user or a typed storage failure.
    void oauth_user_resolved(quint64 request_id, const tcp_chat::storage::UserRecord& user,
        const tcp_chat::storage::StorageError& error);
    /// Returns a user ID lookup or a typed storage failure.
    void user_found(quint64 request_id, const tcp_chat::storage::UserRecord& user,
        const tcp_chat::storage::StorageError& error);
    /// Returns a created session or a typed storage failure.
    void session_created(quint64 request_id, const tcp_chat::storage::SessionRecord& session,
        const tcp_chat::storage::StorageError& error);
    /// Returns an active-session lookup or a typed storage failure.
    void active_session_found(quint64 request_id, const tcp_chat::storage::SessionRecord& session,
        const tcp_chat::storage::StorageError& error);
    /// Returns a revoked session or a typed storage failure.
    void session_revoked(quint64 request_id, const tcp_chat::storage::SessionRecord& session,
        const tcp_chat::storage::StorageError& error);
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

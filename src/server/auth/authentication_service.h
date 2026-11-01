#pragma once

#include "attempt_limiter.h"
#include "oauth_callback_server.h"
#include "oauth_coordinator.h"
#include "password_hasher.h"
#include "server/tls_server.h"
#include "storage/database_worker.h"
#include "tcp_chat/auth_protocol.h"

#include <QHash>
#include <QHostAddress>
#include <QObject>
#include <QThread>
#include <QThreadPool>
#include <QTimer>

#include <functional>
#include <memory>
#include <optional>

namespace tcp_chat::auth {

class PasswordTask;

/// Configures bounded password work, session lifetime, and authentication limits.
struct AuthenticationServiceOptions {
    Argon2idParameters hash_parameters;
    int hash_thread_count               = 2;
    int maximum_pending_operations      = 64;
    int maximum_pending_per_connection  = 4;
    int maximum_attempts_per_connection = 8;
    int maximum_attempts_per_ip         = 32;
    qint64 attempt_window_ms            = 60000;
    qint64 session_lifetime_ms          = 7 * 24 * 60 * 60 * 1000;
    qint64 authentication_timeout_ms    = 30000;
    std::function<qint64()> clock;
    std::optional<OAuthCallbackServerOptions> oauth_callback;
    OAuthCoordinatorOptions oauth;
    QList<std::shared_ptr<OAuthProvider>> oauth_providers;
};

/// Coordinates TLS authentication, bounded password jobs, and thread-affine persistence.
class AuthenticationService : public QObject {
    Q_OBJECT

public:
    /// Creates a service and starts its database thread; the server must outlive it.
    explicit AuthenticationService(server::TlsServer* server, AuthenticationServiceOptions options = AuthenticationServiceOptions { },
        QObject* parent = nullptr);
    /// Stops password work and closes the database thread before destruction.
    ~AuthenticationService() override;

    AuthenticationService(const AuthenticationService&)            = delete;
    AuthenticationService& operator=(const AuthenticationService&) = delete;

    /// Opens and migrates the database, returning local configuration errors synchronously.
    std::optional<QString> start(const QString& database_path, const QString& migrations_path);

    /// Returns whether the database and password verifier are ready for requests.
    bool is_ready() const;

    /// Applies the configured unauthenticated-connection deadline using the injected clock.
    void check_authentication_deadlines();

signals:
    /// Reports startup completion with an empty message on success.
    void ready(bool success, const QString& message);
    /// Emits after a connection has an authenticated identity.
    void authenticated(quint64 connection_id, const tcp_chat::protocol::UserIdentity& user);
    /// Emits after a connection's current session is logged out.
    void logged_out(quint64 connection_id);

private:
    enum class OperationKind {
        SignUp,
        LogIn,
        LogOut,
        Session,
        OAuthStart,
        OAuthStatus,
        OAuthComplete,
    };

    /// Holds one in-flight request without retaining the plaintext session token.
    struct Operation {
        OperationKind kind;
        quint64 id            = 0;
        quint64 connection_id = 0;
        std::optional<QString> request_id;
        storage::NewLocalUser new_user;
        storage::UserRecord user;
        QByteArray password;
        QString password_hash;
        QByteArray token_digest;
        QString issued_token;
        qint64 expires_at = 0;
        qint64 session_id = 0;
        ~Operation();
    };

    /// Tracks one socket's authentication state and bounded request activity.
    struct Connection {
        QHostAddress address;
        qint64 connected_at = 0;
        AttemptLimiter limiter;
        AttemptLimiter oauth_poll_limiter { 120, 60000 };
        int pending               = 0;
        bool authenticated        = false;
        qint64 user_id            = 0;
        qint64 session_id         = 0;
        qint64 session_expires_at = 0;
    };

    friend class PasswordTask;

    /// Handles database startup completion.
    void database_opened(qint64 version, const storage::StorageError& error);
    /// Handles a local-user creation result.
    void local_user_created(quint64 request_id, const storage::UserRecord& user, const storage::StorageError& error);
    /// Handles a username lookup result.
    void local_user_found(quint64 request_id, const storage::UserRecord& user, const storage::StorageError& error);
    /// Handles a user-ID lookup for session resumption.
    void user_found(quint64 request_id, const storage::UserRecord& user, const storage::StorageError& error);
    /// Handles a session creation result.
    void session_created(quint64 request_id, const storage::SessionRecord& session, const storage::StorageError& error);
    /// Handles an active-session lookup result.
    void active_session_found(quint64 request_id, const storage::SessionRecord& session, const storage::StorageError& error);
    /// Handles a session revocation result.
    void session_revoked(quint64 request_id, const storage::SessionRecord& session, const storage::StorageError& error);
    /// Queues atomic provisioning for a provider-validated identity.
    void oauth_account_requested(quint64 flow_id, const QString& provider, const QString& subject,
        const QString& username, const QString& normalized_username, const QString& display_name);
    /// Completes or retries account provisioning for a browser flow.
    void oauth_user_resolved(quint64 request_id, const storage::UserRecord& user, const storage::StorageError& error);
    /// Registers a newly connected TLS peer.
    void client_connected(quint64 connection_id, const QHostAddress& address, quint16 port);
    /// Cancels work associated with a disconnected peer.
    void client_disconnected(quint64 connection_id);
    /// Validates and dispatches an authentication envelope.
    void message_received(quint64 connection_id, const protocol::Envelope& envelope);
    /// Completes a password hash job on the service thread.
    void password_hash_finished(quint64 operation_id, const std::optional<QString>& hash);
    /// Completes a password verification job on the service thread.
    void password_verify_finished(quint64 operation_id, PasswordVerification result);
    /// Starts a password hash job for a signup operation.
    void start_hash(const std::shared_ptr<Operation>& operation, QByteArray password);
    /// Starts a password verification job for a login operation.
    void start_verify(const std::shared_ptr<Operation>& operation, QByteArray password);
    /// Creates and persists a new opaque session for an authenticated user.
    void issue_session(const std::shared_ptr<Operation>& operation);
    /// Allocates a bounded operation or reports why it cannot be accepted.
    std::shared_ptr<Operation> new_operation(OperationKind kind, quint64 connection_id,
        const std::optional<QString>& request_id, protocol::ErrorCode* error, QString* message);
    /// Completes an operation with a public result.
    void succeed(quint64 operation_id, const protocol::AuthenticationResult& result);
    /// Completes an OAuth start/status operation with its public flow result.
    void succeed_oauth(quint64 operation_id, const protocol::OAuthResult& result);
    /// Completes an operation with a safe public error.
    void fail(quint64 operation_id, protocol::ErrorCode code, const QString& message);
    /// Sends a public result to the requesting connection.
    void send_result(const Operation& operation, const protocol::AuthenticationResult& result);
    /// Sends a safe error to a connection, preserving request correlation.
    void send_error(quint64 connection_id, const std::optional<QString>& request_id,
        protocol::ErrorCode code, const QString& message);
    /// Applies per-connection and per-IP fixed-window limits.
    bool allow_attempt(Connection& connection);
    /// Cancels all work for a connection and forgets its authentication state.
    void cancel_connection(quint64 connection_id);
    /// Emits startup success after both dependencies are ready.
    void maybe_ready();
    /// Reports a startup failure once.
    void startup_failed(const QString& message);
    /// Returns the current injected or system time in milliseconds.
    qint64 now() const;
    /// Converts a stored user to its public representation.
    static protocol::UserIdentity public_user(const storage::UserRecord& user);
    /// Stops all owned resources during destruction.
    void shutdown();

    server::TlsServer* const server_;
    AuthenticationServiceOptions options_;
    PasswordHasher hasher_;
    QThreadPool hash_pool_;
    QThread database_thread_;
    storage::DatabaseWorker* worker_ = nullptr;
    std::unique_ptr<OAuthCallbackServer> oauth_callback_server_;
    std::unique_ptr<OAuthCoordinator> oauth_coordinator_;
    QTimer deadline_timer_;
    QHash<quint64, Connection> connections_;
    QHash<quint64, std::shared_ptr<Operation>> operations_;
    QHash<QString, AttemptLimiter> ip_limiters_;
    QString dummy_hash_;
    quint64 next_operation_id_ = 1;
    bool started_              = false;
    bool database_ready_       = false;
    bool dummy_ready_          = false;
    bool ready_                = false;
    bool ready_emitted_        = false;
    bool shutting_down_        = false;
};

} // namespace tcp_chat::auth

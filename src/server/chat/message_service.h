#pragma once

#include "auth/attempt_limiter.h"
#include "auth/authentication_service.h"
#include "server/tls_server.h"
#include "storage/database_worker.h"
#include "tcp_chat/chat_protocol.h"

#include <QHash>
#include <QObject>
#include <QThread>

#include <functional>
#include <memory>
#include <optional>

namespace tcp_chat::chat {

/// Configures bounded message work and fixed-window send limits.
struct MessageServiceOptions {
    int maximum_pending_operations      = 256;
    int maximum_pending_per_connection  = 8;
    int maximum_messages_per_connection = 30;
    int maximum_messages_per_user       = 30;
    qint64 message_window_ms            = 60000;
    std::function<qint64()> clock;
};

/// Coordinates authenticated shared-room history, persistence, and ordered broadcasts.
class MessageService : public QObject {
    Q_OBJECT

public:
    /// Creates a service and starts its database thread; all dependencies must outlive it.
    explicit MessageService(server::TlsServer* server, auth::AuthenticationService* authentication,
        MessageServiceOptions options = MessageServiceOptions { }, QObject* parent = nullptr);
    /// Stops accepting work and closes the database on its owning thread.
    ~MessageService() override;

    MessageService(const MessageService&)            = delete;
    MessageService& operator=(const MessageService&) = delete;

    /// Opens the message database, returning local configuration errors synchronously.
    std::optional<QString> start(const QString& database_path, const QString& migrations_path);
    /// Returns whether message persistence is ready for requests.
    bool is_ready() const;

signals:
    /// Reports startup completion with an empty message on success.
    void ready(bool success, const QString& message);

private:
    enum class OperationKind {
        Send,
        History,
    };

    /// Holds one accepted request until its serialized database result arrives.
    struct Operation {
        OperationKind kind       = OperationKind::History;
        quint64 id               = 0;
        quint64 connection_id    = 0;
        quint64 authorization_id = 0;
        std::optional<QString> request_id;
        protocol::UserIdentity user;
        storage::NewMessage message;
        std::optional<qint64> before_id;
        std::optional<qint64> after_id;
        int limit = protocol::default_history_limit;
    };

    /// Tracks one connection's current authorization and bounded request activity.
    struct Connection {
        protocol::UserIdentity user;
        quint64 authorization_id = 0;
        auth::AttemptLimiter send_limiter;
        int pending = 0;
    };

    /// Handles database startup completion.
    void database_opened(qint64 version, const storage::StorageError& error);
    /// Adds or replaces a connection's authorized identity.
    void authenticated(quint64 connection_id, const protocol::UserIdentity& user);
    /// Removes authorization after logout or session expiry.
    void logged_out(quint64 connection_id);
    /// Removes authorization after transport disconnection.
    void client_disconnected(quint64 connection_id);
    /// Validates and dispatches shared-room requests.
    void message_received(quint64 connection_id, const protocol::Envelope& envelope);
    /// Allocates a bounded operation for the current authorization.
    std::shared_ptr<Operation> new_operation(OperationKind kind, quint64 connection_id,
        const std::optional<QString>& request_id, protocol::ErrorCode* error, QString* message);
    /// Completes an append and broadcasts only newly inserted messages.
    void message_appended(quint64 request_id, const storage::MessageAppendResult& result, const storage::StorageError& error);
    /// Completes a history request with a frame-bounded ascending page.
    void message_history_loaded(quint64 request_id, const QList<storage::MessageRecord>& messages,
        bool has_more, const storage::StorageError& error);
    /// Releases pending capacity and returns whether the authorization is still current.
    bool finish_operation(const Operation& operation);
    /// Applies per-connection and per-user fixed-window send limits.
    bool allow_message(Connection& connection);
    /// Sends a public message acknowledgement or live event.
    void send_message(quint64 connection_id, const std::optional<QString>& request_id, const protocol::ChatMessage& message);
    /// Broadcasts a persisted message to all currently authorized connections.
    void broadcast(const protocol::ChatMessage& message);
    /// Sends a safe error while preserving request correlation.
    void send_error(quint64 connection_id, const std::optional<QString>& request_id,
        protocol::ErrorCode code, const QString& message);
    /// Disconnects a client when its bounded output cannot accept an envelope.
    void send_envelope(quint64 connection_id, const protocol::Envelope& envelope);
    /// Converts a joined storage row to its public representation.
    static protocol::ChatMessage public_message(const storage::MessageRecord& record);
    /// Returns the current injected or system time in milliseconds.
    qint64 now() const;
    /// Stops all owned resources during destruction.
    void shutdown();

    server::TlsServer* const server_;
    auth::AuthenticationService* const authentication_;
    MessageServiceOptions options_;
    QThread database_thread_;
    storage::DatabaseWorker* worker_ = nullptr;
    QHash<quint64, Connection> connections_;
    QHash<quint64, std::shared_ptr<Operation>> operations_;
    QHash<qint64, auth::AttemptLimiter> user_limiters_;
    quint64 next_operation_id_     = 1;
    quint64 next_authorization_id_ = 1;
    bool started_                  = false;
    bool ready_                    = false;
    bool ready_emitted_            = false;
    bool shutting_down_            = false;
};

} // namespace tcp_chat::chat

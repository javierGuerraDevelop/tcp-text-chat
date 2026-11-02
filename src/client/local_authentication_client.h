#pragma once

#include "tcp_chat/auth_protocol.h"
#include "tls_client.h"

#include <QObject>

#include <optional>

namespace tcp_chat::client {

/// Sends correlated local-account and session operations over an established TLS client.
class LocalAuthenticationClient final : public QObject {
    Q_OBJECT

public:
    /// Creates an idle local authentication API; the TLS client must outlive it.
    explicit LocalAuthenticationClient(TlsClient* client, QObject* parent = nullptr);

    /// Starts account creation after applying the shared protocol validation.
    std::optional<QString> sign_up(const QString& username, const QString& password, const std::optional<QString>& display_name = std::nullopt);
    /// Starts local sign-in without distinguishing malformed credentials in server errors.
    std::optional<QString> log_in(const QString& username, const QString& password);
    /// Starts revocation of an in-memory session token.
    std::optional<QString> log_out(const QString& session_token);
    /// Invalidates the pending local response without waiting for network I/O.
    void cancel();
    /// Returns whether one local operation is awaiting a result.
    bool is_busy() const;

signals:
    /// Delivers a validated in-memory session and public user identity.
    void authenticated(const tcp_chat::protocol::AuthenticationResult& result);
    /// Confirms that the server revoked the supplied session.
    void logged_out();
    /// Reports a safe terminal error for the pending operation.
    void failed(const QString& message);
    /// Publishes local request activity without exposing credentials.
    void busy_changed(bool busy);

private:
    /// Identifies the operation that may consume the next correlated response.
    enum class Operation {
        None,
        SignUp,
        LogIn,
        LogOut,
    };

    /// Validates and sends one local authentication request.
    std::optional<QString> send_request(Operation operation, protocol::MessageType type, const QJsonObject& payload);
    /// Handles a correlated authentication result or public error.
    void message_received(const protocol::Envelope& envelope);
    /// Finishes the pending operation before publishing new activity.
    void set_busy(bool busy);
    /// Completes the pending operation with a safe error.
    void fail(const QString& message);

    TlsClient* const client_;
    Operation operation_ = Operation::None;
    QString request_id_;
    quint64 next_request_id_ = 1;
};

} // namespace tcp_chat::client

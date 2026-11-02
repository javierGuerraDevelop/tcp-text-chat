#pragma once

#include "local_authentication_client.h"
#include "oauth_client.h"

#include <QObject>

#include <functional>
#include <optional>

namespace tcp_chat::client {

/// Coordinates connection and authentication state while keeping the chat session in memory.
class AuthenticationController final : public QObject {
    Q_OBJECT

public:
    /// Describes the single authentication flow presented by the application.
    enum class State {
        Disconnected,
        Connecting,
        Ready,
        Authenticating,
        BrowserPending,
        Authenticated,
    };
    Q_ENUM(State)

    /// Creates an idle controller; the TLS client must outlive it and browser opening may be injected.
    explicit AuthenticationController(TlsClient* client, std::function<bool(const QUrl&)> browser_opener = { }, QObject* parent = nullptr);
    /// Releases the controller and its in-memory session using value ownership.
    ~AuthenticationController() override = default;

    /// Starts or replaces an encrypted server connection and clears any previous session.
    void connect_to_server(const TlsClientConfiguration& configuration);
    /// Starts local sign-in after the connection is ready.
    void log_in(const QString& username, const QString& password);
    /// Starts local account creation after the connection is ready.
    void sign_up(const QString& username, const QString& password, const std::optional<QString>& display_name = std::nullopt);
    /// Starts a system-browser OAuth flow through the connected server.
    void sign_in_with_provider(const QString& provider);
    /// Cancels pending work, clears session state, and reconnects when configured.
    void cancel();
    /// Revokes the current in-memory session on the server.
    void log_out();

    /// Returns the current connection and authentication state.
    State state() const;
    /// Returns whether connection or authentication work is in progress.
    bool is_busy() const;
    /// Returns the public identity for the current session, if authenticated.
    std::optional<tcp_chat::protocol::UserIdentity> user() const;
    /// Returns the current session's expiry timestamp, or zero without a session.
    qint64 session_expires_at() const;

signals:
    /// Publishes high-level state without exposing session tokens or credentials.
    void state_changed(tcp_chat::client::AuthenticationController::State state);
    /// Delivers the public identity after a session has been issued.
    void authenticated(const tcp_chat::protocol::UserIdentity& user);
    /// Reports a safe credential or provider error while authentication can be retried.
    void authentication_failed(const QString& message);
    /// Reports a transport failure that requires reconnecting.
    void connection_failed(const QString& message);
    /// Confirms that the in-memory session was revoked and removed.
    void logged_out();

private:
    /// Changes and publishes state only when it differs.
    void set_state(State state);
    /// Stores a validated session and publishes its public identity.
    void complete_authentication(const protocol::AuthenticationResult& result);
    /// Handles a rejected or failed local request according to connection state.
    void local_failed(const QString& message);
    /// Handles an OAuth failure after its socket has been reset.
    void oauth_failed(const QString& message);
    /// Clears session state and reports a transport failure.
    void fail_connection(const QString& message);
    /// Erases the controller's session references.
    void clear_session();

    TlsClient* const client_;
    LocalAuthenticationClient local_;
    OAuthClient oauth_;
    std::optional<TlsClientConfiguration> configuration_;
    State state_ = State::Disconnected;
    QString session_token_;
    std::optional<protocol::UserIdentity> user_;
    qint64 session_expires_at_ = 0;
    bool reconnect_pending_    = false;
};

} // namespace tcp_chat::client

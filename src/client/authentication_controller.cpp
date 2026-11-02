#include "authentication_controller.h"

#include <QTimer>

namespace tcp_chat::client {

AuthenticationController::AuthenticationController(TlsClient* client, std::function<bool(const QUrl&)> browser_opener, QObject* parent)
    : QObject(parent)
    , client_(client)
    , local_(client)
    , oauth_(client, std::move(browser_opener))
{
    connect(client_, &TlsClient::connected, this, [this]() {
        if (state_ == State::Connecting) {
            set_state(State::Ready);
        }
    });
    connect(client_, &TlsClient::error, this, &AuthenticationController::fail_connection);
    connect(client_, &TlsClient::protocol_error, this, [this](const protocol::ProtocolError& error) {
        client_->disconnect_from_host();
        fail_connection(error.message);
    });
    connect(client_, &TlsClient::disconnected, this, [this]() {
        if (reconnect_pending_) {
            reconnect_pending_ = false;
            QTimer::singleShot(0, this, [this]() {
                if (state_ == State::Disconnected && configuration_.has_value()) {
                    connect_to_server(*configuration_);
                }
            });
            return;
        }
        if (state_ != State::Disconnected) {
            fail_connection(QStringLiteral("The server closed the connection"));
        }
    });

    connect(&local_, &LocalAuthenticationClient::authenticated, this, &AuthenticationController::complete_authentication);
    connect(&local_, &LocalAuthenticationClient::failed, this, &AuthenticationController::local_failed);
    connect(&local_, &LocalAuthenticationClient::logged_out, this, [this]() {
        clear_session();
        set_state(State::Ready);
        emit logged_out();
    });

    connect(&oauth_, &OAuthClient::pending, this, [this]() {
        set_state(State::BrowserPending);
    });
    connect(&oauth_, &OAuthClient::authenticated, this, &AuthenticationController::complete_authentication);
    connect(&oauth_, &OAuthClient::failed, this, &AuthenticationController::oauth_failed);
}

void AuthenticationController::connect_to_server(const TlsClientConfiguration& configuration)
{
    configuration_ = configuration;
    local_.cancel();
    clear_session();
    if (client_->state() != TlsClient::State::Disconnected) {
        reconnect_pending_ = true;
        set_state(State::Disconnected);
        if (oauth_.is_busy()) {
            oauth_.cancel();
        }
        client_->disconnect_from_host();
        return;
    }

    reconnect_pending_ = false;
    if (oauth_.is_busy()) {
        oauth_.cancel();
    }
    set_state(State::Connecting);
    if (const auto error = client_->connect_to_host(configuration); error.has_value()) {
        fail_connection(*error);
    }
}

void AuthenticationController::log_in(const QString& username, const QString& password)
{
    if (state_ != State::Ready) {
        emit authentication_failed(QStringLiteral("Connect to the server before signing in"));
        return;
    }
    set_state(State::Authenticating);
    if (const auto error = local_.log_in(username, password); error.has_value()) {
        set_state(State::Ready);
        emit authentication_failed(*error);
    }
}

void AuthenticationController::sign_up(const QString& username, const QString& password, const std::optional<QString>& display_name)
{
    if (state_ != State::Ready) {
        emit authentication_failed(QStringLiteral("Connect to the server before creating an account"));
        return;
    }
    set_state(State::Authenticating);
    if (const auto error = local_.sign_up(username, password, display_name); error.has_value()) {
        set_state(State::Ready);
        emit authentication_failed(*error);
    }
}

void AuthenticationController::sign_in_with_provider(const QString& provider)
{
    if (state_ != State::Ready) {
        emit authentication_failed(QStringLiteral("Connect to the server before using browser sign-in"));
        return;
    }
    set_state(State::Authenticating);
    if (const auto error = oauth_.start(provider); error.has_value()) {
        set_state(State::Ready);
        emit authentication_failed(*error);
    }
}

void AuthenticationController::cancel()
{
    if (configuration_.has_value()) {
        connect_to_server(*configuration_);
        return;
    }
    local_.cancel();
    if (oauth_.is_busy()) {
        oauth_.cancel();
    }
    client_->disconnect_from_host();
    clear_session();
    set_state(State::Disconnected);
}

void AuthenticationController::log_out()
{
    if (state_ != State::Authenticated || session_token_.isEmpty()) {
        return;
    }
    set_state(State::Authenticating);
    if (const auto error = local_.log_out(session_token_); error.has_value()) {
        set_state(State::Authenticated);
        emit authentication_failed(*error);
    }
}

AuthenticationController::State AuthenticationController::state() const
{
    return state_;
}

bool AuthenticationController::is_busy() const
{
    return state_ == State::Connecting || state_ == State::Authenticating || state_ == State::BrowserPending;
}

std::optional<tcp_chat::protocol::UserIdentity> AuthenticationController::user() const
{
    return user_;
}

qint64 AuthenticationController::session_expires_at() const
{
    return session_expires_at_;
}

void AuthenticationController::set_state(State state)
{
    if (state_ == state) {
        return;
    }
    state_ = state;
    emit state_changed(state_);
}

void AuthenticationController::complete_authentication(const protocol::AuthenticationResult& result)
{
    if (!result.user.has_value() || !result.session_token.has_value() || !result.expires_at.has_value()) {
        fail_connection(QStringLiteral("The server returned an invalid session"));
        return;
    }
    session_token_      = *result.session_token;
    user_               = *result.user;
    session_expires_at_ = *result.expires_at;
    set_state(State::Authenticated);
    emit authenticated(*user_);
}

void AuthenticationController::local_failed(const QString& message)
{
    if (client_->state() != TlsClient::State::Connected) {
        fail_connection(message);
        return;
    }
    set_state(user_.has_value() ? State::Authenticated : State::Ready);
    emit authentication_failed(message);
}

void AuthenticationController::oauth_failed(const QString& message)
{
    set_state(State::Disconnected);
    emit authentication_failed(message);
    QTimer::singleShot(0, this, [this]() {
        if (state_ == State::Disconnected && configuration_.has_value()) {
            connect_to_server(*configuration_);
        }
    });
}

void AuthenticationController::fail_connection(const QString& message)
{
    if (reconnect_pending_) {
        return;
    }
    clear_session();
    set_state(State::Disconnected);
    emit connection_failed(message);
}

void AuthenticationController::clear_session()
{
    session_token_.fill(QChar('\0'));
    session_token_.clear();
    user_.reset();
    session_expires_at_ = 0;
}

} // namespace tcp_chat::client

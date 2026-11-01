#include "oauth_client.h"

#include <QDesktopServices>

namespace tcp_chat::client {

OAuthClient::OAuthClient(TlsClient* client, std::function<bool(const QUrl&)> browser_opener, QObject* parent)
    : QObject(parent)
    , client_(client)
    , browser_opener_(std::move(browser_opener))
{
    if (!browser_opener_) {
        browser_opener_ = [](const QUrl& url) { return QDesktopServices::openUrl(url); };
    }
    poll_timer_.setInterval(1000);
    poll_timer_.setSingleShot(false);
    connect(&poll_timer_, &QTimer::timeout, this, &OAuthClient::poll);
    connect(client_, &TlsClient::message_received, this, &OAuthClient::message_received);
    connect(client_, &TlsClient::disconnected, this, [this] {
        if (state_ != State::Idle) {
            fail(QStringLiteral("The connection closed before sign-in completed"));
        }
    });
}

std::optional<QString> OAuthClient::start(const QString& provider)
{
    if (client_ == nullptr || client_->state() != TlsClient::State::Connected || state_ != State::Idle
        || provider.isEmpty() || provider.size() > 32) {
        return QStringLiteral("An idle, connected client and provider are required");
    }
    state_      = State::Starting;
    request_id_ = QStringLiteral("oauth-%1").arg(next_request_id_++);
    protocol::Envelope request;
    request.type       = protocol::MessageType::AuthOAuthStart;
    request.request_id = request_id_;
    request.payload    = QJsonObject { { QStringLiteral("provider"), provider } };
    if (const auto error = client_->send(request); error.has_value()) {
        state_ = State::Idle;
        return error->message;
    }
    return std::nullopt;
}

void OAuthClient::message_received(const protocol::Envelope& envelope)
{
    if (state_ == State::Idle || envelope.request_id != request_id_) {
        return;
    }
    if (envelope.type == protocol::MessageType::Error) {
        fail(envelope.payload.value(QStringLiteral("message")).toString(QStringLiteral("Sign-in could not be completed")));
        return;
    }
    if (state_ == State::Completing) {
        const auto result = protocol::authentication_result_from_envelope(envelope);
        if (!result.has_value() || !result->session_token.has_value()) {
            fail(QStringLiteral("The sign-in response was invalid"));
            return;
        }
        const auto completed = *result;
        state_               = State::Idle;
        flow_handle_.fill(QChar('\0'));
        flow_handle_.clear();
        request_id_.clear();
        emit authenticated(completed);
        return;
    }
    const auto result = protocol::oauth_result_from_envelope(envelope);
    if (!result.has_value() || (state_ == State::Starting && result->status != QStringLiteral("started"))
        || (state_ == State::Polling
            && (result->flow_handle != flow_handle_ || result->status == QStringLiteral("started")))) {
        fail(QStringLiteral("The sign-in response was invalid"));
        return;
    }
    if (result->status == QStringLiteral("failed")) {
        fail(QStringLiteral("Sign-in was not completed"));
        return;
    }
    if (state_ == State::Starting) {
        flow_handle_ = result->flow_handle;
        if (!browser_opener_(QUrl(*result->authorization_url))) {
            fail(QStringLiteral("The system browser could not be opened"));
            return;
        }
        state_ = State::Polling;
        poll_timer_.start();
        emit pending();
        return;
    }
    if (result->status == QStringLiteral("ready")) {
        poll_timer_.stop();
        handoff_ = *result->handoff;
        protocol::Envelope request;
        request.type       = protocol::MessageType::AuthOAuthComplete;
        request.request_id = request_id_;
        request.payload    = QJsonObject { { QStringLiteral("flow"), flow_handle_ }, { QStringLiteral("handoff"), handoff_ } };
        state_             = State::Completing;
        if (const auto error = client_->send(request); error.has_value()) {
            fail(error->message);
        }
    }
}

void OAuthClient::poll()
{
    if (state_ != State::Polling) {
        return;
    }
    protocol::Envelope request;
    request.type       = protocol::MessageType::AuthOAuthStatus;
    request.request_id = request_id_;
    request.payload    = QJsonObject { { QStringLiteral("flow"), flow_handle_ } };
    if (const auto error = client_->send(request); error.has_value()) {
        fail(error->message);
    }
}

void OAuthClient::cancel()
{
    if (state_ == State::Idle) {
        return;
    }
    state_ = State::Idle;
    poll_timer_.stop();
    flow_handle_.fill(QChar('\0'));
    handoff_.fill(QChar('\0'));
    flow_handle_.clear();
    handoff_.clear();
    request_id_.clear();
    client_->disconnect_from_host();
}

bool OAuthClient::is_busy() const
{
    return state_ != State::Idle;
}

void OAuthClient::fail(const QString& message)
{
    const bool disconnect = state_ != State::Idle;
    state_                = State::Idle;
    poll_timer_.stop();
    flow_handle_.fill(QChar('\0'));
    handoff_.fill(QChar('\0'));
    flow_handle_.clear();
    handoff_.clear();
    request_id_.clear();
    if (disconnect) {
        client_->disconnect_from_host();
    }
    emit failed(message);
}

} // namespace tcp_chat::client

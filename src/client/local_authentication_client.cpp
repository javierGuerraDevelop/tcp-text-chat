#include "local_authentication_client.h"

namespace tcp_chat::client {

LocalAuthenticationClient::LocalAuthenticationClient(TlsClient* client, QObject* parent)
    : QObject(parent)
    , client_(client)
{
    connect(client_, &TlsClient::message_received, this, &LocalAuthenticationClient::message_received);
    connect(client_, &TlsClient::disconnected, this, [this]() {
        if (is_busy()) {
            fail(QStringLiteral("The connection closed before authentication completed"));
        }
    });
}

std::optional<QString> LocalAuthenticationClient::sign_up(const QString& username, const QString& password, const std::optional<QString>& display_name)
{
    QJsonObject payload {
        { QStringLiteral("username"), username },
        { QStringLiteral("password"), password },
    };
    if (display_name.has_value()) {
        payload.insert(QStringLiteral("displayName"), *display_name);
    }
    protocol::Envelope request;
    request.type    = protocol::MessageType::AuthSignUp;
    request.payload = payload;
    if (!protocol::sign_up_from_envelope(request).has_value()) {
        return QStringLiteral("Signup credentials are invalid");
    }
    return send_request(Operation::SignUp, request.type, payload);
}

std::optional<QString> LocalAuthenticationClient::log_in(const QString& username, const QString& password)
{
    const QJsonObject payload {
        { QStringLiteral("username"), username },
        { QStringLiteral("password"), password },
    };
    protocol::Envelope request;
    request.type    = protocol::MessageType::AuthLogIn;
    request.payload = payload;
    if (!protocol::log_in_from_envelope(request).has_value()) {
        return QStringLiteral("Login fields are invalid");
    }
    return send_request(Operation::LogIn, request.type, payload);
}

std::optional<QString> LocalAuthenticationClient::log_out(const QString& session_token)
{
    const QJsonObject payload { { QStringLiteral("sessionToken"), session_token } };
    protocol::Envelope request;
    request.type    = protocol::MessageType::AuthLogOut;
    request.payload = payload;
    if (!protocol::session_token_from_envelope(request).has_value()) {
        return QStringLiteral("The session token is invalid");
    }
    return send_request(Operation::LogOut, request.type, payload);
}

void LocalAuthenticationClient::cancel()
{
    set_busy(false);
    request_id_.clear();
}

bool LocalAuthenticationClient::is_busy() const
{
    return operation_ != Operation::None;
}

std::optional<QString> LocalAuthenticationClient::send_request(Operation operation, protocol::MessageType type, const QJsonObject& payload)
{
    if (client_ == nullptr || client_->state() != TlsClient::State::Connected || is_busy()) {
        return QStringLiteral("An idle, connected client is required");
    }

    operation_  = operation;
    request_id_ = QStringLiteral("local-%1").arg(next_request_id_++);
    protocol::Envelope request;
    request.type       = type;
    request.request_id = request_id_;
    request.payload    = payload;
    set_busy(true);
    if (const auto error = client_->send(request); error.has_value()) {
        cancel();
        return error->message;
    }
    return std::nullopt;
}

void LocalAuthenticationClient::message_received(const protocol::Envelope& envelope)
{
    if (!is_busy() || envelope.request_id != request_id_) {
        return;
    }
    if (envelope.type == protocol::MessageType::Error) {
        fail(envelope.payload.value(QStringLiteral("message")).toString(QStringLiteral("Authentication could not be completed")));
        return;
    }

    const auto result         = protocol::authentication_result_from_envelope(envelope);
    const Operation completed = operation_;
    cancel();
    if (!result.has_value()) {
        client_->disconnect_from_host();
        emit failed(QStringLiteral("The authentication response was invalid"));
        return;
    }
    if (completed == Operation::LogOut && result->revoked) {
        emit logged_out();
        return;
    }
    if (completed != Operation::LogOut && result->user.has_value() && result->session_token.has_value()) {
        emit authenticated(*result);
        return;
    }

    client_->disconnect_from_host();
    emit failed(QStringLiteral("The authentication response was invalid"));
}

void LocalAuthenticationClient::set_busy(bool busy)
{
    if (is_busy() == busy) {
        return;
    }
    if (!busy) {
        operation_ = Operation::None;
    }
    emit busy_changed(busy);
}

void LocalAuthenticationClient::fail(const QString& message)
{
    cancel();
    emit failed(message);
}

} // namespace tcp_chat::client

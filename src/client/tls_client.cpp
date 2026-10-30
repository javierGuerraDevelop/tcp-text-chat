#include "client/tls_client.h"

#include <QSslCertificate>
#include <QSslConfiguration>

#include <algorithm>
#include <functional>
#include <limits>

namespace tcp_chat::client {

TlsClient::TlsClient(QObject* parent)
    : QObject(parent)
    , socket_(new QSslSocket(this))
    , session_(socket_, transport::SessionOptions { }, this)
{
    handshake_timer_.setSingleShot(true);
    connect(&handshake_timer_, &QTimer::timeout, this, [this] { fail(QStringLiteral("TLS negotiation timed out")); });
    connect(socket_, &QSslSocket::connected, this, [this] { set_state(State::Securing); });
    connect(socket_, &QSslSocket::encrypted, this, &TlsClient::encrypted);
    connect(socket_, &QSslSocket::sslErrors, this, &TlsClient::certificate_failed);
    connect(socket_, &QSslSocket::errorOccurred, this, &TlsClient::socket_error);
    connect(socket_, &QSslSocket::disconnected, this, &TlsClient::socket_disconnected);
    connect(&session_, &transport::FramedSocket::message_received, this, &TlsClient::message_received);
    connect(&session_, &transport::FramedSocket::protocol_error, this, &TlsClient::protocol_error);
}

std::optional<QString> TlsClient::connect_to_host(const TlsClientConfiguration& configuration)
{
    if (state_ != State::Disconnected || replacement_connect_queued_) {
        return QStringLiteral("The client is already connecting or connected");
    }
    if (configuration.host.trimmed().isEmpty() || configuration.port == 0) {
        return QStringLiteral("A server hostname and nonzero port are required");
    }
    const QString peer_name = configuration.peer_name.isEmpty() ? configuration.host : configuration.peer_name;
    if (peer_name.trimmed().isEmpty()) {
        return QStringLiteral("The certificate verification name must not be empty");
    }
    if (configuration.handshake_timeout <= std::chrono::milliseconds::zero()
        || configuration.handshake_timeout > std::chrono::milliseconds { std::numeric_limits<int>::max() }) {
        return QStringLiteral("The TLS negotiation timeout is invalid");
    }
    if (const auto error = transport::validate_session_options(configuration.session); error.has_value()) {
        return error->message;
    }

    QList<QSslCertificate> trusted_certificates;
    if (!configuration.ca_certificate_file.isEmpty()) {
        trusted_certificates = QSslCertificate::fromPath(configuration.ca_certificate_file, QSsl::Pem);
        if (trusted_certificates.isEmpty()
            || std::any_of(trusted_certificates.cbegin(), trusted_certificates.cend(), std::mem_fn(&QSslCertificate::isNull))) {
            return QStringLiteral("The trusted CA certificate file could not be loaded");
        }
    }

    if (handling_disconnected_) {
        replacement_connect_queued_ = true;
        QTimer::singleShot(0, this, [this, configuration] {
            replacement_connect_queued_ = false;
            if (const auto error = connect_to_host(configuration); error.has_value()) {
                emit this->error(*error);
            }
        });
        return std::nullopt;
    }

    socket_->abort();
    if (const auto error = session_.set_options(configuration.session); error.has_value()) {
        return error->message;
    }
    certificate_error_    = false;
    QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
    ssl.setProtocol(QSsl::TlsV1_2OrLater);
    if (!trusted_certificates.isEmpty()) {
        ssl.setCaCertificates(trusted_certificates);
    }
    socket_->setSslConfiguration(ssl);
    socket_->setPeerVerifyMode(QSslSocket::VerifyPeer);
    socket_->setPeerVerifyName(peer_name);
    set_state(State::Connecting);
    handshake_timer_.start(static_cast<int>(configuration.handshake_timeout.count()));
    socket_->connectToHostEncrypted(configuration.host, configuration.port);
    return std::nullopt;
}

std::optional<protocol::ProtocolError> TlsClient::send(const protocol::Envelope& envelope)
{
    if (state_ != State::Connected) {
        return protocol::ProtocolError { protocol::ErrorCode::InvalidRequest,
            QStringLiteral("The client is not connected") };
    }
    return session_.send(envelope);
}

void TlsClient::disconnect_from_host()
{
    if (state_ == State::Disconnected || state_ == State::Closing) {
        return;
    }
    handshake_timer_.stop();
    set_state(State::Closing);
    if (socket_->isEncrypted()) {
        session_.close();
    } else {
        socket_->abort();
        if (socket_->state() == QAbstractSocket::UnconnectedState) {
            socket_disconnected();
        }
    }
}

TlsClient::State TlsClient::state() const
{
    return state_;
}

void TlsClient::set_state(State state)
{
    if (state_ == state) {
        return;
    }
    state_ = state;
    emit state_changed(state_);
}

void TlsClient::fail(const QString& message)
{
    if (state_ == State::Disconnected) {
        return;
    }
    emit error(message);
    handshake_timer_.stop();
    socket_->abort();
    if (socket_->state() == QAbstractSocket::UnconnectedState) {
        socket_disconnected();
    }
}

void TlsClient::encrypted()
{
    handshake_timer_.stop();
    if (const auto error = session_.start(); error.has_value()) {
        fail(error->message);
        return;
    }
    set_state(State::Connected);
    if (state_ == State::Connected && session_.is_active()) {
        emit connected();
    }
}

void TlsClient::certificate_failed()
{
    certificate_error_ = true;
    emit error(QStringLiteral("The server certificate or hostname could not be verified"));
}

void TlsClient::socket_error(QAbstractSocket::SocketError socket_error)
{
    if (state_ == State::Disconnected) {
        return;
    }
    if (certificate_error_) {
        certificate_error_ = false;
    } else if (socket_error != QAbstractSocket::RemoteHostClosedError) {
        emit error(socket_->errorString());
    }
    if (socket_->state() == QAbstractSocket::UnconnectedState) {
        socket_disconnected();
    }
}

void TlsClient::socket_disconnected()
{
    if (state_ == State::Disconnected) {
        return;
    }
    handling_disconnected_ = true;
    handshake_timer_.stop();
    certificate_error_ = false;
    set_state(State::Disconnected);
    emit disconnected();
    handling_disconnected_ = false;
}

} // namespace tcp_chat::client

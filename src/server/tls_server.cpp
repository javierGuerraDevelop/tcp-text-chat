#include "server/tls_server.h"

#include <QFile>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslSocket>

#include <algorithm>
#include <limits>

namespace tcp_chat::server {

/// Owns one incoming TLS socket, its negotiation deadline, and its framed session.
class TlsConnection : public QObject {
    Q_OBJECT

public:
    /// Prepares an unconnected socket for TLS negotiation on the server's thread.
    TlsConnection(quint64 id, const TlsServerConfiguration& configuration, const QSslConfiguration& ssl, TlsServer* parent)
        : QObject(parent)
        , id_(id)
        , socket_(new QSslSocket(this))
        , session_(socket_, configuration.session, this)
    {
        timer_.setSingleShot(true);
        socket_->setSslConfiguration(ssl);
        connect(&timer_, &QTimer::timeout, this, [this] { fail(); });
        connect(socket_, &QSslSocket::encrypted, this, &TlsConnection::encrypted);
        connect(socket_, &QSslSocket::sslErrors, this, [this] { fail(); });
        connect(socket_, &QSslSocket::errorOccurred, this, [this](QAbstractSocket::SocketError error) {
            if (error != QAbstractSocket::RemoteHostClosedError && !announced_) {
                fail();
            }
        });
        connect(socket_, &QSslSocket::disconnected, this, &TlsConnection::finish_if_unconnected);
        connect(&session_, &transport::FramedSocket::message_received,
            this, [this](const protocol::Envelope& envelope) { emit message(id_, envelope); });
        connect(&session_, &transport::FramedSocket::protocol_error,
            this, [this](const protocol::ProtocolError& error) { emit protocol_failure(id_, error); });
    }

    /// Starts negotiation after the server has connected all lifecycle handlers.
    void start(qintptr descriptor, std::chrono::milliseconds handshake_timeout)
    {
        if (finished_) {
            return;
        }
        if (!socket_->setSocketDescriptor(descriptor)) {
            fail();
            return;
        }
        timer_.start(static_cast<int>(handshake_timeout.count()));
        socket_->startServerEncryption();
    }

    /// Starts framed communication once the peer has completed TLS negotiation.
    void encrypted()
    {
        if (finished_) {
            return;
        }
        timer_.stop();
        if (const auto error = session_.start(); error.has_value()) {
            fail();
            return;
        }
        announced_ = true;
        emit established(this);
    }

    /// Queues an envelope for this established client.
    std::optional<protocol::ProtocolError> send(const protocol::Envelope& envelope)
    {
        return session_.send(envelope);
    }

    /// Flushes established output, or aborts an incomplete handshake.
    void close()
    {
        if (finished_) {
            return;
        }
        timer_.stop();
        if (socket_->state() == QAbstractSocket::UnconnectedState) {
            finish_if_unconnected();
        } else if (socket_->state() == QAbstractSocket::ClosingState) {
            return;
        } else if (socket_->isEncrypted()) {
            session_.close();
        } else {
            socket_->abort();
            finish_connection();
        }
    }

    /// Returns the identifier assigned by the server.
    quint64 id() const
    {
        return id_;
    }

    /// Returns whether this connection has been announced to the application.
    bool is_announced() const
    {
        return announced_;
    }

    /// Returns the connected peer's address.
    QHostAddress peer_address() const
    {
        return socket_->peerAddress();
    }

    /// Returns the connected peer's port.
    quint16 peer_port() const
    {
        return socket_->peerPort();
    }

signals:
    /// Emits after the framed session is ready for application messages.
    void established(TlsConnection* connection);
    /// Emits an application message with this connection's identifier.
    void message(quint64 id, const protocol::Envelope& envelope);
    /// Emits a protocol failure with this connection's identifier.
    void protocol_failure(quint64 id, const protocol::ProtocolError& error);
    /// Reports a negotiation failure without certificate or transport details.
    void negotiation_failed();
    /// Emits once the owned socket has disconnected.
    void finished(TlsConnection* connection);

private:
    /// Stops negotiation and closes the socket after a local or TLS failure.
    void fail()
    {
        if (finished_) {
            return;
        }
        timer_.stop();
        if (!failure_reported_) {
            failure_reported_ = true;
            emit negotiation_failed();
        }
        socket_->abort();
        finish_connection();
    }

    /// Retires the connection when its socket reports disconnection.
    void finish_if_unconnected()
    {
        if (socket_->state() == QAbstractSocket::UnconnectedState) {
            finish_connection();
        }
    }

    /// Emits terminal cleanup exactly once.
    void finish_connection()
    {
        if (finished_) {
            return;
        }
        finished_ = true;
        emit finished(this);
    }

    quint64 id_;
    QSslSocket* const socket_;
    transport::FramedSocket session_;
    QTimer timer_;
    bool announced_        = false;
    bool failure_reported_ = false;
    bool finished_         = false;
};

TlsServer::TlsServer(QObject* parent)
    : QTcpServer(parent)
{
}

std::optional<QString> TlsServer::start(const TlsServerConfiguration& configuration)
{
    if (isListening() || !connections_.isEmpty()) {
        return QStringLiteral("The server is already running or shutting down");
    }
    if (configuration.address.isNull() || configuration.maximum_connections <= 0
        || configuration.maximum_connections > 4096 || configuration.maximum_pending_connections <= 0
        || configuration.maximum_pending_connections > configuration.maximum_connections) {
        return QStringLiteral("The listener address or connection limits are invalid");
    }
    if (configuration.handshake_timeout <= std::chrono::milliseconds::zero()
        || configuration.handshake_timeout > std::chrono::milliseconds { std::numeric_limits<int>::max() }) {
        return QStringLiteral("The TLS negotiation timeout is invalid");
    }
    if (const auto error = transport::validate_session_options(configuration.session); error.has_value()) {
        return error->message;
    }

    const QList<QSslCertificate> chain = QSslCertificate::fromPath(configuration.certificate_chain_file, QSsl::Pem);
    if (chain.isEmpty() || std::any_of(chain.cbegin(), chain.cend(), std::mem_fn(&QSslCertificate::isNull))) {
        return QStringLiteral("The server certificate chain could not be loaded");
    }
    QFile key_file(configuration.private_key_file);
    if (!key_file.open(QIODevice::ReadOnly)) {
        return QStringLiteral("The server private key could not be opened");
    }
    const QSslKey key(&key_file, configuration.private_key_algorithm, QSsl::Pem, QSsl::PrivateKey);
    if (key.isNull()) {
        return QStringLiteral("The server private key could not be loaded");
    }

    QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
    ssl.setProtocol(QSsl::TlsV1_2OrLater);
    ssl.setLocalCertificateChain(chain);
    ssl.setPrivateKey(key);
    ssl.setPeerVerifyMode(QSslSocket::VerifyNone);
    ssl_configuration_ = ssl;
    configuration_     = configuration;
    setMaxPendingConnections(configuration.maximum_pending_connections);
    if (!listen(configuration.address, configuration.port)) {
        return QStringLiteral("The server could not listen: %1").arg(errorString());
    }
    closing_ = false;
    return std::nullopt;
}

std::optional<protocol::ProtocolError> TlsServer::send(quint64 connection_id, const protocol::Envelope& envelope)
{
    TlsConnection* connection = connections_.value(connection_id, nullptr);
    if (connection == nullptr || !connection->is_announced()) {
        return protocol::ProtocolError { protocol::ErrorCode::InvalidRequest,
            QStringLiteral("The client connection does not exist") };
    }
    return connection->send(envelope);
}

void TlsServer::disconnect_client(quint64 connection_id)
{
    if (TlsConnection* connection = connections_.value(connection_id, nullptr); connection != nullptr) {
        connection->close();
    }
}

void TlsServer::close()
{
    QTcpServer::close();
    closing_               = true;
    const auto connections = connections_.values();
    for (TlsConnection* connection : connections) {
        connection->close();
    }
    finish_close();
}

int TlsServer::active_connections() const
{
    return static_cast<int>(std::count_if(connections_.cbegin(), connections_.cend(),
        [](const TlsConnection* connection) { return connection->is_announced(); }));
}

void TlsServer::incomingConnection(qintptr descriptor)
{
    if (closing_ || connections_.size() >= configuration_.maximum_connections) {
        auto* socket = new QSslSocket(this);
        socket->setSocketDescriptor(descriptor);
        socket->abort();
        socket->deleteLater();
        return;
    }

    const quint64 id = next_connection_id_++;
    auto* connection = new TlsConnection(id, configuration_, ssl_configuration_, this);
    connections_.insert(id, connection);
    connect(connection, &TlsConnection::established, this, [this](TlsConnection* connection) {
        emit client_connected(connection->id(), connection->peer_address(), connection->peer_port());
    });
    connect(connection, &TlsConnection::message, this, &TlsServer::message_received);
    connect(connection, &TlsConnection::protocol_failure, this, &TlsServer::client_protocol_error);
    connect(connection, &TlsConnection::negotiation_failed,
        this, [this] { emit connection_error(QStringLiteral("An incoming TLS connection could not be established")); });
    connect(connection, &TlsConnection::finished, this, [this](TlsConnection* connection) {
        const quint64 id     = connection->id();
        const bool announced = connection->is_announced();
        connections_.remove(id);
        connection->deleteLater();
        if (announced) {
            emit client_disconnected(id);
        }
        finish_close();
    });
    connection->start(descriptor, configuration_.handshake_timeout);
}

void TlsServer::finish_close()
{
    closing_ = closing_ && !connections_.isEmpty();
}

} // namespace tcp_chat::server

#include "tls_server.moc"

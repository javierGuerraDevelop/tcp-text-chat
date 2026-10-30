#pragma once

#include "tcp_chat/framed_socket.h"

#include <QHash>
#include <QHostAddress>
#include <QSsl>
#include <QSslConfiguration>
#include <QTcpServer>

#include <chrono>
#include <optional>

namespace tcp_chat::server {

class TlsConnection;

/// Supplies server-owned TLS credentials and bounded connection timing.
struct TlsServerConfiguration {
    QHostAddress address = QHostAddress::AnyIPv4;
    quint16 port         = 0;
    QString certificate_chain_file;
    QString private_key_file;
    QSsl::KeyAlgorithm private_key_algorithm = QSsl::Rsa;
    int maximum_connections                  = 64;
    int maximum_pending_connections          = 32;
    std::chrono::milliseconds handshake_timeout { 10000 };
    transport::SessionOptions session;
};

/// Accepts asynchronous TLS clients and manages their framed sessions on the server thread.
class TlsServer : public QTcpServer {
    Q_OBJECT

public:
    /// Creates a stopped server without loading deployment credentials.
    explicit TlsServer(QObject* parent = nullptr);

    /// Validates credentials and starts listening, returning local errors synchronously.
    std::optional<QString> start(const TlsServerConfiguration& configuration);

    /// Queues an envelope for an established client, or reports a local error.
    std::optional<protocol::ProtocolError> send(quint64 connection_id, const protocol::Envelope& envelope);

    /// Flushes one client's output before disconnecting it.
    void disconnect_client(quint64 connection_id);

    /// Stops accepting clients and gracefully closes established sessions.
    void close();

    /// Returns the number of clients that completed TLS negotiation.
    int active_connections() const;

signals:
    /// Emits a server-issued identifier and peer address after TLS negotiation.
    void client_connected(quint64 connection_id, const QHostAddress& address, quint16 port);
    /// Emits a validated envelope or pong from an established client.
    void message_received(quint64 connection_id, const protocol::Envelope& envelope);
    /// Reports a peer protocol error associated with an established client.
    void client_protocol_error(quint64 connection_id, const protocol::ProtocolError& error);
    /// Emits after an established client disconnects and its identifier is retired.
    void client_disconnected(quint64 connection_id);
    /// Reports a local listener or incoming TLS negotiation failure.
    void connection_error(const QString& message);

protected:
    /// Creates an encrypted child socket for an accepted native descriptor.
    void incomingConnection(qintptr descriptor) override;

private:
    /// Finishes server shutdown once no established clients remain.
    void finish_close();

    QSslConfiguration ssl_configuration_;
    TlsServerConfiguration configuration_;
    QHash<quint64, TlsConnection*> connections_;
    quint64 next_connection_id_ = 1;
    bool closing_               = false;
};

} // namespace tcp_chat::server

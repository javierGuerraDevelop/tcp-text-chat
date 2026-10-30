#pragma once

#include "tcp_chat/framed_socket.h"

#include <QObject>
#include <QSslSocket>

#include <chrono>
#include <optional>

namespace tcp_chat::client {

/// Configures a verified encrypted connection without persisting credentials.
struct TlsClientConfiguration {
    QString host;
    quint16 port = 0;
    QString peer_name;
    QString ca_certificate_file;
    std::chrono::milliseconds handshake_timeout { 10000 };
    transport::SessionOptions session;
};

/// Owns an asynchronous TLS client socket on its QObject thread.
class TlsClient : public QObject {
    Q_OBJECT

public:
    /// Describes the externally observable connection lifecycle.
    enum class State {
        Disconnected,
        Connecting,
        Securing,
        Connected,
        Closing,
    };
    Q_ENUM(State)

    /// Creates a disconnected client and its parent-owned socket.
    explicit TlsClient(QObject* parent = nullptr);

    /// Starts connection negotiation, deferring calls made during a disconnect notification.
    std::optional<QString> connect_to_host(const TlsClientConfiguration& configuration);

    /// Queues an envelope only after the encrypted session is established.
    std::optional<protocol::ProtocolError> send(const protocol::Envelope& envelope);

    /// Flushes an established session before disconnecting.
    void disconnect_from_host();

    /// Returns the current connection state.
    State state() const;

signals:
    /// Emits whenever the connection lifecycle changes.
    void state_changed(State state);
    /// Emits after the peer certificate and hostname have been verified.
    void connected();
    /// Emits a validated application envelope or pong.
    void message_received(const protocol::Envelope& envelope);
    /// Reports a protocol error without exposing sensitive transport data.
    void protocol_error(const protocol::ProtocolError& error);
    /// Reports local configuration, handshake, and socket failures.
    void error(const QString& message);
    /// Emits after the client returns to the disconnected state.
    void disconnected();

private:
    /// Changes and publishes the connection state when it differs.
    void set_state(State state);
    /// Reports a local error once and terminates the pending connection.
    void fail(const QString& message);
    /// Starts framed communication after successful TLS negotiation.
    void encrypted();
    /// Reports a certificate failure without disabling verification.
    void certificate_failed();
    /// Reports asynchronous socket failures.
    void socket_error(QAbstractSocket::SocketError socket_error);
    /// Cleans up connection state after the socket disconnects.
    void socket_disconnected();

    QSslSocket* const socket_;
    transport::FramedSocket session_;
    QTimer handshake_timer_;
    State state_                     = State::Disconnected;
    bool certificate_error_          = false;
    bool handling_disconnected_      = false;
    bool replacement_connect_queued_ = false;
};

} // namespace tcp_chat::client

#pragma once

#include "tcp_chat/frame.h"

#include <QByteArray>
#include <QElapsedTimer>
#include <QObject>
#include <QSslSocket>
#include <QTimer>

#include <chrono>
#include <deque>

namespace tcp_chat::transport {

/// Defines bounded output and monotonic heartbeat timing for a framed connection.
struct SessionOptions {
    std::chrono::milliseconds heartbeat_interval { 15000 };
    std::chrono::milliseconds heartbeat_timeout { 45000 };
    std::chrono::milliseconds shutdown_timeout { 3000 };
    qsizetype maximum_pending_output = protocol::maximum_buffered_size * 4;
};

/// Tracks connection activity against an externally supplied monotonic clock.
class Heartbeat {
public:
    /// Starts activity tracking with a heartbeat timeout greater than its ping interval.
    Heartbeat(std::chrono::milliseconds interval, std::chrono::milliseconds timeout, qint64 now = 0);

    /// Records incoming network activity at the supplied monotonic time.
    void receive(qint64 now);

    /// Returns whether the ping interval has elapsed since the last ping.
    bool should_ping(qint64 now) const;

    /// Records a sent ping at the supplied monotonic time.
    void record_ping(qint64 now);

    /// Returns whether the connection has reached its inactivity deadline.
    bool expired(qint64 now) const;

private:
    qint64 interval_;
    qint64 timeout_;
    qint64 last_activity_;
    qint64 last_ping_;
};

/// Validates session limits without touching a socket.
std::optional<protocol::ProtocolError> validate_session_options(const SessionOptions& options);

/// Exchanges validated envelopes over an encrypted socket on its owning thread.
class FramedSocket : public QObject {
    Q_OBJECT

public:
    /// Wraps a socket owned by the caller; the socket must outlive this object.
    explicit FramedSocket(QSslSocket* socket, SessionOptions options = SessionOptions { }, QObject* parent = nullptr);

    /// Applies validated limits while the session is inactive and not closing.
    std::optional<protocol::ProtocolError> set_options(const SessionOptions& options);

    /// Begins processing an encrypted socket after validating its session limits.
    std::optional<protocol::ProtocolError> start();

    /// Queues a validated envelope, or reports why it cannot be accepted.
    std::optional<protocol::ProtocolError> send(const protocol::Envelope& envelope);

    /// Flushes bounded output before closing, subject to the shutdown deadline.
    void close();

    /// Returns plaintext and encrypted bytes awaiting delivery.
    qsizetype pending_output_bytes() const;

    /// Returns whether this session accepts outbound envelopes.
    bool is_active() const;

signals:
    /// Emits a validated application envelope or a pong.
    void message_received(const protocol::Envelope& envelope);
    /// Reports a wire, protocol, heartbeat, or local write failure before closing.
    void protocol_error(const protocol::ProtocolError& error);
    /// Emits once when the underlying socket disconnects.
    void disconnected();
    /// Emits the changed aggregate pending-output size.
    void pending_output_changed(qsizetype bytes);

private:
    /// Reads bounded chunks and drains complete frames before retrying input.
    void read_ready();
    /// Dispatches one decoded envelope and answers heartbeat requests.
    void handle_payload(const QByteArray& payload);
    /// Sends a protocol error and closes without accepting more application data.
    void fail(protocol::ProtocolError error);
    /// Writes queued data while respecting the aggregate output bound.
    void flush_output();
    /// Sends a ping or expires an inactive connection using a monotonic clock.
    void check_heartbeat();
    /// Aborts a connection that cannot finish graceful shutdown in time.
    void finish_close();
    /// Resets session state when the underlying socket disconnects.
    void socket_disconnected();
    /// Returns elapsed milliseconds since the encrypted session started.
    qint64 now() const;

    QSslSocket* const socket_;
    SessionOptions options_;
    protocol::FrameDecoder decoder_;
    std::deque<QByteArray> output_;
    qsizetype queued_output_bytes_ = 0;
    QTimer heartbeat_timer_;
    QTimer shutdown_timer_;
    QElapsedTimer elapsed_;
    std::optional<Heartbeat> heartbeat_;
    quint64 heartbeat_sequence_ = 0;
    bool active_                = false;
    bool closing_               = false;
};

} // namespace tcp_chat::transport

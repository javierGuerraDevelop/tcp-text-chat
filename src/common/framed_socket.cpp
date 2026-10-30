#include "tcp_chat/framed_socket.h"

#include <limits>

namespace tcp_chat::transport {
namespace {

    using protocol::Envelope;
    using protocol::ErrorCode;
    using protocol::ProtocolError;

    /// Creates a consistent error value for local transport operations.
    ProtocolError make_error(ErrorCode code, const QString& message)
    {
        return ProtocolError { code, message };
    }

    /// Constructs the protocol's standard error envelope.
    Envelope error_envelope(const ProtocolError& error)
    {
        Envelope envelope;
        envelope.type    = protocol::MessageType::Error;
        envelope.payload = QJsonObject {
            { QStringLiteral("code"), QString::fromLatin1(*protocol::error_code_name(error.code)) },
            { QStringLiteral("message"), error.message },
        };
        return envelope;
    }

} // namespace

Heartbeat::Heartbeat(std::chrono::milliseconds interval, std::chrono::milliseconds timeout, qint64 now)
    : interval_(interval.count())
    , timeout_(timeout.count())
    , last_activity_(now)
    , last_ping_(now)
{
}

void Heartbeat::receive(qint64 now)
{
    last_activity_ = now;
}

bool Heartbeat::should_ping(qint64 now) const
{
    return now - last_ping_ >= interval_;
}

void Heartbeat::record_ping(qint64 now)
{
    last_ping_ = now;
}

bool Heartbeat::expired(qint64 now) const
{
    return now - last_activity_ >= timeout_;
}

std::optional<ProtocolError> validate_session_options(const SessionOptions& options)
{
    constexpr auto maximum_timer = std::chrono::milliseconds { std::numeric_limits<int>::max() };
    if (options.heartbeat_interval <= std::chrono::milliseconds::zero()
        || options.heartbeat_timeout <= options.heartbeat_interval
        || options.heartbeat_timeout > maximum_timer
        || options.shutdown_timeout <= std::chrono::milliseconds::zero()
        || options.shutdown_timeout > maximum_timer) {
        return make_error(ErrorCode::InvalidRequest, QStringLiteral("Session heartbeat and shutdown timeouts are invalid"));
    }
    if (options.maximum_pending_output < protocol::maximum_buffered_size) {
        return make_error(ErrorCode::InvalidRequest, QStringLiteral("Session output bound must hold at least one frame"));
    }
    return std::nullopt;
}

FramedSocket::FramedSocket(QSslSocket* socket, SessionOptions options, QObject* parent)
    : QObject(parent)
    , socket_(socket)
    , options_(options)
{
    heartbeat_timer_.setSingleShot(false);
    shutdown_timer_.setSingleShot(true);
    connect(&heartbeat_timer_, &QTimer::timeout, this, &FramedSocket::check_heartbeat);
    connect(&shutdown_timer_, &QTimer::timeout, this, &FramedSocket::finish_close);
    connect(socket_, &QSslSocket::readyRead, this, &FramedSocket::read_ready);
    connect(socket_, &QSslSocket::bytesWritten, this, [this](qint64) { flush_output(); });
    connect(socket_, &QSslSocket::encryptedBytesWritten, this, [this](qint64) { flush_output(); });
    connect(socket_, &QSslSocket::disconnected, this, &FramedSocket::socket_disconnected);
}

std::optional<ProtocolError> FramedSocket::start()
{
    if (active_) {
        return make_error(ErrorCode::InvalidRequest, QStringLiteral("The session is already active"));
    }
    if (const auto error = validate_session_options(options_); error.has_value()) {
        return error;
    }
    if (!socket_->isEncrypted()) {
        return make_error(ErrorCode::InvalidRequest, QStringLiteral("The socket has not completed TLS negotiation"));
    }

    socket_->setReadBufferSize(protocol::maximum_buffered_size);
    decoder_.reset();
    closing_ = false;
    active_  = true;
    elapsed_.start();
    heartbeat_.emplace(options_.heartbeat_interval, options_.heartbeat_timeout, 0);
    heartbeat_timer_.start(static_cast<int>(options_.heartbeat_interval.count()));
    return std::nullopt;
}

std::optional<ProtocolError> FramedSocket::send(const Envelope& envelope)
{
    if (!active_ || closing_) {
        return make_error(ErrorCode::InvalidRequest, QStringLiteral("The session is not accepting outbound messages"));
    }

    ProtocolError error;
    const auto frame = protocol::encode_envelope(envelope, &error);
    if (!frame.has_value()) {
        return error;
    }
    if (frame->size() > options_.maximum_pending_output - pending_output_bytes()) {
        return make_error(ErrorCode::Unavailable, QStringLiteral("The outbound queue is full"));
    }

    output_.push_back(*frame);
    queued_output_bytes_ += frame->size();
    flush_output();
    return std::nullopt;
}

void FramedSocket::close()
{
    if (closing_) {
        return;
    }
    closing_ = true;
    active_  = false;
    heartbeat_timer_.stop();
    shutdown_timer_.start(static_cast<int>(options_.shutdown_timeout.count()));
    flush_output();
    finish_close();
}

qsizetype FramedSocket::pending_output_bytes() const
{
    return queued_output_bytes_ + socket_->bytesToWrite() + socket_->encryptedBytesToWrite();
}

bool FramedSocket::is_active() const
{
    return active_;
}

void FramedSocket::read_ready()
{
    while (active_ && socket_->bytesAvailable() > 0) {
        const QByteArray input = socket_->read(protocol::maximum_buffered_size);
        if (input.isEmpty()) {
            return;
        }
        heartbeat_->receive(now());

        qsizetype offset = 0;
        while (active_ && offset < input.size()) {
            const qsizetype consumed = decoder_.append(QByteArrayView(input.constData() + offset, input.size() - offset));
            offset += consumed;

            bool drained = false;
            while (active_) {
                const auto payload = decoder_.next_frame();
                if (!payload.has_value()) {
                    break;
                }
                drained = true;
                handle_payload(*payload);
            }
            if (const auto* error = decoder_.error(); error != nullptr && active_) {
                fail(*error);
            }
            if (consumed == 0 && !drained && active_) {
                fail(make_error(ErrorCode::InvalidFrame, QStringLiteral("The frame decoder cannot make progress")));
            }
        }
    }
}

void FramedSocket::handle_payload(const QByteArray& payload)
{
    ProtocolError error;
    const auto envelope = protocol::decode_envelope(payload, &error);
    if (!envelope.has_value()) {
        fail(error);
        return;
    }
    heartbeat_->receive(now());

    if (envelope->type == protocol::MessageType::Ping) {
        if (!envelope->payload.isEmpty()) {
            fail(make_error(ErrorCode::InvalidMessage, QStringLiteral("Ping payload must be empty")));
            return;
        }
        Envelope pong;
        pong.type       = protocol::MessageType::Pong;
        pong.request_id = envelope->request_id;
        if (const auto send_error = send(pong); send_error.has_value()) {
            fail(*send_error);
        }
        return;
    }
    emit message_received(*envelope);
}

void FramedSocket::fail(ProtocolError error)
{
    if (!active_) {
        return;
    }
    active_ = false;
    emit protocol_error(error);

    ProtocolError encoding_error;
    const auto frame = protocol::encode_envelope(error_envelope(error), &encoding_error);
    if (frame.has_value() && frame->size() <= options_.maximum_pending_output - pending_output_bytes()) {
        output_.push_back(*frame);
        queued_output_bytes_ += frame->size();
    }
    close();
}

void FramedSocket::flush_output()
{
    const qsizetype previous_pending = pending_output_bytes();
    while (!output_.empty() && pending_output_bytes() < options_.maximum_pending_output) {
        QByteArray& next     = output_.front();
        const qint64 written = socket_->write(next);
        if (written < 0) {
            if (active_) {
                fail(make_error(ErrorCode::Unavailable, QStringLiteral("The transport could not write outbound data")));
            } else {
                output_.clear();
                queued_output_bytes_ = 0;
                finish_close();
            }
            break;
        }
        if (written == 0) {
            break;
        }
        queued_output_bytes_ -= written;
        if (written == next.size()) {
            output_.pop_front();
        } else {
            next.remove(0, written);
        }
    }
    if (previous_pending != pending_output_bytes()) {
        emit pending_output_changed(pending_output_bytes());
    }
    if (closing_) {
        finish_close();
    }
}

void FramedSocket::check_heartbeat()
{
    if (!active_) {
        return;
    }
    if (heartbeat_->expired(now())) {
        fail(make_error(ErrorCode::Unavailable, QStringLiteral("The connection timed out waiting for network activity")));
        return;
    }
    if (!heartbeat_->should_ping(now())) {
        return;
    }

    heartbeat_->record_ping(now());
    Envelope ping;
    ping.type       = protocol::MessageType::Ping;
    ping.request_id = QStringLiteral("heartbeat-%1").arg(++heartbeat_sequence_);
    if (const auto error = send(ping); error.has_value()) {
        fail(*error);
    }
}

void FramedSocket::finish_close()
{
    if (!closing_) {
        return;
    }
    if (!shutdown_timer_.isActive()) {
        socket_->abort();
        return;
    }
    if (pending_output_bytes() > 0 || socket_->state() == QAbstractSocket::ClosingState) {
        return;
    }
    if (socket_->state() == QAbstractSocket::UnconnectedState) {
        shutdown_timer_.stop();
        return;
    }
    socket_->disconnectFromHost();
}

void FramedSocket::socket_disconnected()
{
    heartbeat_timer_.stop();
    shutdown_timer_.stop();
    active_  = false;
    closing_ = false;
    heartbeat_.reset();
    output_.clear();
    queued_output_bytes_ = 0;
    decoder_.reset();
    emit pending_output_changed(0);
    emit disconnected();
}

qint64 FramedSocket::now() const
{
    return elapsed_.elapsed();
}

} // namespace tcp_chat::transport

#include "tcp_chat/frame.h"

#include <QJsonDocument>
#include <QtEndian>

namespace tcp_chat::protocol {
namespace {

    constexpr qsizetype header_size = 4;

    /// Clears any error reported by an earlier codec operation.
    void clear_error(ProtocolError* error)
    {
        if (error != nullptr) {
            error->code = ErrorCode::None;
            error->message.clear();
        }
    }

    /// Records a codec error when the caller supplied an error destination.
    void set_error(ProtocolError* error, ErrorCode code, const QString& message)
    {
        if (error != nullptr) {
            error->code    = code;
            error->message = message;
        }
    }

} // namespace

std::optional<QByteArray> encode_frame(const QByteArray& payload, ProtocolError* error)
{
    clear_error(error);

    if (payload.isEmpty()) {
        set_error(error, ErrorCode::InvalidFrame, QStringLiteral("Frame payload must not be empty"));
        return std::nullopt;
    }
    if (payload.size() > maximum_frame_size) {
        set_error(error, ErrorCode::InvalidFrame, QStringLiteral("Frame payload exceeds the 64 KiB limit"));
        return std::nullopt;
    }

    QByteArray frame;
    frame.resize(header_size);
    qToBigEndian(static_cast<quint32>(payload.size()), frame.data());
    frame.append(payload);
    return frame;
}

std::optional<QByteArray> encode_envelope(const Envelope& envelope, ProtocolError* error)
{
    const auto object = envelope_to_json(envelope, error);
    if (!object.has_value()) {
        return std::nullopt;
    }

    return encode_frame(QJsonDocument(*object).toJson(QJsonDocument::Compact), error);
}

void FrameDecoder::append(QByteArrayView data)
{
    if (error_.has_value()) {
        return;
    }

    buffer_.append(data);
}

std::optional<QByteArray> FrameDecoder::next_frame()
{
    if (error_.has_value()) {
        return std::nullopt;
    }

    if (!expected_size_.has_value()) {
        if (buffer_.size() < header_size) {
            return std::nullopt;
        }

        const quint32 payload_size = qFromBigEndian<quint32>(buffer_.constData());
        buffer_.remove(0, header_size);
        if (payload_size == 0) {
            fail(ErrorCode::InvalidFrame, QStringLiteral("Frame payload must not be empty"));
            return std::nullopt;
        }
        if (payload_size > static_cast<quint32>(maximum_frame_size)) {
            fail(ErrorCode::InvalidFrame, QStringLiteral("Frame payload exceeds the 64 KiB limit"));
            return std::nullopt;
        }

        expected_size_ = static_cast<qsizetype>(payload_size);
    }

    if (buffer_.size() < *expected_size_) {
        return std::nullopt;
    }

    QByteArray payload = buffer_.left(*expected_size_);
    buffer_.remove(0, *expected_size_);
    expected_size_.reset();
    return payload;
}

const ProtocolError* FrameDecoder::error() const noexcept
{
    return error_.has_value() ? &*error_ : nullptr;
}

void FrameDecoder::reset()
{
    buffer_.clear();
    expected_size_.reset();
    error_.reset();
}

void FrameDecoder::fail(ErrorCode code, const QString& message)
{
    error_ = ProtocolError { code, message };
}

} // namespace tcp_chat::protocol

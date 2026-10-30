#pragma once

#include "tcp_chat/protocol.h"

namespace tcp_chat::protocol {

inline constexpr qsizetype maximum_frame_size    = 64 * 1024;
inline constexpr qsizetype maximum_buffered_size = maximum_frame_size + 4;

/// Encodes one nonempty payload with a four-byte big-endian length prefix.
std::optional<QByteArray> encode_frame(const QByteArray& payload, ProtocolError* error = nullptr);

/// Encodes an envelope as compact UTF-8 JSON inside a bounded frame.
std::optional<QByteArray> encode_envelope(const Envelope& envelope, ProtocolError* error = nullptr);

/// Incrementally separates a byte stream into bounded payload frames.
class FrameDecoder {
public:
    /// Consumes bytes that fit the input bound and returns the count; drain frames before retrying a zero append.
    qsizetype append(QByteArrayView data);

    /// Returns the next complete payload, or nullopt when more data is required or an error exists.
    std::optional<QByteArray> next_frame();

    /// Returns the sticky framing error, or nullptr when no error has occurred.
    const ProtocolError* error() const noexcept;

    /// Clears buffered bytes and errors so the decoder can process a new stream.
    void reset();

private:
    /// Records a framing error and stops further decoding until reset.
    void fail(ErrorCode code, const QString& message);

    /// Discards consumed bytes when space is needed or the buffer is fully consumed.
    void compact();

    QByteArray buffer_;
    qsizetype read_offset_ = 0;
    std::optional<qsizetype> expected_size_;
    std::optional<ProtocolError> error_;
};

} // namespace tcp_chat::protocol

#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QString>

#include <optional>

namespace tcp_chat::protocol {

inline constexpr quint32 current_version             = 1;
inline constexpr qsizetype maximum_request_id_length = 128;

/// Identifies a message type registered in protocol version 1.
enum class MessageType {
    Error,
    Ping,
    Pong,
};

/// Identifies stable error codes shared by protocol handlers and codecs.
enum class ErrorCode {
    None,
    InvalidFrame,
    InvalidMessage,
    UnsupportedVersion,
    UnknownMessageType,
    InvalidRequest,
    Unauthenticated,
    InvalidCredentials,
    UsernameTaken,
    RateLimited,
    Unavailable,
    InternalError,
};

/// Describes a codec failure without exposing sensitive payload data.
struct ProtocolError {
    ErrorCode code = ErrorCode::None;
    QString message;
};

/// Contains the common fields carried by every protocol message.
struct Envelope {
    quint32 version  = current_version;
    MessageType type = MessageType::Ping;
    std::optional<QString> request_id;
    QJsonObject payload;

    bool operator==(const Envelope&) const = default;
};

/// Returns the wire name of a valid message type, or nullopt for an invalid enum.
std::optional<QLatin1StringView> message_type_name(MessageType type) noexcept;

/// Resolves a wire message name, or returns nullopt when it is not registered.
std::optional<MessageType> message_type_from_name(QStringView name) noexcept;

/// Returns the wire name of a public error code, excluding ErrorCode::None.
std::optional<QLatin1StringView> error_code_name(ErrorCode code) noexcept;

/// Validates an envelope and converts it to its JSON representation.
std::optional<QJsonObject> envelope_to_json(const Envelope& envelope, ProtocolError* error = nullptr);

/// Validates a JSON object and converts it to an envelope.
std::optional<Envelope> envelope_from_json(const QJsonObject& object, ProtocolError* error = nullptr);

/// Decodes one UTF-8 JSON payload and validates its envelope.
std::optional<Envelope> decode_envelope(const QByteArray& json, ProtocolError* error = nullptr);

} // namespace tcp_chat::protocol

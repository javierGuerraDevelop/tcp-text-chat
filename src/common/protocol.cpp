#include "tcp_chat/protocol.h"

#include <QJsonDocument>
#include <QStringDecoder>

#include <cmath>
#include <limits>

namespace tcp_chat::protocol {
namespace {

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

std::optional<QLatin1StringView> message_type_name(MessageType type) noexcept
{
    switch (type) {
    case MessageType::Error:
        return QLatin1StringView { "error" };
    case MessageType::Ping:
        return QLatin1StringView { "ping" };
    case MessageType::Pong:
        return QLatin1StringView { "pong" };
    }

    return std::nullopt;
}

std::optional<MessageType> message_type_from_name(QStringView name) noexcept
{
    if (name == QLatin1StringView { "error" }) {
        return MessageType::Error;
    }
    if (name == QLatin1StringView { "ping" }) {
        return MessageType::Ping;
    }
    if (name == QLatin1StringView { "pong" }) {
        return MessageType::Pong;
    }

    return std::nullopt;
}

std::optional<QLatin1StringView> error_code_name(ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::None:
        return std::nullopt;
    case ErrorCode::InvalidFrame:
        return QLatin1StringView { "invalid_frame" };
    case ErrorCode::InvalidMessage:
        return QLatin1StringView { "invalid_message" };
    case ErrorCode::UnsupportedVersion:
        return QLatin1StringView { "unsupported_version" };
    case ErrorCode::UnknownMessageType:
        return QLatin1StringView { "unknown_message_type" };
    case ErrorCode::InvalidRequest:
        return QLatin1StringView { "invalid_request" };
    case ErrorCode::Unauthenticated:
        return QLatin1StringView { "unauthenticated" };
    case ErrorCode::InvalidCredentials:
        return QLatin1StringView { "invalid_credentials" };
    case ErrorCode::UsernameTaken:
        return QLatin1StringView { "username_taken" };
    case ErrorCode::RateLimited:
        return QLatin1StringView { "rate_limited" };
    case ErrorCode::Unavailable:
        return QLatin1StringView { "unavailable" };
    case ErrorCode::InternalError:
        return QLatin1StringView { "internal_error" };
    }

    return std::nullopt;
}

std::optional<QJsonObject> envelope_to_json(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);

    if (envelope.version != current_version) {
        set_error(error, ErrorCode::UnsupportedVersion, QStringLiteral("Envelope version is not supported"));
        return std::nullopt;
    }

    const auto type_name = message_type_name(envelope.type);
    if (!type_name.has_value()) {
        set_error(error, ErrorCode::InvalidMessage, QStringLiteral("Envelope message type is invalid"));
        return std::nullopt;
    }

    if (envelope.request_id.has_value()
        && (envelope.request_id->isEmpty() || envelope.request_id->size() > maximum_request_id_length)) {
        set_error(error, ErrorCode::InvalidMessage, QStringLiteral("Request ID must contain 1 to 128 characters"));
        return std::nullopt;
    }

    QJsonObject object;
    object.insert(QStringLiteral("version"), static_cast<double>(envelope.version));
    object.insert(QStringLiteral("type"), QString::fromLatin1(type_name->data(), type_name->size()));
    if (envelope.request_id.has_value()) {
        object.insert(QStringLiteral("requestId"), *envelope.request_id);
    }
    object.insert(QStringLiteral("payload"), envelope.payload);
    return object;
}

std::optional<Envelope> envelope_from_json(const QJsonObject& object, ProtocolError* error)
{
    clear_error(error);

    for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
        const QString key = it.key();
        if (key != QStringLiteral("version") && key != QStringLiteral("type")
            && key != QStringLiteral("requestId") && key != QStringLiteral("payload")) {
            set_error(error, ErrorCode::InvalidMessage, QStringLiteral("Envelope contains an unknown field"));
            return std::nullopt;
        }
    }

    const QJsonValue version_value = object.value(QStringLiteral("version"));
    if (!version_value.isDouble()) {
        set_error(error, ErrorCode::InvalidMessage, QStringLiteral("Envelope version must be an integer"));
        return std::nullopt;
    }

    const double version_number = version_value.toDouble();
    if (!std::isfinite(version_number) || std::trunc(version_number) != version_number
        || version_number < 0 || version_number > std::numeric_limits<quint32>::max()) {
        set_error(error, ErrorCode::InvalidMessage, QStringLiteral("Envelope version must be an unsigned 32-bit integer"));
        return std::nullopt;
    }
    if (version_number != current_version) {
        set_error(error, ErrorCode::UnsupportedVersion, QStringLiteral("Envelope version is not supported"));
        return std::nullopt;
    }

    const QJsonValue type_value = object.value(QStringLiteral("type"));
    if (!type_value.isString()) {
        set_error(error, ErrorCode::InvalidMessage, QStringLiteral("Envelope type must be a string"));
        return std::nullopt;
    }

    const auto type = message_type_from_name(QStringView { type_value.toString() });
    if (!type.has_value()) {
        set_error(error, ErrorCode::UnknownMessageType, QStringLiteral("Envelope message type is not registered"));
        return std::nullopt;
    }

    std::optional<QString> request_id;
    const QJsonValue request_id_value = object.value(QStringLiteral("requestId"));
    if (!request_id_value.isUndefined()) {
        if (!request_id_value.isString()) {
            set_error(error, ErrorCode::InvalidMessage, QStringLiteral("Request ID must be a string"));
            return std::nullopt;
        }

        request_id = request_id_value.toString();
        if (request_id->isEmpty() || request_id->size() > maximum_request_id_length) {
            set_error(error, ErrorCode::InvalidMessage, QStringLiteral("Request ID must contain 1 to 128 characters"));
            return std::nullopt;
        }
    }

    const QJsonValue payload = object.value(QStringLiteral("payload"));
    if (!payload.isObject()) {
        set_error(error, ErrorCode::InvalidMessage, QStringLiteral("Envelope payload must be an object"));
        return std::nullopt;
    }

    Envelope envelope;
    envelope.version    = static_cast<quint32>(version_number);
    envelope.type       = *type;
    envelope.request_id = std::move(request_id);
    envelope.payload    = payload.toObject();
    return envelope;
}

std::optional<Envelope> decode_envelope(const QByteArray& json, ProtocolError* error)
{
    clear_error(error);

    QStringDecoder utf8_decoder(QStringDecoder::Utf8);
    utf8_decoder.decode(json);
    if (utf8_decoder.hasError()) {
        set_error(error, ErrorCode::InvalidMessage, QStringLiteral("Payload is not valid UTF-8"));
        return std::nullopt;
    }

    QJsonParseError parse_error;
    const QJsonDocument document = QJsonDocument::fromJson(json, &parse_error);
    if (parse_error.error != QJsonParseError::NoError) {
        set_error(error, ErrorCode::InvalidMessage,
            QStringLiteral("Payload is not valid JSON: %1").arg(parse_error.errorString()));
        return std::nullopt;
    }
    if (!document.isObject()) {
        set_error(error, ErrorCode::InvalidMessage, QStringLiteral("Payload JSON root must be an object"));
        return std::nullopt;
    }

    return envelope_from_json(document.object(), error);
}

} // namespace tcp_chat::protocol

#include "tcp_chat/chat_protocol.h"

#include <QJsonArray>
#include <QJsonObject>

#include <algorithm>
#include <cmath>

namespace tcp_chat::protocol {
namespace {

    /// Clears any error reported by an earlier payload operation.
    void clear_error(ProtocolError* error)
    {
        if (error != nullptr) {
            error->code = ErrorCode::None;
            error->message.clear();
        }
    }

    /// Reports invalid operation data without including message contents.
    void set_error(ProtocolError* error, const QString& message)
    {
        if (error != nullptr) {
            error->code    = ErrorCode::InvalidRequest;
            error->message = message;
        }
    }

    /// Checks that an object contains no fields outside its operation contract.
    bool valid_fields(const QJsonObject& object, const QList<QString>& fields, ProtocolError* error)
    {
        for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
            if (!fields.contains(it.key())) {
                set_error(error, QStringLiteral("Payload contains an unknown field"));
                return false;
            }
        }
        return true;
    }

    /// Checks the envelope type and exact payload field set.
    bool valid_payload(const Envelope& envelope, MessageType type, const QList<QString>& fields, ProtocolError* error)
    {
        if (envelope.type != type) {
            set_error(error, QStringLiteral("Unexpected message type for this operation"));
            return false;
        }
        return valid_fields(envelope.payload, fields, error);
    }

    /// Reads a bounded nonempty string without reproducing its value in diagnostics.
    std::optional<QString> string_field(const QJsonObject& object, const QString& name, qsizetype maximum, ProtocolError* error)
    {
        const QJsonValue value = object.value(name);
        if (!value.isString()) {
            set_error(error, QStringLiteral("A required string field is missing or invalid"));
            return std::nullopt;
        }
        const QString text = value.toString();
        if (text.isEmpty() || text.size() > maximum) {
            set_error(error, QStringLiteral("A string field has an invalid length"));
            return std::nullopt;
        }
        return text;
    }

    /// Reads a canonical decimal message ID without losing integer precision.
    std::optional<qint64> id_from_value(const QJsonValue& value, bool allow_zero, ProtocolError* error)
    {
        if (!value.isString()) {
            set_error(error, QStringLiteral("Message ID must be a decimal string"));
            return std::nullopt;
        }
        const QString text = value.toString();
        bool valid         = false;
        const qint64 id    = text.toLongLong(&valid);
        if (!valid || id < 0 || (!allow_zero && id == 0) || QString::number(id) != text) {
            set_error(error, QStringLiteral("Message ID is invalid"));
            return std::nullopt;
        }
        return id;
    }

    /// Returns whether a timestamp has an exact JSON number representation.
    bool valid_timestamp(qint64 timestamp)
    {
        return timestamp >= 0 && timestamp <= 9007199254740991LL;
    }

    /// Reads a nonnegative, exactly represented millisecond timestamp.
    std::optional<qint64> timestamp_from_value(const QJsonValue& value, ProtocolError* error)
    {
        if (!value.isDouble()) {
            set_error(error, QStringLiteral("Message timestamp must be an integer"));
            return std::nullopt;
        }
        const double number = value.toDouble();
        if (!std::isfinite(number) || std::trunc(number) != number || number < 0 || number > 9007199254740991.0) {
            set_error(error, QStringLiteral("Message timestamp is outside the supported range"));
            return std::nullopt;
        }
        return static_cast<qint64>(number);
    }

    /// Returns whether all public identity fields are safe to serialize.
    bool valid_sender(const UserIdentity& sender)
    {
        return sender.id > 0 && normalize_username(sender.username).has_value() && valid_display_name(sender.display_name);
    }

    /// Encodes a public sender identity after validating its fields.
    std::optional<QJsonObject> sender_to_json(const UserIdentity& sender, ProtocolError* error)
    {
        if (!valid_sender(sender)) {
            set_error(error, QStringLiteral("Message sender fields are invalid"));
            return std::nullopt;
        }
        return QJsonObject {
            { QStringLiteral("id"), QString::number(sender.id) },
            { QStringLiteral("username"), sender.username },
            { QStringLiteral("displayName"), sender.display_name },
        };
    }

    /// Decodes a public sender identity with an exact field set.
    std::optional<UserIdentity> sender_from_value(const QJsonValue& value, ProtocolError* error)
    {
        if (!value.isObject() || !valid_fields(value.toObject(), { QStringLiteral("id"), QStringLiteral("username"), QStringLiteral("displayName") }, error)) {
            if (error != nullptr && error->code == ErrorCode::None) {
                set_error(error, QStringLiteral("Message sender must be an object"));
            }
            return std::nullopt;
        }
        const QJsonObject object = value.toObject();
        const auto id            = id_from_value(object.value(QStringLiteral("id")), false, error);
        const auto username      = string_field(object, QStringLiteral("username"), maximum_username_length, error);
        const auto display_name  = string_field(object, QStringLiteral("displayName"), maximum_display_name_length, error);
        if (!id.has_value() || !username.has_value() || !display_name.has_value()) {
            return std::nullopt;
        }
        const UserIdentity sender { *id, *username, *display_name };
        if (!valid_sender(sender)) {
            set_error(error, QStringLiteral("Message sender fields are invalid"));
            return std::nullopt;
        }
        return sender;
    }

    /// Decodes a complete public message object.
    std::optional<ChatMessage> message_from_object(const QJsonObject& object, ProtocolError* error)
    {
        if (!valid_fields(object,
                { QStringLiteral("id"), QStringLiteral("sender"), QStringLiteral("clientMessageId"),
                    QStringLiteral("body"), QStringLiteral("createdAt") },
                error)) {
            return std::nullopt;
        }
        const auto id                = id_from_value(object.value(QStringLiteral("id")), false, error);
        const auto sender            = sender_from_value(object.value(QStringLiteral("sender")), error);
        const auto client_message_id = string_field(object, QStringLiteral("clientMessageId"), maximum_client_message_id_length, error);
        const auto body              = string_field(object, QStringLiteral("body"), maximum_chat_body_length, error);
        const auto created_at        = timestamp_from_value(object.value(QStringLiteral("createdAt")), error);
        if (!id.has_value() || !sender.has_value() || !client_message_id.has_value() || !body.has_value() || !created_at.has_value()) {
            return std::nullopt;
        }
        ChatMessage message { *id, *sender, *client_message_id, *body, *created_at };
        if (!valid_client_message_id(message.client_message_id) || !valid_chat_body(message.body)) {
            set_error(error, QStringLiteral("Message fields are invalid"));
            return std::nullopt;
        }
        return message;
    }

} // namespace

bool valid_chat_body(const QString& body)
{
    return !body.trimmed().isEmpty() && body.size() <= maximum_chat_body_length;
}

bool valid_client_message_id(const QString& client_message_id)
{
    return !client_message_id.isEmpty() && client_message_id.size() <= maximum_client_message_id_length
        && std::all_of(client_message_id.cbegin(), client_message_id.cend(), [](QChar character) {
               return character.unicode() >= 33 && character.unicode() <= 126;
           });
}

std::optional<ChatSendData> chat_send_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if (!valid_payload(envelope, MessageType::ChatSend,
            { QStringLiteral("clientMessageId"), QStringLiteral("body") }, error)) {
        return std::nullopt;
    }
    const auto client_message_id = string_field(envelope.payload, QStringLiteral("clientMessageId"), maximum_client_message_id_length, error);
    const auto body              = string_field(envelope.payload, QStringLiteral("body"), maximum_chat_body_length, error);
    if (!client_message_id.has_value() || !body.has_value()) {
        return std::nullopt;
    }
    if (!valid_client_message_id(*client_message_id) || !valid_chat_body(*body)) {
        set_error(error, QStringLiteral("Message fields are invalid"));
        return std::nullopt;
    }
    return ChatSendData { *client_message_id, *body };
}

std::optional<ChatHistoryRequest> chat_history_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if (!valid_payload(envelope, MessageType::ChatHistory,
            { QStringLiteral("beforeId"), QStringLiteral("afterId"), QStringLiteral("limit") }, error)) {
        return std::nullopt;
    }
    if (envelope.payload.contains(QStringLiteral("beforeId")) && envelope.payload.contains(QStringLiteral("afterId"))) {
        set_error(error, QStringLiteral("History request cannot contain both cursors"));
        return std::nullopt;
    }

    ChatHistoryRequest result;
    if (envelope.payload.contains(QStringLiteral("beforeId"))) {
        result.before_id = id_from_value(envelope.payload.value(QStringLiteral("beforeId")), false, error);
        if (!result.before_id.has_value()) {
            return std::nullopt;
        }
    }
    if (envelope.payload.contains(QStringLiteral("afterId"))) {
        result.after_id = id_from_value(envelope.payload.value(QStringLiteral("afterId")), true, error);
        if (!result.after_id.has_value()) {
            return std::nullopt;
        }
    }
    if (envelope.payload.contains(QStringLiteral("limit"))) {
        const QJsonValue value = envelope.payload.value(QStringLiteral("limit"));
        const double number    = value.toDouble();
        if (!value.isDouble() || !std::isfinite(number) || std::trunc(number) != number || number < 1
            || number > maximum_history_limit) {
            set_error(error, QStringLiteral("History limit must be between 1 and 100"));
            return std::nullopt;
        }
        result.limit = static_cast<int>(number);
    }
    return result;
}

std::optional<QJsonObject> chat_message_to_json(const ChatMessage& message, ProtocolError* error)
{
    clear_error(error);
    const auto sender = sender_to_json(message.sender, error);
    if (message.id <= 0 || !sender.has_value() || !valid_client_message_id(message.client_message_id)
        || !valid_chat_body(message.body) || !valid_timestamp(message.created_at)) {
        set_error(error, QStringLiteral("Message fields are invalid"));
        return std::nullopt;
    }
    return QJsonObject {
        { QStringLiteral("id"), QString::number(message.id) },
        { QStringLiteral("sender"), *sender },
        { QStringLiteral("clientMessageId"), message.client_message_id },
        { QStringLiteral("body"), message.body },
        { QStringLiteral("createdAt"), static_cast<double>(message.created_at) },
    };
}

std::optional<ChatMessage> chat_message_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if (!valid_payload(envelope, MessageType::ChatMessage,
            { QStringLiteral("id"), QStringLiteral("sender"), QStringLiteral("clientMessageId"),
                QStringLiteral("body"), QStringLiteral("createdAt") },
            error)) {
        return std::nullopt;
    }
    return message_from_object(envelope.payload, error);
}

std::optional<QJsonObject> chat_history_result_to_json(const ChatHistoryResult& result, ProtocolError* error)
{
    clear_error(error);
    if (result.messages.size() > maximum_history_limit) {
        set_error(error, QStringLiteral("History result exceeds the page limit"));
        return std::nullopt;
    }
    QJsonArray messages;
    qint64 previous_id = 0;
    for (const ChatMessage& message : result.messages) {
        if (message.id <= previous_id) {
            set_error(error, QStringLiteral("History messages must have strictly increasing IDs"));
            return std::nullopt;
        }
        const auto encoded = chat_message_to_json(message, error);
        if (!encoded.has_value()) {
            return std::nullopt;
        }
        messages.append(*encoded);
        previous_id = message.id;
    }
    return QJsonObject {
        { QStringLiteral("messages"), messages },
        { QStringLiteral("hasMore"), result.has_more },
    };
}

std::optional<ChatHistoryResult> chat_history_result_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if (!valid_payload(envelope, MessageType::ChatHistoryResult,
            { QStringLiteral("messages"), QStringLiteral("hasMore") }, error)) {
        return std::nullopt;
    }
    const QJsonValue messages_value = envelope.payload.value(QStringLiteral("messages"));
    const QJsonValue has_more_value = envelope.payload.value(QStringLiteral("hasMore"));
    if (!messages_value.isArray() || !has_more_value.isBool() || messages_value.toArray().size() > maximum_history_limit) {
        set_error(error, QStringLiteral("History result fields are invalid"));
        return std::nullopt;
    }

    ChatHistoryResult result;
    result.has_more           = has_more_value.toBool();
    qint64 previous_id        = 0;
    const QJsonArray messages = messages_value.toArray();
    for (const QJsonValue& value : messages) {
        if (!value.isObject()) {
            set_error(error, QStringLiteral("History message must be an object"));
            return std::nullopt;
        }
        const auto message = message_from_object(value.toObject(), error);
        if (!message.has_value() || message->id <= previous_id) {
            if (message.has_value()) {
                set_error(error, QStringLiteral("History messages must have strictly increasing IDs"));
            }
            return std::nullopt;
        }
        result.messages.append(*message);
        previous_id = message->id;
    }
    return result;
}

} // namespace tcp_chat::protocol

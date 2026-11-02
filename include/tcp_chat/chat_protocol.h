#pragma once

#include "tcp_chat/auth_protocol.h"

#include <QList>

namespace tcp_chat::protocol {

inline constexpr qsizetype maximum_chat_body_length         = 4000;
inline constexpr qsizetype maximum_client_message_id_length = 128;
inline constexpr int default_history_limit                  = 50;
inline constexpr int maximum_history_limit                  = 100;

/// Contains one client-generated idempotency key and its unmodified message body.
struct ChatSendData {
    QString client_message_id;
    QString body;

    bool operator==(const ChatSendData&) const = default;
};

/// Contains one public shared-room message with its server-assigned identity.
struct ChatMessage {
    qint64 id = 0;
    UserIdentity sender;
    QString client_message_id;
    QString body;
    qint64 created_at = 0;

    bool operator==(const ChatMessage&) const = default;
};

/// Selects either the latest history, an older page, or reconnect catch-up.
struct ChatHistoryRequest {
    std::optional<qint64> before_id;
    std::optional<qint64> after_id;
    int limit = default_history_limit;

    bool operator==(const ChatHistoryRequest&) const = default;
};

/// Contains an ascending message page and whether more rows exist in its direction.
struct ChatHistoryResult {
    QList<ChatMessage> messages;
    bool has_more = false;

    bool operator==(const ChatHistoryResult&) const = default;
};

/// Returns whether a body is nonblank and within the shared UTF-16 length limit.
bool valid_chat_body(const QString& body);
/// Returns whether an idempotency key is bounded printable non-whitespace ASCII.
bool valid_client_message_id(const QString& client_message_id);

/// Decodes and validates a shared-room send request without changing its body.
std::optional<ChatSendData> chat_send_from_envelope(const Envelope& envelope, ProtocolError* error = nullptr);
/// Decodes a latest, older-page, or reconnect history request.
std::optional<ChatHistoryRequest> chat_history_from_envelope(const Envelope& envelope, ProtocolError* error = nullptr);
/// Encodes a persisted message for a send acknowledgement or live broadcast.
std::optional<QJsonObject> chat_message_to_json(const ChatMessage& message, ProtocolError* error = nullptr);
/// Decodes a public message event or send acknowledgement.
std::optional<ChatMessage> chat_message_from_envelope(const Envelope& envelope, ProtocolError* error = nullptr);
/// Encodes an ascending history page bounded by the maximum history limit.
std::optional<QJsonObject> chat_history_result_to_json(const ChatHistoryResult& result, ProtocolError* error = nullptr);
/// Decodes and validates an ascending history response.
std::optional<ChatHistoryResult> chat_history_result_from_envelope(const Envelope& envelope, ProtocolError* error = nullptr);

} // namespace tcp_chat::protocol

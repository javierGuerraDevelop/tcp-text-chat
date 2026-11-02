#include "tcp_chat/chat_protocol.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QTest>

namespace {

using tcp_chat::protocol::ChatHistoryRequest;
using tcp_chat::protocol::ChatHistoryResult;
using tcp_chat::protocol::ChatMessage;
using tcp_chat::protocol::Envelope;
using tcp_chat::protocol::ErrorCode;
using tcp_chat::protocol::MessageType;
using tcp_chat::protocol::UserIdentity;

/// Creates an envelope with the requested operation and payload.
Envelope envelope(MessageType type, const QJsonObject& payload = QJsonObject { })
{
    Envelope result;
    result.type    = type;
    result.payload = payload;
    return result;
}

/// Creates a valid public message for conversion tests.
ChatMessage message(qint64 id = 42)
{
    return ChatMessage {
        id,
        UserIdentity { 7, QStringLiteral("Alice"), QStringLiteral("Alice Example") },
        QStringLiteral("client-42"),
        QStringLiteral("Hello, room"),
        123456789,
    };
}

/// Verifies strict shared-room payload conversion and boundaries.
class ChatProtocolTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks latest, older-page, and reconnect history requests.
    void decodesHistoryRequests();
    /// Checks cursor, limit, and field validation.
    void rejectsInvalidHistoryRequests_data();
    /// Checks that malformed history requests produce public errors.
    void rejectsInvalidHistoryRequests();
    /// Checks idempotency-key and body decoding without trimming content.
    void decodesSendRequest();
    /// Checks empty, oversized, and structurally invalid sends.
    void rejectsInvalidSendRequests_data();
    /// Checks send validation errors.
    void rejectsInvalidSendRequests();
    /// Checks message JSON and envelope round trips.
    void roundTripsMessage();
    /// Checks ordered history pages and continuation state.
    void roundTripsHistoryResult();
    /// Checks outbound message invariants.
    void rejectsInvalidOutgoingMessages();
    /// Checks duplicate and decreasing IDs in history results.
    void rejectsUnorderedHistoryResults();
};

void ChatProtocolTest::decodesHistoryRequests()
{
    const auto latest = tcp_chat::protocol::chat_history_from_envelope(envelope(MessageType::ChatHistory));
    QVERIFY(latest.has_value());
    QCOMPARE(*latest, ChatHistoryRequest { });

    const auto older = tcp_chat::protocol::chat_history_from_envelope(envelope(MessageType::ChatHistory,
        QJsonObject { { QStringLiteral("beforeId"), QStringLiteral("42") }, { QStringLiteral("limit"), 1 } }));
    QVERIFY(older.has_value());
    QCOMPARE(older->before_id, std::optional<qint64> { 42 });
    QVERIFY(!older->after_id.has_value());
    QCOMPARE(older->limit, 1);

    const auto reconnect = tcp_chat::protocol::chat_history_from_envelope(envelope(MessageType::ChatHistory,
        QJsonObject { { QStringLiteral("afterId"), QStringLiteral("0") }, { QStringLiteral("limit"), 100 } }));
    QVERIFY(reconnect.has_value());
    QVERIFY(!reconnect->before_id.has_value());
    QCOMPARE(reconnect->after_id, std::optional<qint64> { 0 });
    QCOMPARE(reconnect->limit, 100);
}

void ChatProtocolTest::rejectsInvalidHistoryRequests_data()
{
    QTest::addColumn<QJsonObject>("payload");
    QTest::newRow("both cursors") << QJsonObject {
        { QStringLiteral("beforeId"), QStringLiteral("2") }, { QStringLiteral("afterId"), QStringLiteral("1") }
    };
    QTest::newRow("zero before cursor") << QJsonObject { { QStringLiteral("beforeId"), QStringLiteral("0") } };
    QTest::newRow("negative after cursor") << QJsonObject { { QStringLiteral("afterId"), QStringLiteral("-1") } };
    QTest::newRow("noncanonical cursor") << QJsonObject { { QStringLiteral("afterId"), QStringLiteral("01") } };
    QTest::newRow("numeric cursor") << QJsonObject { { QStringLiteral("afterId"), 1 } };
    QTest::newRow("zero limit") << QJsonObject { { QStringLiteral("limit"), 0 } };
    QTest::newRow("large limit") << QJsonObject { { QStringLiteral("limit"), 101 } };
    QTest::newRow("fractional limit") << QJsonObject { { QStringLiteral("limit"), 1.5 } };
    QTest::newRow("string limit") << QJsonObject { { QStringLiteral("limit"), QStringLiteral("10") } };
    QTest::newRow("unknown field") << QJsonObject { { QStringLiteral("room"), QStringLiteral("general") } };
}

void ChatProtocolTest::rejectsInvalidHistoryRequests()
{
    QFETCH(QJsonObject, payload);
    tcp_chat::protocol::ProtocolError error;
    const auto result = tcp_chat::protocol::chat_history_from_envelope(envelope(MessageType::ChatHistory, payload), &error);
    QVERIFY(!result.has_value());
    QCOMPARE(error.code, ErrorCode::InvalidRequest);
}

void ChatProtocolTest::decodesSendRequest()
{
    const auto result = tcp_chat::protocol::chat_send_from_envelope(envelope(MessageType::ChatSend,
        QJsonObject { { QStringLiteral("clientMessageId"), QStringLiteral("request-1") },
            { QStringLiteral("body"), QStringLiteral("  Hello\nroom  ") } }));
    QVERIFY(result.has_value());
    QCOMPARE(result->client_message_id, QStringLiteral("request-1"));
    QCOMPARE(result->body, QStringLiteral("  Hello\nroom  "));

    const auto maximum = tcp_chat::protocol::chat_send_from_envelope(envelope(MessageType::ChatSend,
        QJsonObject { { QStringLiteral("clientMessageId"),
                          QString(tcp_chat::protocol::maximum_client_message_id_length, QLatin1Char('i')) },
            { QStringLiteral("body"), QString(tcp_chat::protocol::maximum_chat_body_length, QLatin1Char('x')) } }));
    QVERIFY(maximum.has_value());
    QCOMPARE(maximum->client_message_id.size(), tcp_chat::protocol::maximum_client_message_id_length);
    QCOMPARE(maximum->body.size(), tcp_chat::protocol::maximum_chat_body_length);
}

void ChatProtocolTest::rejectsInvalidSendRequests_data()
{
    QTest::addColumn<QJsonObject>("payload");
    QTest::newRow("missing fields") << QJsonObject { };
    QTest::newRow("empty body") << QJsonObject {
        { QStringLiteral("clientMessageId"), QStringLiteral("request-1") }, { QStringLiteral("body"), QString() }
    };
    QTest::newRow("blank body") << QJsonObject {
        { QStringLiteral("clientMessageId"), QStringLiteral("request-1") }, { QStringLiteral("body"), QStringLiteral(" \n") }
    };
    QTest::newRow("long body") << QJsonObject {
        { QStringLiteral("clientMessageId"), QStringLiteral("request-1") },
        { QStringLiteral("body"), QString(tcp_chat::protocol::maximum_chat_body_length + 1, QLatin1Char('x')) }
    };
    QTest::newRow("empty client ID") << QJsonObject {
        { QStringLiteral("clientMessageId"), QString() }, { QStringLiteral("body"), QStringLiteral("body") }
    };
    QTest::newRow("whitespace client ID") << QJsonObject {
        { QStringLiteral("clientMessageId"), QStringLiteral("not valid") }, { QStringLiteral("body"), QStringLiteral("body") }
    };
    QTest::newRow("long client ID") << QJsonObject {
        { QStringLiteral("clientMessageId"), QString(tcp_chat::protocol::maximum_client_message_id_length + 1, QLatin1Char('x')) },
        { QStringLiteral("body"), QStringLiteral("body") }
    };
    QTest::newRow("unknown field") << QJsonObject {
        { QStringLiteral("clientMessageId"), QStringLiteral("request-1") }, { QStringLiteral("body"), QStringLiteral("body") },
        { QStringLiteral("senderId"), QStringLiteral("7") }
    };
}

void ChatProtocolTest::rejectsInvalidSendRequests()
{
    QFETCH(QJsonObject, payload);
    tcp_chat::protocol::ProtocolError error;
    const auto result = tcp_chat::protocol::chat_send_from_envelope(envelope(MessageType::ChatSend, payload), &error);
    QVERIFY(!result.has_value());
    QCOMPARE(error.code, ErrorCode::InvalidRequest);
    QVERIFY(!error.message.contains(QStringLiteral("request-1")));
}

void ChatProtocolTest::roundTripsMessage()
{
    const ChatMessage original = message();
    const auto json            = tcp_chat::protocol::chat_message_to_json(original);
    QVERIFY(json.has_value());
    QCOMPARE(json->value(QStringLiteral("id")).toString(), QStringLiteral("42"));
    QCOMPARE(json->value(QStringLiteral("sender")).toObject().value(QStringLiteral("id")).toString(), QStringLiteral("7"));

    Envelope encoded   = envelope(MessageType::ChatMessage, *json);
    encoded.request_id = QStringLiteral("send-request");
    const auto wire    = tcp_chat::protocol::envelope_to_json(encoded);
    QVERIFY(wire.has_value());
    const auto decoded_envelope = tcp_chat::protocol::decode_envelope(QJsonDocument(*wire).toJson(QJsonDocument::Compact));
    QVERIFY(decoded_envelope.has_value());
    QCOMPARE(decoded_envelope->request_id, encoded.request_id);
    const auto decoded = tcp_chat::protocol::chat_message_from_envelope(*decoded_envelope);
    QVERIFY(decoded.has_value());
    QCOMPARE(*decoded, original);
}

void ChatProtocolTest::roundTripsHistoryResult()
{
    ChatHistoryResult original;
    original.messages = { message(9), message(10) };
    original.has_more = true;
    const auto json   = tcp_chat::protocol::chat_history_result_to_json(original);
    QVERIFY(json.has_value());
    QCOMPARE(json->value(QStringLiteral("messages")).toArray().size(), 2);
    QVERIFY(json->value(QStringLiteral("hasMore")).toBool());

    const auto decoded = tcp_chat::protocol::chat_history_result_from_envelope(envelope(MessageType::ChatHistoryResult, *json));
    QVERIFY(decoded.has_value());
    QCOMPARE(*decoded, original);
}

void ChatProtocolTest::rejectsInvalidOutgoingMessages()
{
    ChatMessage invalid = message(0);
    QVERIFY(!tcp_chat::protocol::chat_message_to_json(invalid).has_value());
    invalid           = message();
    invalid.sender.id = 0;
    QVERIFY(!tcp_chat::protocol::chat_message_to_json(invalid).has_value());
    invalid      = message();
    invalid.body = QStringLiteral(" \t");
    QVERIFY(!tcp_chat::protocol::chat_message_to_json(invalid).has_value());
    invalid            = message();
    invalid.created_at = 9007199254740992LL;
    QVERIFY(!tcp_chat::protocol::chat_message_to_json(invalid).has_value());
    invalid                   = message();
    invalid.client_message_id = QStringLiteral("not valid");
    QVERIFY(!tcp_chat::protocol::chat_message_to_json(invalid).has_value());
}

void ChatProtocolTest::rejectsUnorderedHistoryResults()
{
    ChatHistoryResult result;
    result.messages = { message(10), message(9) };
    QVERIFY(!tcp_chat::protocol::chat_history_result_to_json(result).has_value());
    result.messages = { message(10), message(10) };
    QVERIFY(!tcp_chat::protocol::chat_history_result_to_json(result).has_value());

    const auto first = tcp_chat::protocol::chat_message_to_json(message(10));
    QVERIFY(first.has_value());
    const QJsonObject payload {
        { QStringLiteral("messages"), QJsonArray { *first, *first } },
        { QStringLiteral("hasMore"), false },
    };
    QVERIFY(!tcp_chat::protocol::chat_history_result_from_envelope(envelope(MessageType::ChatHistoryResult, payload)).has_value());
}

} // namespace

QTEST_GUILESS_MAIN(ChatProtocolTest)

#include "test_chat_protocol.moc"

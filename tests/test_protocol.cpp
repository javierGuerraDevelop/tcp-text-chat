#include "tcp_chat/protocol.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QTest>

Q_DECLARE_METATYPE(tcp_chat::protocol::ErrorCode)
Q_DECLARE_METATYPE(tcp_chat::protocol::MessageType)

namespace {

using tcp_chat::protocol::Envelope;
using tcp_chat::protocol::ErrorCode;
using tcp_chat::protocol::MessageType;

/// Returns a minimal valid version-1 envelope object.
QJsonObject valid_object()
{
    return QJsonObject {
        { QStringLiteral("version"), 1 },
        { QStringLiteral("type"), QStringLiteral("ping") },
        { QStringLiteral("payload"), QJsonObject { } },
    };
}

} // namespace

/// Verifies protocol envelope and identifier conversion.
class ProtocolTest : public QObject {
    Q_OBJECT

private slots:
    /// Provides every registered message type name.
    void messageTypeNames_data();
    /// Checks message type name conversion in both directions.
    void messageTypeNames();
    /// Provides every public error code name.
    void errorCodeNames_data();
    /// Checks error code wire names and invalid enum handling.
    void errorCodeNames();
    /// Checks a complete envelope round trip.
    void roundTripsEnvelope();
    /// Checks the optional request ID representation.
    void omitsMissingRequestId();
    /// Checks the maximum accepted request ID length.
    void acceptsMaximumRequestIdLength();
    /// Provides malformed envelope objects.
    void rejectsInvalidEnvelopes_data();
    /// Checks rejection and reporting for malformed envelopes.
    void rejectsInvalidEnvelopes();
    /// Checks explicit version mismatch reporting.
    void rejectsUnsupportedVersion();
    /// Checks outgoing version validation.
    void rejectsUnsupportedOutgoingVersion();
    /// Checks unknown message type reporting.
    void rejectsUnknownMessageType();
    /// Checks malformed JSON reporting.
    void rejectsInvalidJson();
    /// Checks JSON root type validation.
    void rejectsNonObjectJson();
    /// Checks UTF-8 validation before JSON parsing.
    void rejectsInvalidUtf8();
    /// Checks that successful calls clear prior errors.
    void clearsErrorOnSuccess();
};

void ProtocolTest::messageTypeNames_data()
{
    QTest::addColumn<MessageType>("type");
    QTest::addColumn<QString>("name");

    QTest::newRow("error") << MessageType::Error << QStringLiteral("error");
    QTest::newRow("ping") << MessageType::Ping << QStringLiteral("ping");
    QTest::newRow("pong") << MessageType::Pong << QStringLiteral("pong");
}

void ProtocolTest::messageTypeNames()
{
    QFETCH(MessageType, type);
    QFETCH(QString, name);

    const auto encoded = tcp_chat::protocol::message_type_name(type);
    QVERIFY(encoded.has_value());
    QCOMPARE(QString::fromLatin1(encoded->data(), encoded->size()), name);

    const auto decoded = tcp_chat::protocol::message_type_from_name(QStringView { name });
    QVERIFY(decoded.has_value());
    QCOMPARE(*decoded, type);
    QVERIFY(!tcp_chat::protocol::message_type_name(static_cast<MessageType>(999)).has_value());
}

void ProtocolTest::errorCodeNames_data()
{
    QTest::addColumn<ErrorCode>("code");
    QTest::addColumn<QString>("name");

    QTest::newRow("invalid frame") << ErrorCode::InvalidFrame << QStringLiteral("invalid_frame");
    QTest::newRow("invalid message") << ErrorCode::InvalidMessage << QStringLiteral("invalid_message");
    QTest::newRow("unsupported version") << ErrorCode::UnsupportedVersion << QStringLiteral("unsupported_version");
    QTest::newRow("unknown message type") << ErrorCode::UnknownMessageType << QStringLiteral("unknown_message_type");
    QTest::newRow("invalid request") << ErrorCode::InvalidRequest << QStringLiteral("invalid_request");
    QTest::newRow("unauthenticated") << ErrorCode::Unauthenticated << QStringLiteral("unauthenticated");
    QTest::newRow("invalid credentials") << ErrorCode::InvalidCredentials << QStringLiteral("invalid_credentials");
    QTest::newRow("username taken") << ErrorCode::UsernameTaken << QStringLiteral("username_taken");
    QTest::newRow("rate limited") << ErrorCode::RateLimited << QStringLiteral("rate_limited");
    QTest::newRow("unavailable") << ErrorCode::Unavailable << QStringLiteral("unavailable");
    QTest::newRow("internal error") << ErrorCode::InternalError << QStringLiteral("internal_error");
}

void ProtocolTest::errorCodeNames()
{
    QFETCH(ErrorCode, code);
    QFETCH(QString, name);

    const auto encoded = tcp_chat::protocol::error_code_name(code);
    QVERIFY(encoded.has_value());
    QCOMPARE(QString::fromLatin1(encoded->data(), encoded->size()), name);
    QVERIFY(!tcp_chat::protocol::error_code_name(ErrorCode::None).has_value());
    QVERIFY(!tcp_chat::protocol::error_code_name(static_cast<ErrorCode>(999)).has_value());
}

void ProtocolTest::roundTripsEnvelope()
{
    Envelope original;
    original.type       = MessageType::Error;
    original.request_id = QStringLiteral("request-42");
    original.payload    = QJsonObject {
        { QStringLiteral("code"), QStringLiteral("invalid_request") },
        { QStringLiteral("message"), QStringLiteral("Request is invalid") },
    };

    tcp_chat::protocol::ProtocolError error;
    const auto json = tcp_chat::protocol::envelope_to_json(original, &error);
    QVERIFY(json.has_value());
    QCOMPARE(error.code, ErrorCode::None);

    const auto decoded_object = tcp_chat::protocol::envelope_from_json(*json, &error);
    QVERIFY(decoded_object.has_value());
    QCOMPARE(*decoded_object, original);

    const QByteArray bytes   = QJsonDocument(*json).toJson(QJsonDocument::Compact);
    const auto decoded_bytes = tcp_chat::protocol::decode_envelope(bytes, &error);
    QVERIFY(decoded_bytes.has_value());
    QCOMPARE(*decoded_bytes, original);
}

void ProtocolTest::omitsMissingRequestId()
{
    const Envelope original;
    const auto json = tcp_chat::protocol::envelope_to_json(original);
    QVERIFY(json.has_value());
    QVERIFY(!json->contains(QStringLiteral("requestId")));

    const auto decoded = tcp_chat::protocol::envelope_from_json(*json);
    QVERIFY(decoded.has_value());
    QVERIFY(!decoded->request_id.has_value());
}

void ProtocolTest::acceptsMaximumRequestIdLength()
{
    Envelope original;
    original.request_id = QString(tcp_chat::protocol::maximum_request_id_length, QLatin1Char('x'));

    const auto json = tcp_chat::protocol::envelope_to_json(original);
    QVERIFY(json.has_value());
    const auto decoded = tcp_chat::protocol::envelope_from_json(*json);
    QVERIFY(decoded.has_value());
    QCOMPARE(decoded->request_id, original.request_id);
}

void ProtocolTest::rejectsInvalidEnvelopes_data()
{
    QTest::addColumn<QJsonObject>("object");

    QJsonObject object;
    QTest::newRow("empty object") << object;

    object = valid_object();
    object.remove(QStringLiteral("version"));
    QTest::newRow("missing version") << object;

    object = valid_object();
    object.insert(QStringLiteral("version"), QStringLiteral("1"));
    QTest::newRow("string version") << object;

    object = valid_object();
    object.insert(QStringLiteral("version"), 1.5);
    QTest::newRow("fractional version") << object;

    object = valid_object();
    object.insert(QStringLiteral("version"), -1);
    QTest::newRow("negative version") << object;

    object = valid_object();
    object.remove(QStringLiteral("type"));
    QTest::newRow("missing type") << object;

    object = valid_object();
    object.insert(QStringLiteral("type"), 1);
    QTest::newRow("numeric type") << object;

    object = valid_object();
    object.insert(QStringLiteral("requestId"), 42);
    QTest::newRow("numeric request ID") << object;

    object = valid_object();
    object.insert(QStringLiteral("requestId"), QString());
    QTest::newRow("empty request ID") << object;

    object = valid_object();
    object.insert(QStringLiteral("requestId"), QString(tcp_chat::protocol::maximum_request_id_length + 1, QLatin1Char('x')));
    QTest::newRow("long request ID") << object;

    object = valid_object();
    object.remove(QStringLiteral("payload"));
    QTest::newRow("missing payload") << object;

    object = valid_object();
    object.insert(QStringLiteral("payload"), QJsonArray { });
    QTest::newRow("array payload") << object;

    object = valid_object();
    object.insert(QStringLiteral("unknown"), true);
    QTest::newRow("unknown field") << object;
}

void ProtocolTest::rejectsInvalidEnvelopes()
{
    QFETCH(QJsonObject, object);

    tcp_chat::protocol::ProtocolError error;
    const auto decoded = tcp_chat::protocol::envelope_from_json(object, &error);
    QVERIFY(!decoded.has_value());
    QCOMPARE(error.code, ErrorCode::InvalidMessage);
    QVERIFY(!error.message.isEmpty());
}

void ProtocolTest::rejectsUnsupportedVersion()
{
    QJsonObject object = valid_object();
    object.insert(QStringLiteral("version"), 2);

    tcp_chat::protocol::ProtocolError error;
    const auto decoded = tcp_chat::protocol::envelope_from_json(object, &error);
    QVERIFY(!decoded.has_value());
    QCOMPARE(error.code, ErrorCode::UnsupportedVersion);
}

void ProtocolTest::rejectsUnsupportedOutgoingVersion()
{
    Envelope envelope;
    envelope.version = 2;

    tcp_chat::protocol::ProtocolError error;
    const auto json = tcp_chat::protocol::envelope_to_json(envelope, &error);
    QVERIFY(!json.has_value());
    QCOMPARE(error.code, ErrorCode::UnsupportedVersion);
}

void ProtocolTest::rejectsUnknownMessageType()
{
    QJsonObject object = valid_object();
    object.insert(QStringLiteral("type"), QStringLiteral("chat.send"));

    tcp_chat::protocol::ProtocolError error;
    const auto decoded = tcp_chat::protocol::envelope_from_json(object, &error);
    QVERIFY(!decoded.has_value());
    QCOMPARE(error.code, ErrorCode::UnknownMessageType);
}

void ProtocolTest::rejectsInvalidJson()
{
    tcp_chat::protocol::ProtocolError error;
    const auto decoded = tcp_chat::protocol::decode_envelope(QByteArrayLiteral("{not-json"), &error);
    QVERIFY(!decoded.has_value());
    QCOMPARE(error.code, ErrorCode::InvalidMessage);
}

void ProtocolTest::rejectsNonObjectJson()
{
    tcp_chat::protocol::ProtocolError error;
    const auto decoded = tcp_chat::protocol::decode_envelope(QByteArrayLiteral("[1,2]"), &error);
    QVERIFY(!decoded.has_value());
    QCOMPARE(error.code, ErrorCode::InvalidMessage);
}

void ProtocolTest::rejectsInvalidUtf8()
{
    tcp_chat::protocol::ProtocolError error;
    const auto decoded = tcp_chat::protocol::decode_envelope(QByteArray::fromHex("c328"), &error);
    QVERIFY(!decoded.has_value());
    QCOMPARE(error.code, ErrorCode::InvalidMessage);
}

void ProtocolTest::clearsErrorOnSuccess()
{
    tcp_chat::protocol::ProtocolError error { ErrorCode::InvalidFrame, QStringLiteral("old error") };
    const auto json = tcp_chat::protocol::envelope_to_json(Envelope { }, &error);
    QVERIFY(json.has_value());
    QCOMPARE(error.code, ErrorCode::None);
    QVERIFY(error.message.isEmpty());
}

QTEST_GUILESS_MAIN(ProtocolTest)

#include "test_protocol.moc"

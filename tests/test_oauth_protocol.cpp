#include "tcp_chat/auth_protocol.h"

#include <QTest>

using namespace tcp_chat::protocol;

/// Verifies strict OAuth message types, field combinations, and token separation.
class OAuthProtocolTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks every OAuth wire name in both directions.
    void messageNames();
    /// Checks strict start/status/complete decoding.
    void decodesRequests();
    /// Checks all public flow states and invalid field combinations.
    void validatesResults();
};

void OAuthProtocolTest::messageNames()
{
    const QList<QPair<MessageType, QString>> messages = {
        { MessageType::AuthOAuthStart, QStringLiteral("auth.oauth.start") },
        { MessageType::AuthOAuthStatus, QStringLiteral("auth.oauth.status") },
        { MessageType::AuthOAuthComplete, QStringLiteral("auth.oauth.complete") },
        { MessageType::AuthOAuthResult, QStringLiteral("auth.oauth.result") },
    };
    for (const auto& message : messages) {
        const auto name = message_type_name(message.first);
        QVERIFY(name.has_value());
        QCOMPARE(QString::fromLatin1(name->data(), name->size()), message.second);
        QCOMPARE(message_type_from_name(message.second), std::optional<MessageType> { message.first });
    }
}

void OAuthProtocolTest::decodesRequests()
{
    Envelope envelope;
    envelope.type    = MessageType::AuthOAuthStart;
    envelope.payload = QJsonObject { { QStringLiteral("provider"), QStringLiteral("fake") } };
    QCOMPARE(oauth_provider_from_envelope(envelope), std::optional<QString> { QStringLiteral("fake") });
    envelope.payload.insert(QStringLiteral("unexpected"), true);
    QVERIFY(!oauth_provider_from_envelope(envelope).has_value());
    envelope.payload = QJsonObject { { QStringLiteral("provider"), QStringLiteral("Fake") } };
    QVERIFY(!oauth_provider_from_envelope(envelope).has_value());
    envelope.payload = QJsonObject { { QStringLiteral("provider"), QString::fromUtf8("\xc3\xa9") } };
    QVERIFY(!oauth_provider_from_envelope(envelope).has_value());

    const QString token = QStringLiteral("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    envelope.type       = MessageType::AuthOAuthStatus;
    envelope.payload    = QJsonObject { { QStringLiteral("flow"), token } };
    QCOMPARE(oauth_flow_from_envelope(envelope), std::optional<QString> { token });
    envelope.type         = MessageType::AuthOAuthComplete;
    envelope.payload      = QJsonObject { { QStringLiteral("flow"), token }, { QStringLiteral("handoff"), token } };
    const auto completion = oauth_completion_from_envelope(envelope);
    QVERIFY(completion.has_value());
    QCOMPARE(completion->flow_handle, token);
    QCOMPARE(completion->handoff, token);
    envelope.type = MessageType::AuthSession;
    QVERIFY(!oauth_completion_from_envelope(envelope).has_value());
}

void OAuthProtocolTest::validatesResults()
{
    const QString token              = QStringLiteral("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    const QList<OAuthResult> results = {
        { token, QStringLiteral("started"), QStringLiteral("https://provider.invalid/authorize?client=test"), std::nullopt, 1000 },
        { token, QStringLiteral("pending"), std::nullopt, std::nullopt, 1000 },
        { token, QStringLiteral("ready"), std::nullopt, token, 1000 },
        { token, QStringLiteral("failed"), std::nullopt, std::nullopt, 1000 },
    };
    for (const auto& result : results) {
        const auto payload = oauth_result_to_json(result);
        QVERIFY(payload.has_value());
        Envelope envelope;
        envelope.type      = MessageType::AuthOAuthResult;
        envelope.payload   = *payload;
        const auto decoded = oauth_result_from_envelope(envelope);
        QVERIFY(decoded.has_value());
        QCOMPARE(decoded->flow_handle, result.flow_handle);
        QCOMPARE(decoded->status, result.status);
        QCOMPARE(decoded->authorization_url, result.authorization_url);
        QCOMPARE(decoded->handoff, result.handoff);
        QCOMPARE(decoded->expires_at, result.expires_at);
    }
    QVERIFY(!oauth_result_to_json(OAuthResult { token, QStringLiteral("ready"), std::nullopt, std::nullopt, 1000 }).has_value());
    QVERIFY(!oauth_result_to_json(OAuthResult { token, QStringLiteral("started"), QStringLiteral("http://insecure.invalid"), std::nullopt, 1000 }).has_value());
    QVERIFY(!oauth_result_to_json(OAuthResult { QStringLiteral("short"), QStringLiteral("pending"), std::nullopt, std::nullopt, 1000 }).has_value());
    QVERIFY(!oauth_result_to_json(OAuthResult { token, QStringLiteral("unknown"), std::nullopt, std::nullopt, 1000 }).has_value());
}

QTEST_GUILESS_MAIN(OAuthProtocolTest)

#include "test_oauth_protocol.moc"

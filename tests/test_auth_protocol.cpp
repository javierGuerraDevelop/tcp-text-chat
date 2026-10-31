#include "tcp_chat/auth_protocol.h"

#include <QJsonObject>
#include <QTest>

namespace {

using tcp_chat::protocol::AuthenticationResult;
using tcp_chat::protocol::Envelope;
using tcp_chat::protocol::ErrorCode;
using tcp_chat::protocol::MessageType;
using tcp_chat::protocol::UserIdentity;

/// Creates a syntactically valid token-shaped value for protocol tests.
QString issued_token()
{
    return QString(43, QLatin1Char('a'));
}

/// Creates an envelope with the requested operation and payload.
Envelope envelope(MessageType type, const QJsonObject& payload)
{
    Envelope result;
    result.type    = type;
    result.payload = payload;
    return result;
}

/// Verifies strict local-authentication payload conversion.
class AuthenticationProtocolTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks case-folded and trimmed username normalization.
    void normalizesUsernames();
    /// Rejects invalid username lengths and characters.
    void rejectsInvalidUsernames();
    /// Decodes signup fields and the optional display name.
    void decodesSignUp();
    /// Decodes login fields without changing the password.
    void decodesLogIn();
    /// Rejects malformed credentials without exposing values.
    void rejectsInvalidCredentials();
    /// Decodes opaque session and logout tokens.
    void decodesSessionTokens();
    /// Rejects malformed session-token payloads.
    void rejectsInvalidSessionPayloads();
    /// Round-trips an authenticated identity and issued token.
    void roundTripsAuthenticationResult();
    /// Round-trips an idempotent logout result.
    void roundTripsLogoutResult();
    /// Rejects invalid result field combinations.
    void rejectsInvalidResults();
};

void AuthenticationProtocolTest::normalizesUsernames()
{
    QCOMPARE(tcp_chat::protocol::normalize_username(QStringLiteral("  Alice  ")), std::optional<QString> { QStringLiteral("alice") });
    QCOMPARE(tcp_chat::protocol::normalize_username(QStringLiteral("alice.example")), std::optional<QString> { QStringLiteral("alice.example") });
    QVERIFY(tcp_chat::protocol::valid_display_name(QStringLiteral("Alice Example")));
    QVERIFY(!tcp_chat::protocol::valid_display_name(QStringLiteral(" Alice")));
    QVERIFY(!tcp_chat::protocol::valid_display_name(QStringLiteral("Alice\nExample")));
}

void AuthenticationProtocolTest::rejectsInvalidUsernames()
{
    QVERIFY(!tcp_chat::protocol::normalize_username(QStringLiteral("ab")).has_value());
    QVERIFY(!tcp_chat::protocol::normalize_username(QStringLiteral("has space")).has_value());
    QVERIFY(!tcp_chat::protocol::normalize_username(QStringLiteral("a/b")).has_value());
    QVERIFY(!tcp_chat::protocol::normalize_username(QString(33, QLatin1Char('a'))).has_value());
}

void AuthenticationProtocolTest::decodesSignUp()
{
    const auto result = tcp_chat::protocol::sign_up_from_envelope(envelope(MessageType::AuthSignUp,
        QJsonObject { { QStringLiteral("username"), QStringLiteral(" Alice ") },
            { QStringLiteral("password"), QStringLiteral("correct horse battery staple") },
            { QStringLiteral("displayName"), QStringLiteral("Alice Example") } }));
    QVERIFY(result.has_value());
    QCOMPARE(result->username, QStringLiteral("Alice"));
    QCOMPARE(result->password, QStringLiteral("correct horse battery staple"));
    QCOMPARE(result->display_name, std::optional<QString> { QStringLiteral("Alice Example") });
}

void AuthenticationProtocolTest::decodesLogIn()
{
    const auto result = tcp_chat::protocol::log_in_from_envelope(envelope(MessageType::AuthLogIn,
        QJsonObject { { QStringLiteral("username"), QStringLiteral("alice") },
            { QStringLiteral("password"), QStringLiteral("  eight-or-more  ") } }));
    QVERIFY(result.has_value());
    QCOMPARE(result->username, QStringLiteral("alice"));
    QCOMPARE(result->password, QStringLiteral("  eight-or-more  "));
}

void AuthenticationProtocolTest::rejectsInvalidCredentials()
{
    tcp_chat::protocol::ProtocolError error;
    QVERIFY(!tcp_chat::protocol::sign_up_from_envelope(envelope(MessageType::AuthSignUp,
                                                           QJsonObject { { QStringLiteral("username"), QStringLiteral("ab") },
                                                               { QStringLiteral("password"), QStringLiteral("long-enough") } }),
        &error)
            .has_value());
    QCOMPARE(error.code, ErrorCode::InvalidRequest);
    QVERIFY(!tcp_chat::protocol::log_in_from_envelope(envelope(MessageType::AuthLogIn,
                                                          QJsonObject { { QStringLiteral("username"), QStringLiteral("alice") },
                                                              { QStringLiteral("password"), QStringLiteral("short") } }),
        &error)
            .has_value());
    QCOMPARE(error.code, ErrorCode::InvalidRequest);
    QVERIFY(!tcp_chat::protocol::log_in_from_envelope(envelope(MessageType::AuthLogIn,
                                                          QJsonObject { { QStringLiteral("username"), QStringLiteral("alice") },
                                                              { QStringLiteral("password"), QStringLiteral("long-enough") },
                                                              { QStringLiteral("unexpected"), true } }),
        &error)
            .has_value());
    QCOMPARE(error.code, ErrorCode::InvalidRequest);
}

void AuthenticationProtocolTest::decodesSessionTokens()
{
    const auto result = tcp_chat::protocol::session_token_from_envelope(envelope(MessageType::AuthSession,
        QJsonObject { { QStringLiteral("sessionToken"), issued_token() } }));
    QCOMPARE(result, std::optional<QString> { issued_token() });
    const auto logout = tcp_chat::protocol::session_token_from_envelope(envelope(MessageType::AuthLogOut,
        QJsonObject { { QStringLiteral("sessionToken"), issued_token() } }));
    QCOMPARE(logout, result);
}

void AuthenticationProtocolTest::rejectsInvalidSessionPayloads()
{
    QVERIFY(!tcp_chat::protocol::session_token_from_envelope(envelope(MessageType::AuthSession,
                                                                 QJsonObject { { QStringLiteral("sessionToken"), QString() } }))
            .has_value());
    QVERIFY(!tcp_chat::protocol::session_token_from_envelope(envelope(MessageType::AuthSession, QJsonObject { })).has_value());
    QVERIFY(!tcp_chat::protocol::session_token_from_envelope(envelope(MessageType::AuthLogIn,
                                                                 QJsonObject { { QStringLiteral("sessionToken"), issued_token() } }))
            .has_value());
}

void AuthenticationProtocolTest::roundTripsAuthenticationResult()
{
    AuthenticationResult original;
    original.user          = UserIdentity { 42, QStringLiteral("Alice"), QStringLiteral("Alice Example") };
    original.session_token = issued_token();
    original.expires_at    = 123456789;
    const auto json        = tcp_chat::protocol::authentication_result_to_json(original);
    QVERIFY(json.has_value());
    const auto decoded = tcp_chat::protocol::authentication_result_from_envelope(envelope(MessageType::AuthResult, *json));
    QVERIFY(decoded.has_value());
    QCOMPARE(decoded, original);
}

void AuthenticationProtocolTest::roundTripsLogoutResult()
{
    const AuthenticationResult original { std::nullopt, std::nullopt, std::nullopt, true };
    const auto json = tcp_chat::protocol::authentication_result_to_json(original);
    QVERIFY(json.has_value());
    QCOMPARE(json->value(QStringLiteral("revoked")).toBool(), true);
    const auto decoded = tcp_chat::protocol::authentication_result_from_envelope(envelope(MessageType::AuthResult, *json));
    QVERIFY(decoded.has_value());
    QCOMPARE(decoded, original);
}

void AuthenticationProtocolTest::rejectsInvalidResults()
{
    AuthenticationResult invalid;
    invalid.user          = UserIdentity { 1, QStringLiteral("Alice"), QStringLiteral("Alice") };
    invalid.expires_at    = 100;
    invalid.session_token = QStringLiteral("not-a-valid-token");
    QVERIFY(!tcp_chat::protocol::authentication_result_to_json(invalid).has_value());

    QVERIFY(!tcp_chat::protocol::authentication_result_from_envelope(envelope(MessageType::AuthResult,
                                                                         QJsonObject { { QStringLiteral("revoked"), true }, { QStringLiteral("user"), QJsonObject { } } }))
            .has_value());
    QVERIFY(!tcp_chat::protocol::authentication_result_from_envelope(envelope(MessageType::AuthResult, QJsonObject { })).has_value());
    QVERIFY(!tcp_chat::protocol::authentication_result_from_envelope(envelope(MessageType::AuthResult,
                                                                         QJsonObject { { QStringLiteral("revoked"), false } }))
            .has_value());
}

} // namespace

QTEST_GUILESS_MAIN(AuthenticationProtocolTest)

#include "test_auth_protocol.moc"

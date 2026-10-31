#include "auth/session_token.h"

#include <QTest>

namespace {

using tcp_chat::auth::digest_session_token;
using tcp_chat::auth::generate_session_token;
using tcp_chat::auth::GeneratedSessionToken;
using tcp_chat::auth::session_token_bytes;
using tcp_chat::auth::session_token_encoded_size;

/// Verifies opaque session-token generation, validation, and digesting.
class SessionTokenTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks encoding shape and agreement between both digest paths.
    void generatesExpectedShapeAndMatchingDigest();
    /// Checks independent token generation.
    void generatesDistinctTokens();
    /// Provides malformed encoded tokens.
    void rejectsMalformedTokens_data();
    /// Checks exact-length and strict Base64URL validation.
    void rejectsMalformedTokens();
    /// Checks the persisted digest is not the token or its decoded bytes.
    void digestContainsNoPlaintext();
};

void SessionTokenTest::generatesExpectedShapeAndMatchingDigest()
{
    const auto generated = generate_session_token();
    QVERIFY(generated.has_value());
    QCOMPARE(generated->value.size(), session_token_encoded_size);
    QCOMPARE(generated->digest.size(), session_token_bytes);

    const QByteArray encoded = generated->value.toLatin1();
    QVERIFY(!encoded.contains('='));
    for (const char character : encoded) {
        QVERIFY((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')
            || (character >= '0' && character <= '9') || character == '-' || character == '_');
    }

    const auto decoded = QByteArray::fromBase64Encoding(encoded,
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals | QByteArray::AbortOnBase64DecodingErrors);
    QVERIFY(decoded);
    QCOMPARE(decoded.decoded.size(), session_token_bytes);

    const auto digest = digest_session_token(generated->value);
    QVERIFY(digest.has_value());
    QCOMPARE(*digest, generated->digest);
}

void SessionTokenTest::generatesDistinctTokens()
{
    const auto first  = generate_session_token();
    const auto second = generate_session_token();
    QVERIFY(first.has_value());
    QVERIFY(second.has_value());
    QVERIFY(first->value != second->value);
    QVERIFY(first->digest != second->digest);
}

void SessionTokenTest::rejectsMalformedTokens_data()
{
    const auto generated = generate_session_token();
    QVERIFY(generated.has_value());
    const QString valid = generated->value;

    QString illegal_character = valid;
    illegal_character.replace(4, 1, QLatin1Char('*'));
    QString standard_base64 = valid;
    standard_base64.replace(4, 1, QLatin1Char('+'));
    QString embedded_null = valid;
    embedded_null.replace(4, 1, QChar(u'\0'));
    QString non_ascii = valid;
    non_ascii.replace(4, 1, QChar(u'\u00e9'));

    QTest::addColumn<QString>("token");
    QTest::newRow("empty") << QString();
    QTest::newRow("short") << valid.left(session_token_encoded_size - 1);
    QTest::newRow("long") << valid + QLatin1Char('A');
    QTest::newRow("padded") << valid + QLatin1Char('=');
    QTest::newRow("illegal character") << illegal_character;
    QTest::newRow("standard Base64 alphabet") << standard_base64;
    QTest::newRow("embedded NUL") << embedded_null;
    QTest::newRow("non-ASCII") << non_ascii;
}

void SessionTokenTest::rejectsMalformedTokens()
{
    QFETCH(QString, token);
    QVERIFY(!digest_session_token(token).has_value());
}

void SessionTokenTest::digestContainsNoPlaintext()
{
    const GeneratedSessionToken generated = generate_session_token().value();
    const auto decoded                    = QByteArray::fromBase64Encoding(generated.value.toLatin1(),
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals | QByteArray::AbortOnBase64DecodingErrors);
    QVERIFY(decoded);
    QVERIFY(generated.digest != decoded.decoded);
    QVERIFY(!generated.digest.contains(decoded.decoded));
    QVERIFY(!generated.digest.contains(generated.value.toLatin1()));
}

} // namespace

QTEST_GUILESS_MAIN(SessionTokenTest)

#include "test_session_token.moc"

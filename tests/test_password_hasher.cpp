#include "auth/password_hasher.h"

#include <QTest>

Q_DECLARE_METATYPE(tcp_chat::auth::PasswordVerification)

namespace {

using tcp_chat::auth::Argon2idParameters;
using tcp_chat::auth::PasswordHasher;
using tcp_chat::auth::PasswordVerification;

/// Returns inexpensive parameters suitable for offline tests.
Argon2idParameters test_parameters()
{
    return Argon2idParameters { 1, 1024 * 1024 };
}

/// Verifies Argon2id password hashing and input validation.
class PasswordHasherTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks successful hashing and verification.
    void hashesAndVerifiesPassword();
    /// Checks rejection of an incorrect password.
    void rejectsWrongPassword();
    /// Checks that equal passwords receive independent random salts.
    void generatesUniqueSalts();
    /// Provides passwords requiring length-aware UTF-8 handling.
    void supportsUnicodeAndEmbeddedNull_data();
    /// Checks Unicode and embedded-NUL password round trips.
    void supportsUnicodeAndEmbeddedNull();
    /// Checks an empty password remains valid at this layer.
    void acceptsEmptyPassword();
    /// Checks malformed and oversized encoded hashes.
    void rejectsMalformedHashes();
    /// Checks the password-size boundary in both operations.
    void validatesPasswordSize();
    /// Checks invalid Argon2id configuration is rejected.
    void rejectsInvalidParameters();
    /// Checks defaults match libsodium's interactive profile.
    void usesInteractiveParametersByDefault();
};

void PasswordHasherTest::hashesAndVerifiesPassword()
{
    const PasswordHasher hasher(test_parameters());
    const QByteArray password = QByteArrayLiteral("correct horse battery staple");
    const auto encoded        = hasher.hash(password);
    QVERIFY(encoded.has_value());
    QVERIFY(encoded->startsWith(QStringLiteral("$argon2id$")));
    QCOMPARE(hasher.verify(password, *encoded), PasswordVerification::Match);
}

void PasswordHasherTest::rejectsWrongPassword()
{
    const PasswordHasher hasher(test_parameters());
    const auto encoded = hasher.hash(QByteArrayLiteral("right password"));
    QVERIFY(encoded.has_value());
    QCOMPARE(hasher.verify(QByteArrayLiteral("wrong password"), *encoded), PasswordVerification::Mismatch);
}

void PasswordHasherTest::generatesUniqueSalts()
{
    const PasswordHasher hasher(test_parameters());
    const QByteArray password = QByteArrayLiteral("same password");
    const auto first          = hasher.hash(password);
    const auto second         = hasher.hash(password);
    QVERIFY(first.has_value());
    QVERIFY(second.has_value());
    QVERIFY(*first != *second);
    QCOMPARE(hasher.verify(password, *first), PasswordVerification::Match);
    QCOMPARE(hasher.verify(password, *second), PasswordVerification::Match);
}

void PasswordHasherTest::supportsUnicodeAndEmbeddedNull_data()
{
    QTest::addColumn<QByteArray>("password");
    QTest::newRow("unicode") << QStringLiteral("p\u00e2ssword \u5bc6\u7801 \U0001f512").toUtf8();
    QTest::newRow("embedded NUL") << QByteArray("abc\0def", 7);
}

void PasswordHasherTest::supportsUnicodeAndEmbeddedNull()
{
    QFETCH(QByteArray, password);
    const PasswordHasher hasher(test_parameters());
    const auto encoded = hasher.hash(password);
    QVERIFY(encoded.has_value());
    QCOMPARE(hasher.verify(password, *encoded), PasswordVerification::Match);
}

void PasswordHasherTest::acceptsEmptyPassword()
{
    const PasswordHasher hasher(test_parameters());
    const auto encoded = hasher.hash(QByteArrayView());
    QVERIFY(encoded.has_value());
    QCOMPARE(hasher.verify(QByteArrayView(), *encoded), PasswordVerification::Match);
    QCOMPARE(hasher.verify(QByteArrayLiteral("not empty"), *encoded), PasswordVerification::Mismatch);
}

void PasswordHasherTest::rejectsMalformedHashes()
{
    const PasswordHasher hasher(test_parameters());
    const auto valid = hasher.hash(QByteArrayLiteral("password"));
    QVERIFY(valid.has_value());

    QString embedded_null = *valid;
    embedded_null.insert(10, QChar(u'\0'));
    QString non_ascii = *valid;
    non_ascii.replace(10, 1, QChar(u'\u00e9'));
    const QList<QString> malformed {
        QString(),
        QStringLiteral("not an Argon2id hash"),
        valid->left(20),
        *valid + QLatin1Char('!'),
        embedded_null,
        non_ascii,
        QString(crypto_pwhash_STRBYTES, QLatin1Char('a')),
    };
    for (qsizetype index = 0; index < malformed.size(); ++index) {
        QVERIFY2(hasher.verify(QByteArrayLiteral("password"), malformed.at(index)) == PasswordVerification::InvalidHash,
            qPrintable(QStringLiteral("Malformed hash index %1 was not rejected").arg(index)));
    }
}

void PasswordHasherTest::validatesPasswordSize()
{
    const PasswordHasher hasher(test_parameters());
    const QByteArray maximum(1024, 'x');
    const auto encoded = hasher.hash(maximum);
    QVERIFY(encoded.has_value());
    QCOMPARE(hasher.verify(maximum, *encoded), PasswordVerification::Match);

    const QByteArray oversized(1025, 'x');
    QVERIFY(!hasher.hash(oversized).has_value());
    QCOMPARE(hasher.verify(oversized, *encoded), PasswordVerification::InvalidInput);
}

void PasswordHasherTest::rejectsInvalidParameters()
{
    const PasswordHasher no_operations(Argon2idParameters { 0, 1024 * 1024 });
    QVERIFY(!no_operations.hash(QByteArrayLiteral("password")).has_value());

    const PasswordHasher insufficient_memory(Argon2idParameters { 1, crypto_pwhash_MEMLIMIT_MIN - 1 });
    QVERIFY(!insufficient_memory.hash(QByteArrayLiteral("password")).has_value());

    const PasswordHasher valid(test_parameters());
    const auto encoded = valid.hash(QByteArrayLiteral("password"));
    QVERIFY(encoded.has_value());
    QCOMPARE(no_operations.verify(QByteArrayLiteral("password"), *encoded), PasswordVerification::InvalidInput);
    QCOMPARE(insufficient_memory.verify(QByteArrayLiteral("password"), *encoded), PasswordVerification::InvalidInput);
}

void PasswordHasherTest::usesInteractiveParametersByDefault()
{
    const PasswordHasher hasher;
    QCOMPARE(hasher.parameters().operations_limit,
        static_cast<unsigned long long>(crypto_pwhash_OPSLIMIT_INTERACTIVE));
    QCOMPARE(hasher.parameters().memory_limit, static_cast<size_t>(crypto_pwhash_MEMLIMIT_INTERACTIVE));
}

} // namespace

QTEST_GUILESS_MAIN(PasswordHasherTest)

#include "test_password_hasher.moc"

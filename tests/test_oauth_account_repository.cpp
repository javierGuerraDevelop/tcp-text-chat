#include "storage/account_repository.h"

#include "storage_test_utils.h"

#include <QSqlQuery>
#include <QTemporaryDir>
#include <QTest>

Q_DECLARE_METATYPE(tcp_chat::storage::StorageErrorCode)

namespace {

using tcp_chat::storage::AccountRepository;
using tcp_chat::storage::NewOAuthUser;
using tcp_chat::storage::StorageErrorCode;

/// Returns a valid OAuth-only user candidate.
NewOAuthUser oauth_user(const QString& subject = QStringLiteral("subject-1"))
{
    return NewOAuthUser { QStringLiteral("fake"), subject, QStringLiteral("user_abc123"),
        QStringLiteral("user_abc123"), QStringLiteral("user_abc123"), 1000 };
}

/// Counts persisted rows without exposing database contents in failures.
int row_count(QSqlDatabase& database, const QString& table)
{
    QSqlQuery query(database);
    if (!query.exec(QStringLiteral("SELECT COUNT(*) FROM ") + table) || !query.next()) {
        return -1;
    }
    return query.value(0).toInt();
}

} // namespace

/// Verifies transactional OAuth account provisioning and identity isolation.
class OAuthAccountRepositoryTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks repeat sign-in, null password hashes, and exact-subject behavior.
    void findsOrProvisionsIdentity();
    /// Checks that username collisions never link an existing local user.
    void rejectsUsernameCollisionWithoutMerging();
    /// Checks provider identifiers remain case-sensitive and subjects distinct.
    void isolatesProviderAndSubject();
    /// Checks bad provider and subject input before SQL execution.
    void validatesIdentityInput();
};

void OAuthAccountRepositoryTest::findsOrProvisionsIdentity()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository repository(connection.database());
    tcp_chat::storage::StorageError error;
    const auto created = repository.find_or_create_oauth_user(oauth_user(), &error);
    QVERIFY(created.has_value());
    QCOMPARE(error.code, StorageErrorCode::None);
    QCOMPARE(created->password_hash, std::nullopt);
    QCOMPARE(row_count(connection.database(), QStringLiteral("oauth_accounts")), 1);

    NewOAuthUser repeat        = oauth_user();
    repeat.username            = QStringLiteral("user_different");
    repeat.normalized_username = repeat.username;
    repeat.display_name        = repeat.username;
    const auto existing        = repository.find_or_create_oauth_user(repeat, &error);
    QVERIFY(existing.has_value());
    QCOMPARE(*existing, *created);
    QCOMPARE(row_count(connection.database(), QStringLiteral("users")), 1);
    QCOMPARE(row_count(connection.database(), QStringLiteral("oauth_accounts")), 1);
}

void OAuthAccountRepositoryTest::rejectsUsernameCollisionWithoutMerging()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository repository(connection.database());
    QVERIFY(repository.find_or_create_oauth_user(oauth_user()).has_value());

    NewOAuthUser other = oauth_user(QStringLiteral("different-subject"));
    tcp_chat::storage::StorageError error;
    QVERIFY(!repository.find_or_create_oauth_user(other, &error).has_value());
    QCOMPARE(error.code, StorageErrorCode::Conflict);
    QCOMPARE(row_count(connection.database(), QStringLiteral("users")), 1);
    QCOMPARE(row_count(connection.database(), QStringLiteral("oauth_accounts")), 1);

    other.username            = QStringLiteral("user_new");
    other.normalized_username = other.username;
    other.display_name        = other.username;
    const auto second         = repository.find_or_create_oauth_user(other, &error);
    QVERIFY(second.has_value());
    other.provider_subject = QStringLiteral("third-subject");
    QVERIFY(!repository.find_or_create_oauth_user(other, &error).has_value());
    QCOMPARE(error.code, StorageErrorCode::Conflict);
    QCOMPARE(row_count(connection.database(), QStringLiteral("users")), 2);
    QCOMPARE(row_count(connection.database(), QStringLiteral("oauth_accounts")), 2);
}

void OAuthAccountRepositoryTest::isolatesProviderAndSubject()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository repository(connection.database());
    const auto first = repository.find_or_create_oauth_user(oauth_user());
    QVERIFY(first.has_value());
    NewOAuthUser second        = oauth_user();
    second.provider            = QStringLiteral("other");
    second.username            = QStringLiteral("user_other");
    second.normalized_username = second.username;
    second.display_name        = second.username;
    const auto other           = repository.find_or_create_oauth_user(second);
    QVERIFY(other.has_value());
    QVERIFY(other->id != first->id);
    QCOMPARE(row_count(connection.database(), QStringLiteral("oauth_accounts")), 2);
}

void OAuthAccountRepositoryTest::validatesIdentityInput()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository repository(connection.database());
    QList<NewOAuthUser> inputs;
    NewOAuthUser input = oauth_user();
    input.provider     = QStringLiteral("Fake");
    inputs.append(input);
    input = oauth_user();
    input.provider_subject.clear();
    inputs.append(input);
    input                  = oauth_user();
    input.provider_subject = QString(257, QLatin1Char('x'));
    inputs.append(input);
    input     = oauth_user();
    input.now = -1;
    inputs.append(input);
    for (const auto& candidate : inputs) {
        tcp_chat::storage::StorageError error;
        QVERIFY(!repository.find_or_create_oauth_user(candidate, &error).has_value());
        QCOMPARE(error.code, StorageErrorCode::InvalidInput);
    }
    QCOMPARE(row_count(connection.database(), QStringLiteral("users")), 0);
}

QTEST_GUILESS_MAIN(OAuthAccountRepositoryTest)

#include "test_oauth_account_repository.moc"

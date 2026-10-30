#include "storage/account_repository.h"

#include "storage/migration_runner.h"
#include "storage_test_utils.h"

#include <QTemporaryDir>
#include <QTest>

Q_DECLARE_METATYPE(tcp_chat::storage::StorageErrorCode)

namespace {

using tcp_chat::storage::AccountRepository;
using tcp_chat::storage::NewLocalUser;
using tcp_chat::storage::StorageErrorCode;

/// Returns valid local-user input for repository tests.
NewLocalUser local_user()
{
    return NewLocalUser {
        QStringLiteral("Alice"),
        QStringLiteral("alice"),
        QStringLiteral("Alice Example"),
        QStringLiteral("argon2id-encoded-hash"),
        1000,
    };
}

} // namespace

/// Verifies local account persistence and lookup behavior.
class AccountRepositoryTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks insertion and both lookup paths.
    void createsAndFindsLocalUser();
    /// Checks normalized-username uniqueness.
    void rejectsDuplicateNormalizedUsername();
    /// Checks missing-user error reporting.
    void reportsMissingUser();
    /// Checks incomplete input rejection before SQL execution.
    void validatesLocalUserInput();
};

void AccountRepositoryTest::createsAndFindsLocalUser()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository repository(connection.database());

    tcp_chat::storage::StorageError error;
    const auto created = repository.create_local_user(local_user(), &error);
    QVERIFY(created.has_value());
    QVERIFY(created->id > 0);
    QCOMPARE(created->username, QStringLiteral("Alice"));
    QCOMPARE(created->password_hash, std::optional<QString> { QStringLiteral("argon2id-encoded-hash") });
    QCOMPARE(created->created_at, 1000);
    QCOMPARE(created->updated_at, 1000);
    QCOMPARE(error.code, StorageErrorCode::None);

    const auto by_id = repository.find_user_by_id(created->id, &error);
    QVERIFY(by_id.has_value());
    QCOMPARE(*by_id, *created);
    const auto by_name = repository.find_user_by_normalized_username(QStringLiteral("alice"), &error);
    QVERIFY(by_name.has_value());
    QCOMPARE(*by_name, *created);
}

void AccountRepositoryTest::rejectsDuplicateNormalizedUsername()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository repository(connection.database());
    QVERIFY(repository.create_local_user(local_user()).has_value());

    NewLocalUser duplicate = local_user();
    duplicate.username     = QStringLiteral("Different Alice");
    tcp_chat::storage::StorageError error;
    const auto result = repository.create_local_user(duplicate, &error);
    QVERIFY(!result.has_value());
    QCOMPARE(error.code, StorageErrorCode::Conflict);
}

void AccountRepositoryTest::reportsMissingUser()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository repository(connection.database());

    tcp_chat::storage::StorageError error;
    const auto result = repository.find_user_by_id(12345, &error);
    QVERIFY(!result.has_value());
    QCOMPARE(error.code, StorageErrorCode::NotFound);
}

void AccountRepositoryTest::validatesLocalUserInput()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository repository(connection.database());

    QList<NewLocalUser> inputs;
    NewLocalUser input = local_user();
    input.username.clear();
    inputs.append(input);
    input = local_user();
    input.normalized_username.clear();
    inputs.append(input);
    input = local_user();
    input.display_name.clear();
    inputs.append(input);
    input = local_user();
    input.password_hash.clear();
    inputs.append(input);
    input     = local_user();
    input.now = -1;
    inputs.append(input);

    for (const NewLocalUser& candidate : inputs) {
        tcp_chat::storage::StorageError error;
        const auto result = repository.create_local_user(candidate, &error);
        QVERIFY(!result.has_value());
        QCOMPARE(error.code, StorageErrorCode::InvalidInput);
    }
}

QTEST_GUILESS_MAIN(AccountRepositoryTest)

#include "test_account_repository.moc"

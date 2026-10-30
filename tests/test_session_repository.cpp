#include "storage/session_repository.h"

#include "storage/account_repository.h"
#include "storage_test_utils.h"

#include <QTemporaryDir>
#include <QTest>

Q_DECLARE_METATYPE(tcp_chat::storage::StorageErrorCode)

namespace {

using tcp_chat::storage::AccountRepository;
using tcp_chat::storage::NewLocalUser;
using tcp_chat::storage::NewSession;
using tcp_chat::storage::SessionRepository;
using tcp_chat::storage::StorageErrorCode;
using tcp_chat::storage::UserRecord;

/// Creates a user for session foreign-key tests.
UserRecord create_user(AccountRepository& repository)
{
    const auto user = repository.create_local_user(NewLocalUser {
        QStringLiteral("Alice"), QStringLiteral("alice"), QStringLiteral("Alice"), QStringLiteral("hash"), 1000 });
    return user.value_or(UserRecord { });
}

/// Returns valid session input for a given user ID.
NewSession session_for(qint64 user_id)
{
    return NewSession { user_id, QByteArray(32, 's'), 1000, 5000, 1000 };
}

} // namespace

/// Verifies session expiry, revocation, and digest persistence.
class SessionRepositoryTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks creation and active lookup.
    void createsAndFindsActiveSession();
    /// Checks the exact expiry boundary.
    void rejectsExpiredSession();
    /// Checks revocation and repeated revocation.
    void revokesSessionIdempotently();
    /// Checks invalid digest and timestamp rejection.
    void validatesSessionInput();
    /// Checks the user foreign key.
    void enforcesUserForeignKey();
    /// Checks token-digest uniqueness.
    void rejectsDuplicateDigest();
};

void SessionRepositoryTest::createsAndFindsActiveSession()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository accounts(connection.database());
    SessionRepository sessions(connection.database());
    const UserRecord user = create_user(accounts);
    QVERIFY(user.id > 0);

    tcp_chat::storage::StorageError error;
    const auto created = sessions.create_session(session_for(user.id), &error);
    QVERIFY(created.has_value());
    QCOMPARE(created->user_id, user.id);
    QCOMPARE(created->token_digest, QByteArray(32, 's'));
    QVERIFY(!created->revoked_at.has_value());

    const auto active = sessions.find_active_session(created->token_digest, 2000, &error);
    QVERIFY(active.has_value());
    QCOMPARE(*active, *created);
}

void SessionRepositoryTest::rejectsExpiredSession()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository accounts(connection.database());
    SessionRepository sessions(connection.database());
    const UserRecord user = create_user(accounts);
    const auto created    = sessions.create_session(session_for(user.id));
    QVERIFY(created.has_value());

    tcp_chat::storage::StorageError error;
    const auto active = sessions.find_active_session(created->token_digest, 5000, &error);
    QVERIFY(!active.has_value());
    QCOMPARE(error.code, StorageErrorCode::NotFound);
}

void SessionRepositoryTest::revokesSessionIdempotently()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository accounts(connection.database());
    SessionRepository sessions(connection.database());
    const UserRecord user = create_user(accounts);
    const auto created    = sessions.create_session(session_for(user.id));
    QVERIFY(created.has_value());

    const auto revoked = sessions.revoke_session(created->id, 3000);
    QVERIFY(revoked.has_value());
    QCOMPARE(revoked->revoked_at, std::optional<qint64> { 3000 });
    const auto revoked_again = sessions.revoke_session(created->id, 4000);
    QVERIFY(revoked_again.has_value());
    QCOMPARE(revoked_again->revoked_at, std::optional<qint64> { 3000 });

    tcp_chat::storage::StorageError error;
    const auto active = sessions.find_active_session(created->token_digest, 2000, &error);
    QVERIFY(!active.has_value());
    QCOMPARE(error.code, StorageErrorCode::NotFound);
}

void SessionRepositoryTest::validatesSessionInput()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository accounts(connection.database());
    SessionRepository sessions(connection.database());
    const UserRecord user = create_user(accounts);

    QList<NewSession> inputs;
    NewSession input   = session_for(user.id);
    input.token_digest = QByteArrayLiteral("short");
    inputs.append(input);
    input            = session_for(user.id);
    input.expires_at = input.created_at;
    inputs.append(input);
    input              = session_for(user.id);
    input.last_seen_at = input.created_at - 1;
    inputs.append(input);
    input         = session_for(user.id);
    input.user_id = 0;
    inputs.append(input);

    for (const NewSession& candidate : inputs) {
        tcp_chat::storage::StorageError error;
        const auto result = sessions.create_session(candidate, &error);
        QVERIFY(!result.has_value());
        QCOMPARE(error.code, StorageErrorCode::InvalidInput);
    }
}

void SessionRepositoryTest::enforcesUserForeignKey()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    SessionRepository sessions(connection.database());

    tcp_chat::storage::StorageError error;
    const auto result = sessions.create_session(session_for(999), &error);
    QVERIFY(!result.has_value());
    QCOMPARE(error.code, StorageErrorCode::ConstraintViolation);
}

void SessionRepositoryTest::rejectsDuplicateDigest()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository accounts(connection.database());
    SessionRepository sessions(connection.database());
    const UserRecord user = create_user(accounts);
    QVERIFY(sessions.create_session(session_for(user.id)).has_value());

    tcp_chat::storage::StorageError error;
    const auto duplicate = sessions.create_session(session_for(user.id), &error);
    QVERIFY(!duplicate.has_value());
    QCOMPARE(error.code, StorageErrorCode::Conflict);
}

QTEST_GUILESS_MAIN(SessionRepositoryTest)

#include "test_session_repository.moc"

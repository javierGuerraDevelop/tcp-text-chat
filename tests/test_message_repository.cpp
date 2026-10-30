#include "storage/message_repository.h"

#include "storage/account_repository.h"
#include "storage_test_utils.h"

#include <QSqlQuery>
#include <QTemporaryDir>
#include <QTest>

Q_DECLARE_METATYPE(tcp_chat::storage::StorageErrorCode)

namespace {

using tcp_chat::storage::AccountRepository;
using tcp_chat::storage::MessageRepository;
using tcp_chat::storage::NewLocalUser;
using tcp_chat::storage::NewMessage;
using tcp_chat::storage::StorageErrorCode;
using tcp_chat::storage::UserRecord;

/// Creates a sender for message foreign-key tests.
UserRecord create_sender(AccountRepository& repository)
{
    const auto user = repository.create_local_user(NewLocalUser {
        QStringLiteral("Alice"), QStringLiteral("alice"), QStringLiteral("Alice"), QStringLiteral("hash"), 1000 });
    return user.value_or(UserRecord { });
}

/// Returns valid message input for a sender and sequence number.
NewMessage message_for(qint64 sender_id, int sequence)
{
    return NewMessage {
        sender_id,
        QStringLiteral("client-%1").arg(sequence),
        QStringLiteral("message %1").arg(sequence),
        1000 + sequence,
    };
}

} // namespace

/// Verifies idempotent message insertion and chronological history queries.
class MessageRepositoryTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks insertion and both pagination directions.
    void appendsAndPagesMessages();
    /// Checks exact send retry behavior and row count.
    void returnsExistingMessageForIdempotentRetry();
    /// Checks idempotency-key misuse detection.
    void rejectsDifferentContentForSameClientId();
    /// Checks message field validation before SQL execution.
    void validatesMessageInput();
    /// Checks the sender foreign key.
    void enforcesSenderForeignKey();
};

void MessageRepositoryTest::appendsAndPagesMessages()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository accounts(connection.database());
    MessageRepository messages(connection.database());
    const UserRecord sender = create_sender(accounts);
    QVERIFY(sender.id > 0);

    QList<qint64> ids;
    for (int sequence = 1; sequence <= 5; ++sequence) {
        const auto appended = messages.append_message(message_for(sender.id, sequence));
        QVERIFY(appended.has_value());
        QVERIFY(appended->inserted);
        ids.append(appended->message.id);
    }

    const auto latest = messages.history_before(std::nullopt, 2);
    QVERIFY(latest.has_value());
    QCOMPARE(latest->size(), 2);
    QCOMPARE((*latest)[0].id, ids[3]);
    QCOMPARE((*latest)[1].id, ids[4]);

    const auto older = messages.history_before(ids[3], 2);
    QVERIFY(older.has_value());
    QCOMPARE(older->size(), 2);
    QCOMPARE((*older)[0].id, ids[1]);
    QCOMPARE((*older)[1].id, ids[2]);

    const auto after = messages.history_after(ids[1], 2);
    QVERIFY(after.has_value());
    QCOMPARE(after->size(), 2);
    QCOMPARE((*after)[0].id, ids[2]);
    QCOMPARE((*after)[1].id, ids[3]);

    const auto empty = messages.history_after(ids[4], 2);
    QVERIFY(empty.has_value());
    QVERIFY(empty->isEmpty());
}

void MessageRepositoryTest::returnsExistingMessageForIdempotentRetry()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository accounts(connection.database());
    MessageRepository messages(connection.database());
    const UserRecord sender = create_sender(accounts);
    const NewMessage input  = message_for(sender.id, 1);

    const auto first = messages.append_message(input);
    QVERIFY(first.has_value());
    QVERIFY(first->inserted);
    const auto retry = messages.append_message(input);
    QVERIFY(retry.has_value());
    QVERIFY(!retry->inserted);
    QCOMPARE(retry->message, first->message);

    QSqlQuery count(connection.database());
    QVERIFY(count.exec(QStringLiteral("SELECT COUNT(*) FROM messages")));
    QVERIFY(count.next());
    QCOMPARE(count.value(0).toInt(), 1);
}

void MessageRepositoryTest::rejectsDifferentContentForSameClientId()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository accounts(connection.database());
    MessageRepository messages(connection.database());
    const UserRecord sender = create_sender(accounts);
    QVERIFY(messages.append_message(message_for(sender.id, 1)).has_value());

    NewMessage changed = message_for(sender.id, 1);
    changed.body       = QStringLiteral("different");
    tcp_chat::storage::StorageError error;
    const auto result = messages.append_message(changed, &error);
    QVERIFY(!result.has_value());
    QCOMPARE(error.code, StorageErrorCode::Conflict);
}

void MessageRepositoryTest::validatesMessageInput()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    AccountRepository accounts(connection.database());
    MessageRepository messages(connection.database());
    const UserRecord sender = create_sender(accounts);

    QList<NewMessage> inputs;
    NewMessage input = message_for(sender.id, 1);
    input.body.clear();
    inputs.append(input);
    input      = message_for(sender.id, 1);
    input.body = QStringLiteral(" \n");
    inputs.append(input);
    input      = message_for(sender.id, 1);
    input.body = QString(tcp_chat::storage::maximum_message_body_size + 1, QLatin1Char('x'));
    inputs.append(input);
    input = message_for(sender.id, 1);
    input.client_message_id.clear();
    inputs.append(input);
    input                   = message_for(sender.id, 1);
    input.client_message_id = QString(tcp_chat::storage::maximum_client_message_id_size + 1, QLatin1Char('x'));
    inputs.append(input);
    input            = message_for(sender.id, 1);
    input.created_at = -1;
    inputs.append(input);
    input           = message_for(sender.id, 1);
    input.sender_id = 0;
    inputs.append(input);

    for (const NewMessage& candidate : inputs) {
        tcp_chat::storage::StorageError error;
        const auto result = messages.append_message(candidate, &error);
        QVERIFY(!result.has_value());
        QCOMPARE(error.code, StorageErrorCode::InvalidInput);
    }
}

void MessageRepositoryTest::enforcesSenderForeignKey()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(tcp_chat::testing::initialize_database(connection));
    MessageRepository messages(connection.database());

    tcp_chat::storage::StorageError error;
    const auto result = messages.append_message(message_for(999, 1), &error);
    QVERIFY(!result.has_value());
    QCOMPARE(error.code, StorageErrorCode::ConstraintViolation);
}

QTEST_GUILESS_MAIN(MessageRepositoryTest)

#include "test_message_repository.moc"

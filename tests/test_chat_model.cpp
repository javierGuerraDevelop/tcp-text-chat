#include "client/chat_model.h"

#include <QTest>

namespace {

using tcp_chat::client::ChatModel;
using tcp_chat::protocol::ChatMessage;
using tcp_chat::protocol::UserIdentity;

/// Creates a public message with a selectable sender and client ID.
ChatMessage message(qint64 id, const QString& client_id = QStringLiteral("client"), qint64 sender_id = 7)
{
    return ChatMessage {
        id,
        UserIdentity { sender_id, QStringLiteral("user_%1").arg(sender_id), QStringLiteral("User %1").arg(sender_id) },
        client_id,
        QStringLiteral("message %1").arg(id),
        1000 + id,
    };
}

/// Verifies bounded model ordering, deduplication, and delivery transitions.
class ChatModelTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks pending acknowledgement and live-event deduplication.
    void acknowledgesAndDeduplicates();
    /// Checks incremental older and newer history batches.
    void mergesHistoryBatches();
    /// Checks the loaded window bound in both pagination directions.
    void boundsLoadedMessages();
    /// Checks failed retry state and outgoing alignment.
    void tracksDeliveryAndIdentity();
};

void ChatModelTest::acknowledgesAndDeduplicates()
{
    ChatModel model;
    model.set_user(UserIdentity { 7, QStringLiteral("Alice"), QStringLiteral("Alice") });
    model.add_pending(QStringLiteral("client-1"), QStringLiteral("<b>plain text</b>"));
    QCOMPARE(model.rowCount(), 1);
    QCOMPARE(model.data(model.index(0)), QStringLiteral("<b>plain text</b>"));
    QCOMPARE(model.data(model.index(0), ChatModel::DeliveryRole).toInt(), static_cast<int>(ChatModel::Delivery::Sending));
    QVERIFY(model.data(model.index(0), ChatModel::OutgoingRole).toBool());

    const ChatMessage persisted = message(42, QStringLiteral("client-1"));
    model.mark_sent(QStringLiteral("client-1"), persisted);
    QCOMPARE(model.rowCount(), 1);
    QCOMPARE(model.data(model.index(0), ChatModel::IdRole).toLongLong(), 42);
    QCOMPARE(model.delivery_for_client_id(QStringLiteral("client-1")), std::optional<ChatModel::Delivery> { ChatModel::Delivery::Sent });

    model.append_message(persisted);
    QCOMPARE(model.rowCount(), 1);
    ChatMessage other_sender = message(43, QStringLiteral("client-1"), 8);
    model.append_message(other_sender);
    QCOMPARE(model.rowCount(), 2);
    QCOMPARE(model.data(model.index(1), ChatModel::SenderRole).toString(), QStringLiteral("User 8"));
}

void ChatModelTest::mergesHistoryBatches()
{
    ChatModel model;
    model.append_history({ message(3), message(4) });
    model.prepend_history({ message(1), message(2) });
    model.append_history({ message(4), message(5) });
    model.prepend_history({ message(1), message(2) });
    QCOMPARE(model.rowCount(), 5);
    for (int row = 0; row < 5; ++row) {
        QCOMPARE(model.data(model.index(row), ChatModel::IdRole).toLongLong(), row + 1);
    }
    QCOMPARE(model.first_message_id(), 1);
    QCOMPARE(model.last_message_id(), 5);

    model.add_pending(QStringLiteral("pending"), QStringLiteral("pending"));
    model.append_history({ message(6) });
    QCOMPARE(model.rowCount(), 7);
    QCOMPARE(model.data(model.index(5), ChatModel::IdRole).toLongLong(), 6);
    QCOMPARE(model.data(model.index(6), ChatModel::IdRole).toLongLong(), 0);
}

void ChatModelTest::boundsLoadedMessages()
{
    ChatModel model;
    QList<ChatMessage> messages;
    for (qint64 id = 1; id <= 510; ++id) {
        messages.append(message(id));
    }
    model.append_history(messages);
    QCOMPARE(model.rowCount(), ChatModel::maximum_loaded_messages);
    QCOMPARE(model.first_message_id(), 11);
    QCOMPARE(model.last_message_id(), 510);

    model.add_pending(QStringLiteral("pending"), QStringLiteral("pending"));
    QList<ChatMessage> older;
    for (qint64 id = 1; id <= 10; ++id) {
        older.append(message(id));
    }
    model.prepend_history(older);
    QCOMPARE(model.rowCount(), ChatModel::maximum_loaded_messages);
    QCOMPARE(model.first_message_id(), 1);
    QCOMPARE(model.last_message_id(), 500);
    QCOMPARE(model.data(model.index(model.rowCount() - 1), ChatModel::ClientMessageIdRole).toString(), QStringLiteral("pending"));
}

void ChatModelTest::tracksDeliveryAndIdentity()
{
    ChatModel model;
    model.set_user(UserIdentity { 7, QStringLiteral("Alice"), QStringLiteral("Alice") });
    model.add_pending(QStringLiteral("client-1"), QStringLiteral("body"));
    model.mark_failed(QStringLiteral("client-1"));
    QCOMPARE(model.delivery_for_client_id(QStringLiteral("client-1")), std::optional<ChatModel::Delivery> { ChatModel::Delivery::Failed });
    model.mark_sending(QStringLiteral("client-1"));
    QCOMPARE(model.delivery_for_client_id(QStringLiteral("client-1")), std::optional<ChatModel::Delivery> { ChatModel::Delivery::Sending });
    model.mark_sent(QStringLiteral("client-1"), message(1, QStringLiteral("client-1")));
    QCOMPARE(model.delivery_for_client_id(QStringLiteral("client-1")), std::optional<ChatModel::Delivery> { ChatModel::Delivery::Sent });

    model.set_user(UserIdentity { 7, QStringLiteral("Alice"), QStringLiteral("Renamed") });
    QVERIFY(model.data(model.index(0), ChatModel::OutgoingRole).toBool());
    model.set_user(UserIdentity { 8, QStringLiteral("Bob"), QStringLiteral("Bob") });
    QVERIFY(!model.data(model.index(0), ChatModel::OutgoingRole).toBool());
    model.clear();
    QCOMPARE(model.rowCount(), 0);
    QCOMPARE(model.last_message_id(), 0);
}

} // namespace

QTEST_GUILESS_MAIN(ChatModelTest)

#include "test_chat_model.moc"

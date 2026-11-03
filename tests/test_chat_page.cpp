#include "client/chat_model.h"
#include "client/chat_page.h"

#include <QLabel>
#include <QListView>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalSpy>
#include <QTest>

namespace {

using tcp_chat::client::ChatModel;
using tcp_chat::client::ChatPage;
using tcp_chat::protocol::ChatMessage;
using tcp_chat::protocol::UserIdentity;

/// Creates a connected page with an attached model and public identity.
class ChatPageFixture {
public:
    /// Initializes the model, identity, and connected controls.
    ChatPageFixture()
    {
        page.set_model(&model);
        page.set_user(user);
        page.set_connection_state(ChatPage::ConnectionState::Connected);
    }

    ChatModel model;
    ChatPage page;
    UserIdentity user { 7, QStringLiteral("Alice"), QStringLiteral("Alice Example") };
};

/// Verifies chat keyboard behavior, recovery actions, and model-backed rendering.
class ChatPageTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks draft validation, Enter submission, and Shift+Enter newlines.
    void composerKeyboardAndValidation();
    /// Checks failed-message activation and reconnect controls.
    void retryAndReconnect();
    /// Checks older-history actions and plain-text wrapping geometry.
    void historyAndRendering();
};

void ChatPageTest::composerKeyboardAndValidation()
{
    ChatPageFixture fixture;
    auto* composer = fixture.page.findChild<QPlainTextEdit*>(QStringLiteral("messageComposer"));
    auto* send     = fixture.page.findChild<QPushButton*>(QStringLiteral("sendMessage"));
    QVERIFY(composer != nullptr && send != nullptr);
    QVERIFY(!send->isEnabled());
    composer->setPlainText(QStringLiteral("Hello room"));
    QVERIFY(send->isEnabled());

    QSignalSpy sent(&fixture.page, &ChatPage::send_requested);
    QTest::keyClick(composer, Qt::Key_Return);
    QCOMPARE(sent.size(), 1);
    QCOMPARE(sent.at(0).at(0).toString(), QStringLiteral("Hello room"));
    QCOMPARE(composer->toPlainText(), QStringLiteral("Hello room"));
    fixture.page.clear_composer();
    QVERIFY(composer->toPlainText().isEmpty());

    QTest::keyClick(composer, Qt::Key_Return, Qt::ShiftModifier);
    QTest::keyClicks(composer, QStringLiteral("second line"));
    QCOMPARE(composer->toPlainText(), QStringLiteral("\nsecond line"));
    composer->setPlainText(QString(tcp_chat::protocol::maximum_chat_body_length + 1, QLatin1Char('x')));
    QVERIFY(!send->isEnabled());
    QCOMPARE(fixture.page.findChild<QLabel*>(QStringLiteral("messageCounter"))->text(),
        QStringLiteral("4001 / 4000"));
}

void ChatPageTest::retryAndReconnect()
{
    ChatPageFixture fixture;
    fixture.model.add_pending(QStringLiteral("client-1"), QStringLiteral("retry body"));
    fixture.model.mark_failed(QStringLiteral("client-1"));
    auto* messages = fixture.page.findChild<QListView*>(QStringLiteral("messageList"));
    QVERIFY(messages != nullptr);
    QSignalSpy retry(&fixture.page, &ChatPage::retry_requested);
    emit messages->activated(fixture.model.index(0));
    QCOMPARE(retry.size(), 1);
    QCOMPARE(retry.at(0).at(0).toString(), QStringLiteral("client-1"));

    QSignalSpy reconnect(&fixture.page, &ChatPage::reconnect_requested);
    fixture.page.set_connection_state(ChatPage::ConnectionState::Disconnected, QStringLiteral("Connection lost"));
    auto* button   = fixture.page.findChild<QPushButton*>(QStringLiteral("reconnectChat"));
    auto* composer = fixture.page.findChild<QPlainTextEdit*>(QStringLiteral("messageComposer"));
    QVERIFY(button != nullptr && button->isEnabled());
    QVERIFY(composer->isReadOnly());
    QVERIFY(fixture.page.findChild<QWidget*>(QStringLiteral("chatConnectionBanner"))->isVisibleTo(&fixture.page));
    button->click();
    QCOMPARE(reconnect.size(), 1);

    fixture.page.set_connection_state(ChatPage::ConnectionState::Reconnecting);
    QVERIFY(!button->isEnabled());
    fixture.page.set_connection_state(ChatPage::ConnectionState::Connected);
    QVERIFY(fixture.page.findChild<QWidget*>(QStringLiteral("chatConnectionBanner"))->isHidden());
    QVERIFY(!composer->isReadOnly());
}

void ChatPageTest::historyAndRendering()
{
    ChatPageFixture fixture;
    ChatMessage message;
    message.id                = 1;
    message.sender            = fixture.user;
    message.client_message_id = QStringLiteral("client-1");
    message.body              = QStringLiteral("<b>Plain text</b>\nwith a second line");
    message.created_at        = 1000;
    fixture.model.append_message(message);
    fixture.page.set_older_history_available(true);
    fixture.page.resize(760, 640);
    fixture.page.show();
    QVERIFY(QTest::qWaitForWindowExposed(&fixture.page));

    auto* messages = fixture.page.findChild<QListView*>(QStringLiteral("messageList"));
    auto* older    = fixture.page.findChild<QPushButton*>(QStringLiteral("loadOlder"));
    QVERIFY(messages != nullptr && older != nullptr);
    QVERIFY(older->isVisibleTo(&fixture.page));
    QCOMPARE(messages->model(), &fixture.model);
    QCOMPARE(fixture.model.data(fixture.model.index(0)), message.body);
    QVERIFY(messages->visualRect(fixture.model.index(0)).height() > 40);

    QSignalSpy load_older(&fixture.page, &ChatPage::load_older_requested);
    older->click();
    QCOMPARE(load_older.size(), 1);
    fixture.page.set_history_loading(true);
    QVERIFY(!older->isEnabled());
    QCOMPARE(older->text(), QStringLiteral("Loading…"));
    fixture.page.set_history_loading(false);
    QVERIFY(older->isEnabled());
}

} // namespace

QTEST_MAIN(ChatPageTest)

#include "test_chat_page.moc"

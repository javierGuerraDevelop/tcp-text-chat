#include "chat_page.h"

#include "chat_model.h"
#include "message_delegate.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QListView>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollBar>
#include <QStackedWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace tcp_chat::client {

ChatPage::ChatPage(QWidget* parent)
    : QWidget(parent)
    , identity_(new QLabel)
    , connection_banner_(new QFrame)
    , connection_status_(new QLabel)
    , reconnect_button_(new QPushButton(QStringLiteral("Reconnect")))
    , load_older_button_(new QPushButton(QStringLiteral("Load older messages")))
    , history_stack_(new QStackedWidget)
    , messages_(new QListView)
    , composer_(new QPlainTextEdit)
    , character_counter_(new QLabel)
    , send_button_(new QPushButton(QStringLiteral("Send")))
    , sign_out_button_(new QPushButton(QStringLiteral("Sign out")))
    , error_message_(new QLabel)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(28, 24, 28, 24);
    layout->setSpacing(12);

    auto* top_bar = new QHBoxLayout;
    auto* titles  = new QVBoxLayout;
    auto* title   = new QLabel(QStringLiteral("General room"), this);
    title->setObjectName(QStringLiteral("pageTitle"));
    title->setProperty("role", QStringLiteral("title"));
    titles->addWidget(title);
    auto* subtitle = new QLabel(QStringLiteral("One shared conversation with everyone in the room."), this);
    subtitle->setProperty("role", QStringLiteral("secondary"));
    titles->addWidget(subtitle);
    top_bar->addLayout(titles);
    top_bar->addStretch();

    identity_->setObjectName(QStringLiteral("chatIdentity"));
    identity_->setProperty("role", QStringLiteral("secondary"));
    identity_->setTextFormat(Qt::PlainText);
    top_bar->addWidget(identity_);
    sign_out_button_->setObjectName(QStringLiteral("signOut"));
    sign_out_button_->setAccessibleName(QStringLiteral("Sign out"));
    top_bar->addWidget(sign_out_button_);
    layout->addLayout(top_bar);

    connection_banner_->setObjectName(QStringLiteral("chatConnectionBanner"));
    connection_banner_->setProperty("role", QStringLiteral("banner"));
    auto* banner_layout = new QHBoxLayout(connection_banner_);
    banner_layout->setContentsMargins(12, 6, 12, 6);
    connection_status_->setObjectName(QStringLiteral("chatConnectionStatus"));
    connection_status_->setWordWrap(true);
    connection_status_->setTextFormat(Qt::PlainText);
    banner_layout->addWidget(connection_status_, 1);
    reconnect_button_->setObjectName(QStringLiteral("reconnectChat"));
    reconnect_button_->setAccessibleName(QStringLiteral("Reconnect to the room"));
    banner_layout->addWidget(reconnect_button_);
    layout->addWidget(connection_banner_);

    load_older_button_->setObjectName(QStringLiteral("loadOlder"));
    load_older_button_->setAccessibleName(QStringLiteral("Load older messages"));
    layout->addWidget(load_older_button_, 0, Qt::AlignCenter);

    auto* loading_page   = new QWidget(history_stack_);
    auto* loading_layout = new QVBoxLayout(loading_page);
    loading_layout->addStretch();
    auto* loading_label = new QLabel(QStringLiteral("Loading messages…"), loading_page);
    loading_label->setObjectName(QStringLiteral("loadingChatLabel"));
    loading_label->setProperty("role", QStringLiteral("heading"));
    loading_label->setAlignment(Qt::AlignCenter);
    loading_layout->addWidget(loading_label);
    auto* progress = new QProgressBar(loading_page);
    progress->setRange(0, 0);
    progress->setTextVisible(false);
    progress->setAccessibleName(QStringLiteral("Loading message history"));
    loading_layout->addWidget(progress, 0, Qt::AlignHCenter);
    loading_layout->addStretch();
    history_stack_->addWidget(loading_page);

    auto* empty_page   = new QWidget(history_stack_);
    auto* empty_layout = new QVBoxLayout(empty_page);
    empty_layout->addStretch();
    auto* empty_label = new QLabel(QStringLiteral("No messages yet"), empty_page);
    empty_label->setObjectName(QStringLiteral("emptyChatLabel"));
    empty_label->setProperty("role", QStringLiteral("heading"));
    empty_label->setAlignment(Qt::AlignCenter);
    empty_layout->addWidget(empty_label);
    auto* empty_description = new QLabel(QStringLiteral("Send the first message to start the conversation."), empty_page);
    empty_description->setProperty("role", QStringLiteral("secondary"));
    empty_description->setAlignment(Qt::AlignCenter);
    empty_layout->addWidget(empty_description);
    empty_layout->addStretch();
    history_stack_->addWidget(empty_page);

    messages_->setObjectName(QStringLiteral("messageList"));
    messages_->setAccessibleName(QStringLiteral("Room messages"));
    messages_->setItemDelegate(new MessageDelegate(messages_));
    messages_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    messages_->setSelectionMode(QAbstractItemView::SingleSelection);
    messages_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    messages_->setResizeMode(QListView::Adjust);
    messages_->setLayoutMode(QListView::Batched);
    messages_->setUniformItemSizes(false);
    messages_->setToolTip(QStringLiteral("Click or press Enter on a failed message to retry it"));
    history_stack_->addWidget(messages_);
    layout->addWidget(history_stack_, 1);

    error_message_->setObjectName(QStringLiteral("chatError"));
    error_message_->setProperty("role", QStringLiteral("error"));
    error_message_->setTextFormat(Qt::PlainText);
    error_message_->setWordWrap(true);
    error_message_->hide();
    layout->addWidget(error_message_);

    auto* composer_row = new QHBoxLayout;
    composer_->setObjectName(QStringLiteral("messageComposer"));
    composer_->setAccessibleName(QStringLiteral("Message body"));
    composer_->setPlaceholderText(QStringLiteral("Message the room  ·  Enter to send, Shift+Enter for a new line"));
    composer_->setTabChangesFocus(true);
    composer_->setMinimumHeight(76);
    composer_->setMaximumHeight(112);
    composer_->installEventFilter(this);
    composer_row->addWidget(composer_, 1);

    auto* send_column = new QVBoxLayout;
    send_button_->setObjectName(QStringLiteral("sendMessage"));
    send_button_->setAccessibleName(QStringLiteral("Send message"));
    send_button_->setProperty("role", QStringLiteral("primary"));
    send_column->addWidget(send_button_);
    character_counter_->setObjectName(QStringLiteral("messageCounter"));
    character_counter_->setProperty("role", QStringLiteral("secondary"));
    character_counter_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    send_column->addWidget(character_counter_);
    send_column->addStretch();
    composer_row->addLayout(send_column);
    layout->addLayout(composer_row);

    connect(send_button_, &QPushButton::clicked, this, &ChatPage::submit);
    connect(composer_, &QPlainTextEdit::textChanged, this, &ChatPage::update_composer);
    connect(reconnect_button_, &QPushButton::clicked, this, &ChatPage::reconnect_requested);
    connect(sign_out_button_, &QPushButton::clicked, this, &ChatPage::log_out_requested);
    connect(load_older_button_, &QPushButton::clicked, this, &ChatPage::request_older_history);
    connect(messages_, &QListView::activated, this, &ChatPage::retry_message);
    connect(messages_, &QListView::clicked, this, &ChatPage::retry_message);

    set_connection_state(ConnectionState::Disconnected, QStringLiteral("Connect to the server to join the room."));
    set_older_history_available(false);
    update_history_content();
}

void ChatPage::set_model(ChatModel* model)
{
    if (model_ == model) {
        return;
    }
    if (model_ != nullptr) {
        disconnect(model_, nullptr, this, nullptr);
    }
    model_ = model;
    messages_->setModel(model_);
    if (model_ != nullptr) {
        connect(model_, &ChatModel::rowsInserted, this, &ChatPage::rows_inserted);
        connect(model_, &ChatModel::rowsRemoved, this, [this] { update_history_content(); });
        connect(model_, &ChatModel::modelReset, this, [this] { update_history_content(); });
    }
    update_history_content();
}

void ChatPage::set_user(const protocol::UserIdentity& user)
{
    identity_->setText(QStringLiteral("Signed in as %1 (@%2)").arg(user.display_name, user.username));
}

void ChatPage::set_connection_state(ConnectionState state, const QString& status)
{
    connected_ = state == ConnectionState::Connected;
    connection_banner_->setVisible(!connected_);
    reconnect_button_->setEnabled(state == ConnectionState::Disconnected);
    if (connected_) {
        connection_status_->clear();
        error_message_->clear();
        error_message_->hide();
    } else if (!status.trimmed().isEmpty()) {
        connection_status_->setText(status.trimmed());
    } else {
        connection_status_->setText(state == ConnectionState::Reconnecting
                ? QStringLiteral("Reconnecting and restoring your session…")
                : QStringLiteral("Disconnected. Reconnect to resume the conversation."));
    }
    sign_out_button_->setEnabled(connected_);
    update_composer();
}

void ChatPage::set_history_loading(bool loading)
{
    history_loading_ = loading;
    load_older_button_->setEnabled(connected_ && !loading);
    load_older_button_->setText(loading ? QStringLiteral("Loading…") : QStringLiteral("Load older messages"));
    if (!loading) {
        preserve_scroll_ = false;
    }
    update_history_content();
}

void ChatPage::set_older_history_available(bool available)
{
    older_history_available_ = available;
    load_older_button_->setVisible(available);
    load_older_button_->setEnabled(connected_ && !history_loading_);
}

void ChatPage::show_error(const QString& message)
{
    preserve_scroll_ = false;
    error_message_->setText(message.trimmed());
    error_message_->setVisible(!message.trimmed().isEmpty());
}

void ChatPage::clear_composer()
{
    composer_->clear();
    composer_->setFocus(Qt::OtherFocusReason);
}

bool ChatPage::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == composer_ && event->type() == QEvent::KeyPress) {
        const auto* key = static_cast<QKeyEvent*>(event);
        if ((key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter) && !key->modifiers().testFlag(Qt::ShiftModifier)) {
            submit();
            return true;
        }
    }
    return QWidget::eventFilter(watched, event);
}

void ChatPage::submit()
{
    if (send_button_->isEnabled()) {
        emit send_requested(composer_->toPlainText());
    }
}

void ChatPage::update_composer()
{
    const QString body = composer_->toPlainText();
    character_counter_->setText(QStringLiteral("%1 / %2").arg(body.size()).arg(protocol::maximum_chat_body_length));
    send_button_->setEnabled(connected_ && protocol::valid_chat_body(body));
    composer_->setReadOnly(!connected_);
}

void ChatPage::update_history_content()
{
    if (model_ != nullptr && model_->rowCount() > 0) {
        history_stack_->setCurrentIndex(2);
    } else {
        history_stack_->setCurrentIndex(history_loading_ ? 0 : 1);
    }
    load_older_button_->setVisible(older_history_available_ && model_ != nullptr && model_->rowCount() > 0);
}

void ChatPage::retry_message(const QModelIndex& index)
{
    if (!connected_ || !index.isValid()
        || index.data(ChatModel::DeliveryRole).toInt() != static_cast<int>(ChatModel::Delivery::Failed)) {
        return;
    }
    const QString client_message_id = index.data(ChatModel::ClientMessageIdRole).toString();
    if (!client_message_id.isEmpty()) {
        emit retry_requested(client_message_id);
    }
}

void ChatPage::rows_inserted(const QModelIndex& parent, int first, int last)
{
    Q_UNUSED(parent);
    Q_UNUSED(first);
    update_history_content();
    QScrollBar* scroll = messages_->verticalScrollBar();
    if (preserve_scroll_) {
        preserve_scroll_           = false;
        const int previous_value   = previous_scroll_value_;
        const int previous_maximum = previous_scroll_maximum_;
        QTimer::singleShot(0, this, [this, previous_value, previous_maximum] {
            messages_->verticalScrollBar()->setValue(messages_->verticalScrollBar()->maximum() - previous_maximum + previous_value);
        });
        return;
    }
    const bool outgoing = model_ != nullptr && model_->data(model_->index(last), ChatModel::OutgoingRole).toBool();
    if (outgoing || scroll->value() >= scroll->maximum() - 80) {
        QTimer::singleShot(0, messages_, &QListView::scrollToBottom);
    }
}

void ChatPage::request_older_history()
{
    QScrollBar* scroll       = messages_->verticalScrollBar();
    previous_scroll_value_   = scroll->value();
    previous_scroll_maximum_ = scroll->maximum();
    preserve_scroll_         = true;
    emit load_older_requested();
}

} // namespace tcp_chat::client

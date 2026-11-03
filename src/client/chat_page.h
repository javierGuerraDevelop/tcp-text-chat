#pragma once

#include "tcp_chat/auth_protocol.h"

#include <QWidget>

class QAbstractItemModel;
class QFrame;
class QLabel;
class QListView;
class QPlainTextEdit;
class QPushButton;
class QStackedWidget;

namespace tcp_chat::client {

class ChatModel;

/// Presents the shared room with incremental history, composition, and connection feedback.
class ChatPage final : public QWidget {
    Q_OBJECT

public:
    /// Identifies the connection presentation without changing network ownership.
    enum class ConnectionState {
        Connected,
        Reconnecting,
        Disconnected,
    };
    Q_ENUM(ConnectionState)

    /// Creates a disconnected page; child widgets and the delegate are Qt-owned.
    explicit ChatPage(QWidget* parent = nullptr);

    /// Attaches the bounded message model, replacing any previous model connections.
    void set_model(ChatModel* model);
    /// Displays the authenticated identity as plain text.
    void set_user(const protocol::UserIdentity& user);
    /// Shows connected, reconnecting, or disconnected controls and status.
    void set_connection_state(ConnectionState state, const QString& status = QString());
    /// Updates history progress without replacing already loaded messages.
    void set_history_loading(bool loading);
    /// Shows or hides the older-history action.
    void set_older_history_available(bool available);
    /// Displays a safe operation error within the chat page.
    void show_error(const QString& message);
    /// Clears an accepted composer draft and returns keyboard focus.
    void clear_composer();

signals:
    /// Emits the unmodified draft after local nonblank and length validation.
    void send_requested(const QString& body);
    /// Emits the idempotency key of a failed message activated by the user.
    void retry_requested(const QString& client_message_id);
    /// Requests the next older history page.
    void load_older_requested();
    /// Requests session-preserving network recovery.
    void reconnect_requested();
    /// Requests revocation of the current session.
    void log_out_requested();

protected:
    /// Sends on Enter while preserving Shift+Enter for a newline.
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    /// Submits the composer when its current contents and connection are valid.
    void submit();
    /// Updates the send action and character counter after draft or connection changes.
    void update_composer();
    /// Selects loading, empty, or populated history content.
    void update_history_content();
    /// Retries only failed entries activated by pointer or keyboard.
    void retry_message(const QModelIndex& index);
    /// Preserves scroll position for prepends and follows new messages near the bottom.
    void rows_inserted(const QModelIndex& parent, int first, int last);
    /// Captures the current scroll geometry before requesting older history.
    void request_older_history();

    ChatModel* model_ = nullptr;
    QLabel* const identity_;
    QFrame* const connection_banner_;
    QLabel* const connection_status_;
    QPushButton* const reconnect_button_;
    QPushButton* const load_older_button_;
    QStackedWidget* const history_stack_;
    QListView* const messages_;
    QPlainTextEdit* const composer_;
    QLabel* const character_counter_;
    QPushButton* const send_button_;
    QPushButton* const sign_out_button_;
    QLabel* const error_message_;
    bool connected_               = false;
    bool history_loading_         = false;
    bool older_history_available_ = false;
    bool preserve_scroll_         = false;
    int previous_scroll_value_    = 0;
    int previous_scroll_maximum_  = 0;
};

} // namespace tcp_chat::client

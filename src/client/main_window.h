#pragma once

#include "tcp_chat/auth_protocol.h"
#include "theme_manager.h"

#include <QMainWindow>

class QComboBox;
class QLabel;
class QStackedWidget;

namespace tcp_chat::client {

class AuthenticationPage;

/// Owns the client navigation and its authentication, connection, chat, and error states.
class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    /// Identifies the single application page currently presented to the user.
    enum class Page {
        Welcome,
        Connecting,
        Chat,
        Error,
    };
    Q_ENUM(Page)

    /// Creates the window; the theme manager must outlive it and all child widgets are Qt-owned.
    explicit MainWindow(ThemeManager& theme_manager, QWidget* parent = nullptr);

    /// Shows a top-level application state without performing network operations.
    void show_page(Page page);
    /// Shows a recoverable connection error using plain, caller-sanitized text.
    void show_error(const QString& message);
    /// Displays authentication progress without exposing credential contents.
    void set_authentication_busy(bool busy, const QString& status = QString());
    /// Returns to the forms with a safe error and cleared password fields.
    void show_authentication_error(const QString& message);
    /// Resets the forms and optionally displays a neutral status message.
    void reset_authentication(const QString& status = QString());
    /// Shows the shared-room empty state for an authenticated public identity.
    void show_authenticated(const protocol::UserIdentity& user);
    /// Returns the visible application state.
    Page current_page() const;

signals:
    /// Emits validated local sign-in fields.
    void log_in_requested(const QString& username, const QString& password);
    /// Emits validated signup fields and an optional display name.
    void sign_up_requested(const QString& username, const QString& password, const QString& display_name);
    /// Emits the selected Google or GitHub provider identifier.
    void oauth_requested(const QString& provider);
    /// Emits when the user cancels connection or authentication work.
    void cancel_requested();
    /// Emits when the user retries a failed connection.
    void retry_requested();

private:
    /// Builds a theme preference control initialized from the manager.
    QComboBox* create_theme_selector(QWidget* parent);

    ThemeManager& theme_manager_;
    QComboBox* const theme_selector_;
    QStackedWidget* const pages_;
    QLabel* const error_message_;
    AuthenticationPage* const authentication_page_;
    QLabel* const chat_identity_;
};

} // namespace tcp_chat::client

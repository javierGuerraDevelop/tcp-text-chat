#pragma once

#include <QWidget>

class QCheckBox;
class QLabel;
class QLineEdit;
class QProgressBar;
class QPushButton;
class QTabWidget;

namespace tcp_chat::client {

/// Presents validated local login/signup forms and provider sign-in actions without performing I/O.
class AuthenticationPage final : public QWidget {
    Q_OBJECT

public:
    /// Creates parent-owned form controls with no initial network activity.
    explicit AuthenticationPage(QWidget* parent = nullptr);

    /// Enables or disables all credential actions and displays optional progress text.
    void set_busy(bool busy, const QString& status = QString());
    /// Restores the forms, clears passwords, and presents a safe plain-text error.
    void show_error(const QString& message);
    /// Restores the sign-in tab and clears all passwords and transient messages.
    void reset();
    /// Returns whether an authentication action is in progress.
    bool is_busy() const;

signals:
    /// Emits validated local sign-in fields for one attempt.
    void log_in_requested(const QString& username, const QString& password);
    /// Emits validated account fields; an empty display name lets the server use the username.
    void sign_up_requested(const QString& username, const QString& password, const QString& display_name);
    /// Emits the canonical provider identifier selected by the user.
    void oauth_requested(const QString& provider);
    /// Emits when the user cancels an in-progress authentication action.
    void cancel_requested();

private:
    /// Validates and emits the sign-in form.
    void submit_log_in();
    /// Validates and emits the signup form when both passwords match.
    void submit_sign_up();
    /// Begins a provider flow without reading or storing provider credentials.
    void start_oauth(const QString& provider);
    /// Updates the default action when the selected local-auth tab changes.
    void mode_changed(int index);
    /// Shows a local validation error without emitting credentials.
    void validation_error(const QString& message);
    /// Returns whether a password's UTF-8 representation satisfies protocol limits.
    static bool valid_password(const QString& password);

    QTabWidget* const modes_;
    QLineEdit* login_username_;
    QLineEdit* login_password_;
    QLineEdit* signup_username_;
    QLineEdit* signup_display_name_;
    QLineEdit* signup_password_;
    QLineEdit* signup_confirmation_;
    QCheckBox* const show_password_;
    QPushButton* const login_button_;
    QPushButton* const signup_button_;
    QPushButton* const google_button_;
    QPushButton* const github_button_;
    QPushButton* const cancel_button_;
    QProgressBar* const progress_;
    QLabel* const status_;
    QLabel* const error_;
    bool busy_ = false;
};

} // namespace tcp_chat::client

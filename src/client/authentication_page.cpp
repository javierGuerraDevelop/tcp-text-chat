#include "authentication_page.h"

#include "tcp_chat/auth_protocol.h"

#include <QCheckBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QTabWidget>
#include <QVBoxLayout>

namespace tcp_chat::client {
namespace {

    /// Creates a labeled, keyboard-focusable credential field.
    QLineEdit* create_field(QWidget* parent, QFormLayout* form, const QString& label, const QString& name, bool password = false)
    {
        auto* field = new QLineEdit(parent);
        field->setObjectName(name);
        field->setAccessibleName(label);
        field->setClearButtonEnabled(!password);
        if (password) {
            field->setEchoMode(QLineEdit::Password);
        }
        auto* field_label = new QLabel(label, parent);
        field_label->setBuddy(field);
        form->addRow(field_label, field);
        return field;
    }

    /// Creates a form page for use inside the local authentication tabs.
    QWidget* create_form(QTabWidget* tabs, const QString& label, QFormLayout** form)
    {
        auto* page = new QWidget(tabs);
        *form      = new QFormLayout(page);
        (*form)->setContentsMargins(0, 12, 0, 8);
        (*form)->setHorizontalSpacing(16);
        (*form)->setVerticalSpacing(10);
        (*form)->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        tabs->addTab(page, label);
        return page;
    }

} // namespace

AuthenticationPage::AuthenticationPage(QWidget* parent)
    : QWidget(parent)
    , modes_(new QTabWidget(this))
    , login_username_(nullptr)
    , login_password_(nullptr)
    , signup_username_(nullptr)
    , signup_display_name_(nullptr)
    , signup_password_(nullptr)
    , signup_confirmation_(nullptr)
    , show_password_(new QCheckBox(QStringLiteral("Show passwords"), this))
    , login_button_(new QPushButton(QStringLiteral("Sign in"), this))
    , signup_button_(new QPushButton(QStringLiteral("Create account"), this))
    , google_button_(new QPushButton(QStringLiteral("Continue with Google"), this))
    , github_button_(new QPushButton(QStringLiteral("Continue with GitHub"), this))
    , cancel_button_(new QPushButton(QStringLiteral("Cancel"), this))
    , progress_(new QProgressBar(this))
    , status_(new QLabel(this))
    , error_(new QLabel(this))
{
    setObjectName(QStringLiteral("authenticationPage"));
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 12, 0, 0);
    layout->setSpacing(12);

    modes_->setObjectName(QStringLiteral("authenticationModes"));
    modes_->setDocumentMode(true);
    QFormLayout* login_form  = nullptr;
    QWidget* login_page      = create_form(modes_, QStringLiteral("Sign in"), &login_form);
    QFormLayout* signup_form = nullptr;
    QWidget* signup_page     = create_form(modes_, QStringLiteral("Create account"), &signup_form);

    auto* login_username      = create_field(login_page, login_form, QStringLiteral("Username"), QStringLiteral("loginUsername"));
    auto* login_password      = create_field(login_page, login_form, QStringLiteral("Password"), QStringLiteral("loginPassword"), true);
    auto* signup_username     = create_field(signup_page, signup_form, QStringLiteral("Username"), QStringLiteral("signupUsername"));
    auto* signup_display      = create_field(signup_page, signup_form, QStringLiteral("Display name (optional)"), QStringLiteral("signupDisplayName"));
    auto* signup_password     = create_field(signup_page, signup_form, QStringLiteral("Password"), QStringLiteral("signupPassword"), true);
    auto* signup_confirmation = create_field(signup_page, signup_form, QStringLiteral("Confirm password"), QStringLiteral("signupConfirmation"), true);

    login_username_      = login_username;
    login_password_      = login_password;
    signup_username_     = signup_username;
    signup_display_name_ = signup_display;
    signup_password_     = signup_password;
    signup_confirmation_ = signup_confirmation;

    login_username_->setMaxLength(128);
    signup_username_->setMaxLength(128);
    signup_display_name_->setMaxLength(protocol::maximum_display_name_length);
    show_password_->setObjectName(QStringLiteral("showPasswords"));
    show_password_->setAccessibleName(QStringLiteral("Show passwords"));

    login_button_->setObjectName(QStringLiteral("loginSubmit"));
    login_button_->setProperty("role", QStringLiteral("primary"));
    signup_button_->setObjectName(QStringLiteral("signupSubmit"));
    signup_button_->setProperty("role", QStringLiteral("primary"));
    google_button_->setObjectName(QStringLiteral("googleSignIn"));
    github_button_->setObjectName(QStringLiteral("githubSignIn"));
    cancel_button_->setObjectName(QStringLiteral("cancelAuthentication"));
    cancel_button_->setAccessibleName(QStringLiteral("Cancel authentication"));

    layout->addWidget(modes_);
    layout->addWidget(show_password_, 0, Qt::AlignRight);
    layout->addWidget(login_button_);
    layout->addWidget(signup_button_);

    auto* separator = new QLabel(QStringLiteral("or continue with"), this);
    separator->setProperty("role", QStringLiteral("secondary"));
    separator->setAlignment(Qt::AlignCenter);
    layout->addWidget(separator);
    auto* providers = new QHBoxLayout;
    providers->setSpacing(12);
    providers->addWidget(google_button_);
    providers->addWidget(github_button_);
    layout->addLayout(providers);

    progress_->setObjectName(QStringLiteral("authenticationProgress"));
    progress_->setRange(0, 0);
    progress_->setTextVisible(false);
    progress_->setAccessibleName(QStringLiteral("Authentication in progress"));
    layout->addWidget(progress_);
    status_->setObjectName(QStringLiteral("authenticationStatus"));
    status_->setProperty("role", QStringLiteral("secondary"));
    status_->setWordWrap(true);
    layout->addWidget(status_);
    error_->setObjectName(QStringLiteral("authenticationError"));
    error_->setProperty("role", QStringLiteral("error"));
    error_->setTextFormat(Qt::PlainText);
    error_->setWordWrap(true);
    layout->addWidget(error_);
    cancel_button_->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    layout->addWidget(cancel_button_, 0, Qt::AlignRight);

    connect(modes_, &QTabWidget::currentChanged, this, &AuthenticationPage::mode_changed);
    connect(login_button_, &QPushButton::clicked, this, &AuthenticationPage::submit_log_in);
    connect(signup_button_, &QPushButton::clicked, this, &AuthenticationPage::submit_sign_up);
    connect(login_password_, &QLineEdit::returnPressed, this, &AuthenticationPage::submit_log_in);
    connect(signup_confirmation_, &QLineEdit::returnPressed, this, &AuthenticationPage::submit_sign_up);
    connect(google_button_, &QPushButton::clicked, this, [this]() { start_oauth(QStringLiteral("google")); });
    connect(github_button_, &QPushButton::clicked, this, [this]() { start_oauth(QStringLiteral("github")); });
    connect(cancel_button_, &QPushButton::clicked, this, &AuthenticationPage::cancel_requested);
    connect(show_password_, &QCheckBox::toggled, this, [this](bool visible) {
        const QLineEdit::EchoMode mode = visible ? QLineEdit::Normal : QLineEdit::Password;
        login_password_->setEchoMode(mode);
        signup_password_->setEchoMode(mode);
        signup_confirmation_->setEchoMode(mode);
    });

    reset();
}

void AuthenticationPage::set_busy(bool busy, const QString& status)
{
    busy_ = busy;
    modes_->setEnabled(!busy);
    login_username_->setEnabled(!busy);
    login_password_->setEnabled(!busy);
    signup_username_->setEnabled(!busy);
    signup_display_name_->setEnabled(!busy);
    signup_password_->setEnabled(!busy);
    signup_confirmation_->setEnabled(!busy);
    show_password_->setEnabled(!busy);
    login_button_->setEnabled(!busy);
    signup_button_->setEnabled(!busy);
    google_button_->setEnabled(!busy);
    github_button_->setEnabled(!busy);
    cancel_button_->setVisible(busy);
    progress_->setVisible(busy);
    status_->setText(status);
    status_->setVisible(!status.isEmpty());
    if (busy) {
        error_->clear();
        error_->hide();
    }
}

void AuthenticationPage::show_error(const QString& message)
{
    set_busy(false);
    error_->setText(message);
    error_->setVisible(!message.isEmpty());
    login_password_->clear();
    signup_password_->clear();
    signup_confirmation_->clear();
}

void AuthenticationPage::reset()
{
    set_busy(false);
    error_->clear();
    error_->hide();
    login_password_->clear();
    signup_password_->clear();
    signup_confirmation_->clear();
    show_password_->setChecked(false);
    if (modes_->currentIndex() == 0) {
        mode_changed(0);
    } else {
        modes_->setCurrentIndex(0);
    }
}

bool AuthenticationPage::is_busy() const
{
    return busy_;
}

void AuthenticationPage::submit_log_in()
{
    if (busy_) {
        return;
    }
    if (!protocol::normalize_username(login_username_->text()).has_value()) {
        validation_error(QStringLiteral("Enter a valid username using 3–32 letters, numbers, dots, dashes, or underscores."));
        return;
    }
    if (!valid_password(login_password_->text())) {
        validation_error(QStringLiteral("Passwords must contain between 8 and 1024 UTF-8 bytes."));
        return;
    }

    const QString username = login_username_->text().trimmed();
    const QString password = login_password_->text();
    set_busy(true, QStringLiteral("Signing in…"));
    login_password_->clear();
    emit log_in_requested(username, password);
}

void AuthenticationPage::submit_sign_up()
{
    if (busy_) {
        return;
    }
    if (!protocol::normalize_username(signup_username_->text()).has_value()) {
        validation_error(QStringLiteral("Use 3–32 letters, numbers, dots, dashes, or underscores for your username."));
        return;
    }
    const QString display_name = signup_display_name_->text().trimmed();
    if (!display_name.isEmpty() && !protocol::valid_display_name(display_name)) {
        validation_error(QStringLiteral("Display names must contain printable characters and no more than 64 characters."));
        return;
    }
    if (!valid_password(signup_password_->text())) {
        validation_error(QStringLiteral("Choose a password containing between 8 and 1024 UTF-8 bytes."));
        return;
    }
    if (signup_password_->text() != signup_confirmation_->text()) {
        validation_error(QStringLiteral("The passwords do not match."));
        return;
    }

    const QString username = signup_username_->text().trimmed();
    const QString password = signup_password_->text();
    set_busy(true, QStringLiteral("Creating your account…"));
    signup_password_->clear();
    signup_confirmation_->clear();
    emit sign_up_requested(username, password, display_name);
}

void AuthenticationPage::start_oauth(const QString& provider)
{
    if (busy_) {
        return;
    }
    set_busy(true, QStringLiteral("Opening your browser…"));
    emit oauth_requested(provider);
}

void AuthenticationPage::mode_changed(int index)
{
    error_->clear();
    error_->hide();
    login_password_->clear();
    signup_password_->clear();
    signup_confirmation_->clear();
    login_button_->setVisible(index == 0);
    signup_button_->setVisible(index == 1);
    login_button_->setDefault(index == 0);
    signup_button_->setDefault(index == 1);
}

void AuthenticationPage::validation_error(const QString& message)
{
    error_->setText(message);
    error_->show();
}

bool AuthenticationPage::valid_password(const QString& password)
{
    const qsizetype bytes = password.toUtf8().size();
    return bytes >= protocol::minimum_password_bytes && bytes <= protocol::maximum_password_bytes;
}

} // namespace tcp_chat::client

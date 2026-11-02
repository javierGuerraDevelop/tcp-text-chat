#include "main_window.h"

#include "authentication_page.h"

#include <QComboBox>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QStackedWidget>
#include <QVBoxLayout>

namespace tcp_chat::client {
namespace {

    /// Adds a centered content page with consistent width and spacing.
    QVBoxLayout* create_page(QStackedWidget* pages, const QString& title, const QString& description)
    {
        auto* page         = new QWidget(pages);
        auto* outer_layout = new QVBoxLayout(page);
        outer_layout->setContentsMargins(32, 32, 32, 32);
        outer_layout->addStretch();

        auto* card = new QFrame(page);
        card->setProperty("role", QStringLiteral("card"));
        card->setFixedWidth(600);
        auto* layout = new QVBoxLayout(card);
        layout->setContentsMargins(36, 36, 36, 36);
        layout->setSpacing(16);

        auto* title_label = new QLabel(title, card);
        title_label->setObjectName(QStringLiteral("pageTitle"));
        title_label->setProperty("role", QStringLiteral("title"));
        title_label->setWordWrap(true);
        layout->addWidget(title_label);

        auto* description_label = new QLabel(description, card);
        description_label->setProperty("role", QStringLiteral("secondary"));
        description_label->setWordWrap(true);
        layout->addWidget(description_label);

        outer_layout->addWidget(card, 0, Qt::AlignHCenter);
        outer_layout->addStretch();
        pages->addWidget(page);
        return layout;
    }

    /// Creates a horizontally aligned, keyboard-focusable action row.
    QHBoxLayout* create_action_row(QVBoxLayout* page_layout)
    {
        auto* row = new QHBoxLayout;
        row->setContentsMargins(0, 8, 0, 0);
        row->addStretch();
        page_layout->addLayout(row);
        return row;
    }

} // namespace

MainWindow::MainWindow(ThemeManager& theme_manager, QWidget* parent)
    : QMainWindow(parent)
    , theme_manager_(theme_manager)
    , theme_selector_(create_theme_selector(nullptr))
    , pages_(new QStackedWidget)
    , error_message_(new QLabel)
    , authentication_page_(new AuthenticationPage)
    , chat_identity_(new QLabel)
{
    setWindowTitle(QStringLiteral("TCP Chat"));
    setMinimumSize(800, 680);
    resize(1000, 760);

    auto* central_widget = new QWidget(this);
    auto* window_layout  = new QVBoxLayout(central_widget);
    window_layout->setContentsMargins(0, 0, 0, 0);
    window_layout->setSpacing(0);
    setCentralWidget(central_widget);

    auto* header = new QFrame(central_widget);
    header->setObjectName(QStringLiteral("navigation"));
    auto* header_layout = new QHBoxLayout(header);
    header_layout->setContentsMargins(32, 18, 32, 18);
    header_layout->setSpacing(12);

    auto* brand = new QLabel(QStringLiteral("TCP Chat"), header);
    brand->setProperty("role", QStringLiteral("brand"));
    brand->setAccessibleName(QStringLiteral("TCP Chat"));
    header_layout->addWidget(brand);
    header_layout->addStretch();

    auto* theme_label = new QLabel(QStringLiteral("Appearance"), header);
    theme_label->setProperty("role", QStringLiteral("secondary"));
    theme_label->setBuddy(theme_selector_);
    header_layout->addWidget(theme_label);
    header_layout->addWidget(theme_selector_);
    window_layout->addWidget(header);

    auto* content = new QFrame(central_widget);
    content->setObjectName(QStringLiteral("content"));
    auto* content_layout = new QVBoxLayout(content);
    content_layout->setContentsMargins(0, 0, 0, 0);
    pages_->setParent(content);
    content_layout->addWidget(pages_);
    window_layout->addWidget(content, 1);

    auto* welcome_layout = create_page(pages_, QStringLiteral("Good conversations start here."),
        QStringLiteral("Sign in or create an account to join one shared room with your people."));
    authentication_page_->setParent(welcome_layout->parentWidget());
    welcome_layout->addWidget(authentication_page_);

    auto* connecting_layout = create_page(pages_, QStringLiteral("Connecting securely"),
        QStringLiteral("Establishing an encrypted connection to the chat server."));
    auto* progress          = new QProgressBar(connecting_layout->parentWidget());
    progress->setObjectName(QStringLiteral("connectionProgress"));
    progress->setRange(0, 0);
    progress->setTextVisible(false);
    progress->setAccessibleName(QStringLiteral("Connection in progress"));
    connecting_layout->addWidget(progress);
    auto* cancel_button = new QPushButton(QStringLiteral("Cancel"), connecting_layout->parentWidget());
    cancel_button->setObjectName(QStringLiteral("cancelConnection"));
    cancel_button->setAccessibleName(QStringLiteral("Cancel connection"));
    create_action_row(connecting_layout)->addWidget(cancel_button);

    auto* chat_layout = create_page(pages_, QStringLiteral("General room"),
        QStringLiteral("One shared conversation with everyone in the room."));
    auto* empty_label = new QLabel(QStringLiteral("No messages yet"), chat_layout->parentWidget());
    empty_label->setObjectName(QStringLiteral("emptyChatLabel"));
    empty_label->setProperty("role", QStringLiteral("heading"));
    empty_label->setAlignment(Qt::AlignCenter);
    chat_layout->addSpacing(32);
    chat_layout->addWidget(empty_label);
    auto* empty_description = new QLabel(QStringLiteral("Messages you send will appear here."), chat_layout->parentWidget());
    empty_description->setProperty("role", QStringLiteral("secondary"));
    empty_description->setAlignment(Qt::AlignCenter);
    chat_layout->addWidget(empty_description);
    chat_identity_->setParent(chat_layout->parentWidget());
    chat_identity_->setObjectName(QStringLiteral("chatIdentity"));
    chat_identity_->setProperty("role", QStringLiteral("secondary"));
    chat_identity_->setTextFormat(Qt::PlainText);
    chat_identity_->setAlignment(Qt::AlignCenter);
    chat_layout->addWidget(chat_identity_);

    auto* error_layout = create_page(pages_, QStringLiteral("Unable to continue"), QString());
    error_message_->setParent(error_layout->parentWidget());
    error_message_->setObjectName(QStringLiteral("errorMessage"));
    error_message_->setProperty("role", QStringLiteral("error"));
    error_message_->setTextFormat(Qt::PlainText);
    error_message_->setWordWrap(true);
    error_layout->addWidget(error_message_);
    auto* retry_button = new QPushButton(QStringLiteral("Try again"), error_layout->parentWidget());
    retry_button->setObjectName(QStringLiteral("dismissError"));
    retry_button->setDefault(true);
    create_action_row(error_layout)->addWidget(retry_button);

    connect(theme_selector_, &QComboBox::currentIndexChanged, this, [this](int index) {
        const auto preference = static_cast<ThemeManager::Preference>(theme_selector_->itemData(index).toInt());
        theme_manager_.set_preference(preference);
    });
    connect(cancel_button, &QPushButton::clicked, this, [this]() {
        show_page(Page::Welcome);
        emit cancel_requested();
    });
    connect(retry_button, &QPushButton::clicked, this, [this]() {
        show_page(Page::Connecting);
        emit retry_requested();
    });
    connect(authentication_page_, &AuthenticationPage::log_in_requested, this, &MainWindow::log_in_requested);
    connect(authentication_page_, &AuthenticationPage::sign_up_requested, this, &MainWindow::sign_up_requested);
    connect(authentication_page_, &AuthenticationPage::oauth_requested, this, &MainWindow::oauth_requested);
    connect(authentication_page_, &AuthenticationPage::cancel_requested, this, &MainWindow::cancel_requested);

    show_page(Page::Welcome);
}

void MainWindow::show_page(Page page)
{
    pages_->setCurrentIndex(static_cast<int>(page));
}

void MainWindow::show_error(const QString& message)
{
    error_message_->setText(message.trimmed().isEmpty()
            ? QStringLiteral("Something went wrong. Check the server configuration and try again.")
            : message.trimmed());
    show_page(Page::Error);
}

void MainWindow::set_authentication_busy(bool busy, const QString& status)
{
    authentication_page_->set_busy(busy, status);
}

void MainWindow::show_authentication_error(const QString& message)
{
    show_page(Page::Welcome);
    authentication_page_->show_error(message);
}

void MainWindow::reset_authentication(const QString& status)
{
    authentication_page_->reset();
    authentication_page_->set_busy(false, status);
    show_page(Page::Welcome);
}

void MainWindow::show_authenticated(const protocol::UserIdentity& user)
{
    chat_identity_->setText(QStringLiteral("Signed in as %1 (@%2)").arg(user.display_name, user.username));
    show_page(Page::Chat);
}

MainWindow::Page MainWindow::current_page() const
{
    return static_cast<Page>(pages_->currentIndex());
}

QComboBox* MainWindow::create_theme_selector(QWidget* parent)
{
    auto* selector = new QComboBox(parent);
    selector->setObjectName(QStringLiteral("themeSelector"));
    selector->setAccessibleName(QStringLiteral("Theme"));
    selector->setToolTip(QStringLiteral("Auto follows your system's appearance"));
    selector->addItem(QStringLiteral("Auto"), static_cast<int>(ThemeManager::Preference::Auto));
    selector->addItem(QStringLiteral("Light"), static_cast<int>(ThemeManager::Preference::Light));
    selector->addItem(QStringLiteral("Dark"), static_cast<int>(ThemeManager::Preference::Dark));
    selector->setCurrentIndex(selector->findData(static_cast<int>(theme_manager_.preference())));
    return selector;
}

} // namespace tcp_chat::client

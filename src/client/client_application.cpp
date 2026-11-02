#include "client_application.h"

#include "main_window.h"

namespace tcp_chat::client {

ClientApplication::ClientApplication(MainWindow& window, AuthenticationController& controller,
    TlsClientConfiguration configuration, QObject* parent)
    : QObject(parent)
    , window_(window)
    , controller_(controller)
    , configuration_(std::move(configuration))
{
    connect(&window_, &MainWindow::log_in_requested, &controller_, &AuthenticationController::log_in);
    connect(&window_, &MainWindow::sign_up_requested, &controller_, [this](const QString& username, const QString& password, const QString& display_name) {
        controller_.sign_up(username, password,
            display_name.isEmpty() ? std::nullopt : std::optional<QString> { display_name });
    });
    connect(&window_, &MainWindow::oauth_requested, &controller_, &AuthenticationController::sign_in_with_provider);
    connect(&window_, &MainWindow::cancel_requested, this, [this]() {
        window_.show_page(MainWindow::Page::Connecting);
        controller_.cancel();
    });
    connect(&window_, &MainWindow::retry_requested, this, &ClientApplication::start);

    connect(&controller_, &AuthenticationController::state_changed, this, &ClientApplication::update_state);
    connect(&controller_, &AuthenticationController::authenticated, this, [this](const protocol::UserIdentity& user) {
        window_.show_authenticated(user);
    });
    connect(&controller_, &AuthenticationController::authentication_failed, this, [this](const QString& message) {
        if (controller_.user().has_value() && window_.current_page() == MainWindow::Page::Chat) {
            window_.show_error(message);
        } else {
            window_.show_authentication_error(message);
        }
    });
    connect(&controller_, &AuthenticationController::connection_failed, this, [this](const QString& message) {
        window_.show_error(message);
    });
    connect(&controller_, &AuthenticationController::logged_out, this, [this]() {
        window_.reset_authentication(QStringLiteral("You have signed out."));
    });
}

void ClientApplication::start()
{
    window_.show_page(MainWindow::Page::Connecting);
    controller_.connect_to_server(configuration_);
}

void ClientApplication::update_state(AuthenticationController::State state)
{
    switch (state) {
    case AuthenticationController::State::Connecting:
        window_.show_page(MainWindow::Page::Connecting);
        return;
    case AuthenticationController::State::Ready:
        window_.set_authentication_busy(false);
        window_.show_page(MainWindow::Page::Welcome);
        return;
    case AuthenticationController::State::Authenticating:
        if (window_.current_page() != MainWindow::Page::Chat) {
            window_.set_authentication_busy(true, QStringLiteral("Signing in…"));
            window_.show_page(MainWindow::Page::Welcome);
        }
        return;
    case AuthenticationController::State::BrowserPending:
        window_.set_authentication_busy(true, QStringLiteral("Finish signing in in your browser. You can cancel to return to the forms."));
        window_.show_page(MainWindow::Page::Welcome);
        return;
    case AuthenticationController::State::Authenticated:
        if (const auto user = controller_.user(); user.has_value()) {
            window_.show_authenticated(*user);
        }
        return;
    case AuthenticationController::State::Disconnected:
        return;
    }
}

} // namespace tcp_chat::client

#include "authentication_test_harness.h"
#include "client/authentication_controller.h"
#include "client/client_application.h"
#include "client/main_window.h"
#include "client/theme_manager.h"

#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSettings>
#include <QTabWidget>
#include <QTemporaryDir>
#include <QTest>

using tcp_chat::client::AuthenticationController;
using tcp_chat::client::ClientApplication;
using tcp_chat::client::MainWindow;
using tcp_chat::client::ThemeManager;
using tcp_chat::client::TlsClient;
using State = tcp_chat::client::AuthenticationController::State;

namespace {

/// Owns a real window/controller composition connected to one test backend.
class ClientApplicationHarness {
public:
    /// Creates the application with an isolated theme and optional browser callback adapter.
    explicit ClientApplicationHarness(bool oauth = false, const QString& provider = QStringLiteral("fake"))
        : backend(oauth, provider)
        , controller(&socket, [this](const QUrl& url) { return backend.open_browser(url); })
    {
        qRegisterMetaType<State>("tcp_chat::client::AuthenticationController::State");
    }

    /// Starts the server and application, then waits for the sign-in forms.
    bool start()
    {
        if (!backend.start()) {
            return false;
        }
        window.show();
        application = std::make_unique<ClientApplication>(window, controller, backend.client_options());
        application->start();
        return wait_ready();
    }

    /// Waits for a cancelled or replaced connection to return to the forms.
    bool wait_ready()
    {
        QSignalSpy states(&controller, &AuthenticationController::state_changed);
        return (controller.state() == State::Ready && window.current_page() == MainWindow::Page::Welcome)
            || (states.wait(5000) && controller.state() == State::Ready && window.current_page() == MainWindow::Page::Welcome);
    }

    QTemporaryDir settings_directory;
    ThemeManager theme { *qApp, nullptr, std::make_unique<QSettings>(settings_directory.filePath(QStringLiteral("window.ini")), QSettings::IniFormat) };
    MainWindow window { theme };
    AuthenticationTestHarness backend;
    TlsClient socket;
    AuthenticationController controller;
    std::unique_ptr<ClientApplication> application;
};

} // namespace

/// Verifies real user input through local and browser authentication flows.
class ClientApplicationTest final : public QObject {
    Q_OBJECT

private slots:
    /// Signs up, logs out, handles a wrong password, and logs in through the actual widgets.
    void local_account_flow()
    {
        ClientApplicationHarness harness;
        QVERIFY(harness.start());
        auto* tabs = harness.window.findChild<QTabWidget*>(QStringLiteral("authenticationModes"));
        QVERIFY(tabs);
        tabs->setCurrentIndex(1);
        harness.window.findChild<QLineEdit*>(QStringLiteral("signupUsername"))->setText(QStringLiteral("Alice"));
        harness.window.findChild<QLineEdit*>(QStringLiteral("signupDisplayName"))->setText(QStringLiteral("Alice Example"));
        harness.window.findChild<QLineEdit*>(QStringLiteral("signupPassword"))->setText(QStringLiteral("correct horse battery staple"));
        harness.window.findChild<QLineEdit*>(QStringLiteral("signupConfirmation"))->setText(QStringLiteral("correct horse battery staple"));
        harness.window.findChild<QPushButton*>(QStringLiteral("signupSubmit"))->click();

        QTRY_COMPARE(harness.controller.state(), State::Authenticated);
        QTRY_COMPARE(harness.window.current_page(), MainWindow::Page::Chat);
        auto* identity = harness.window.findChild<QLabel*>(QStringLiteral("chatIdentity"));
        QVERIFY(identity);
        QVERIFY(identity->text().contains(QStringLiteral("Alice Example")));
        QVERIFY(harness.window.findChild<QLineEdit*>(QStringLiteral("signupPassword"))->text().isEmpty());

        harness.controller.log_out();
        QTRY_COMPARE(harness.controller.state(), State::Ready);
        QTRY_COMPARE(harness.window.current_page(), MainWindow::Page::Welcome);
        harness.window.findChild<QLineEdit*>(QStringLiteral("loginUsername"))->setText(QStringLiteral("Alice"));
        harness.window.findChild<QLineEdit*>(QStringLiteral("loginPassword"))->setText(QStringLiteral("wrong-password"));
        harness.window.findChild<QPushButton*>(QStringLiteral("loginSubmit"))->click();
        auto* error = harness.window.findChild<QLabel*>(QStringLiteral("authenticationError"));
        QVERIFY(error);
        QTRY_COMPARE(error->text(), QStringLiteral("The username or password is incorrect"));
        QVERIFY(harness.window.findChild<QLineEdit*>(QStringLiteral("loginPassword"))->text().isEmpty());

        harness.window.findChild<QLineEdit*>(QStringLiteral("loginPassword"))->setText(QStringLiteral("correct horse battery staple"));
        harness.window.findChild<QPushButton*>(QStringLiteral("loginSubmit"))->click();
        QTRY_COMPARE(harness.controller.state(), State::Authenticated);
        QTRY_COMPARE(harness.window.current_page(), MainWindow::Page::Chat);
    }

    /// Connects the Google button to a real browser callback and fake-provider identity exchange.
    void google_browser_flow()
    {
        ClientApplicationHarness harness(true, QStringLiteral("google"));
        QVERIFY(harness.start());
        harness.window.findChild<QPushButton*>(QStringLiteral("googleSignIn"))->click();

        QTRY_VERIFY(harness.backend.browser.response.startsWith("HTTP/1.1 200"));
        QTRY_COMPARE(harness.controller.state(), State::Authenticated);
        QTRY_COMPARE(harness.window.current_page(), MainWindow::Page::Chat);
        QVERIFY(harness.controller.user().has_value());
        QVERIFY(harness.controller.user()->username.startsWith(QStringLiteral("user_")));
    }

    /// Cancels a browser flow from the form and returns to a fresh server connection.
    void browser_cancellation()
    {
        ClientApplicationHarness harness(true, QStringLiteral("google"));
        QVERIFY(harness.backend.start());
        TlsClient socket;
        AuthenticationController controller(&socket, [](const QUrl&) { return true; });
        ClientApplication application(harness.window, controller, harness.backend.client_options());
        application.start();
        QTRY_COMPARE(controller.state(), State::Ready);
        harness.window.findChild<QPushButton*>(QStringLiteral("googleSignIn"))->click();
        QTRY_COMPARE(controller.state(), State::BrowserPending);

        harness.window.findChild<QPushButton*>(QStringLiteral("cancelAuthentication"))->click();

        QTRY_COMPARE(controller.state(), State::Ready);
        QTRY_COMPARE(harness.window.current_page(), MainWindow::Page::Welcome);
        QVERIFY(!controller.user().has_value());
        QVERIFY(harness.window.findChild<QPushButton*>(QStringLiteral("googleSignIn"))->isEnabled());
    }
};

QTEST_MAIN(ClientApplicationTest)
#include "test_client_application.moc"

#include "authentication_test_harness.h"
#include "client/authentication_controller.h"

#include <QSignalSpy>
#include <QTest>

using tcp_chat::client::AuthenticationController;
using tcp_chat::client::TlsClient;
using State = tcp_chat::client::AuthenticationController::State;

Q_DECLARE_METATYPE(State)

namespace {

/// Connects a controller and waits until the server can accept authentication.
bool connect_controller(AuthenticationTestHarness& harness, AuthenticationController& controller)
{
    qRegisterMetaType<State>("tcp_chat::client::AuthenticationController::State");
    QSignalSpy states(&controller, &AuthenticationController::state_changed);
    controller.connect_to_server(harness.client_options());
    return controller.state() == State::Ready || (states.wait(5000) && controller.state() == State::Ready);
}

} // namespace

/// Verifies local and browser authentication against real TLS and SQLite services.
class AuthenticationControllerTest final : public QObject {
    Q_OBJECT

private slots:
    /// Covers local signup, logout, generic login failure, and normalized successful login.
    void local_account_lifecycle()
    {
        AuthenticationTestHarness harness;
        QVERIFY(harness.start());
        TlsClient socket;
        AuthenticationController controller(&socket);
        QSignalSpy authenticated(&controller, &AuthenticationController::authenticated);
        QSignalSpy failed(&controller, &AuthenticationController::authentication_failed);
        QSignalSpy logged_out(&controller, &AuthenticationController::logged_out);
        QVERIFY(connect_controller(harness, controller));

        controller.sign_up(QStringLiteral("Alice"), QStringLiteral("correct horse battery staple"), QStringLiteral("Alice Example"));
        QTRY_COMPARE(controller.state(), State::Authenticated);
        QCOMPARE(authenticated.count(), 1);
        QVERIFY(controller.user().has_value());
        QCOMPARE(controller.user()->username, QStringLiteral("Alice"));
        QCOMPARE(controller.user()->display_name, QStringLiteral("Alice Example"));
        QCOMPARE(controller.session_expires_at(), harness.current_time + 10000);

        controller.log_out();
        QTRY_COMPARE(controller.state(), State::Ready);
        QCOMPARE(logged_out.count(), 1);
        QVERIFY(!controller.user().has_value());
        QCOMPARE(controller.session_expires_at(), 0);

        controller.log_in(QStringLiteral("Alice"), QStringLiteral("incorrect-password"));
        QTRY_COMPARE(failed.count(), 1);
        QCOMPARE(failed.at(0).at(0).toString(), QStringLiteral("The username or password is incorrect"));
        QCOMPARE(controller.state(), State::Ready);
        QVERIFY(!controller.user().has_value());

        controller.log_in(QStringLiteral("  ALICE  "), QStringLiteral("correct horse battery staple"));
        QTRY_COMPARE(authenticated.count(), 2);
        QCOMPARE(controller.state(), State::Authenticated);
        QVERIFY(controller.user().has_value());
    }

    /// Rejects malformed credentials before starting a network operation.
    void validates_local_fields()
    {
        AuthenticationTestHarness harness;
        QVERIFY(harness.start());
        TlsClient socket;
        AuthenticationController controller(&socket);
        QSignalSpy failed(&controller, &AuthenticationController::authentication_failed);

        controller.log_in(QStringLiteral("Alice"), QStringLiteral("correct horse battery staple"));
        QCOMPARE(failed.count(), 1);
        controller.sign_up(QStringLiteral("Alice"), QStringLiteral("short"));
        QCOMPARE(failed.count(), 2);

        QVERIFY(connect_controller(harness, controller));
        controller.log_in(QStringLiteral("Alice"), QStringLiteral("short"));
        QCOMPARE(failed.count(), 3);
        QCOMPARE(controller.state(), State::Ready);
        controller.sign_up(QStringLiteral("not valid!"), QStringLiteral("correct horse battery staple"));
        QCOMPARE(failed.count(), 4);
        QCOMPARE(controller.state(), State::Ready);
    }

    /// Completes a fake-provider browser flow through the real OAuth callback server.
    void completes_browser_sign_in()
    {
        AuthenticationTestHarness harness(true);
        QVERIFY(harness.start());
        TlsClient socket;
        AuthenticationController controller(&socket, [&harness](const QUrl& url) { return harness.open_browser(url); });
        QSignalSpy authenticated(&controller, &AuthenticationController::authenticated);
        QSignalSpy failed(&controller, &AuthenticationController::authentication_failed);
        QVERIFY(connect_controller(harness, controller));

        controller.sign_in_with_provider(QStringLiteral("fake"));

        QTRY_VERIFY(harness.browser.response.startsWith("HTTP/1.1 200"));
        QTRY_COMPARE(authenticated.count(), 1);
        QCOMPARE(controller.state(), State::Authenticated);
        QVERIFY(controller.user().has_value());
        QVERIFY(controller.user()->username.startsWith(QStringLiteral("user_")));
        QCOMPARE(failed.count(), 0);
    }

    /// Cancels browser polling and reconnects before accepting local credentials.
    void cancels_browser_sign_in()
    {
        AuthenticationTestHarness harness(true);
        QVERIFY(harness.start());
        TlsClient socket;
        bool browser_opened = false;
        AuthenticationController controller(&socket, [&browser_opened](const QUrl&) {
            browser_opened = true;
            return true;
        });
        QVERIFY(connect_controller(harness, controller));
        controller.sign_in_with_provider(QStringLiteral("fake"));
        QTRY_COMPARE(controller.state(), State::BrowserPending);
        QVERIFY(browser_opened);

        controller.cancel();

        QTRY_COMPARE(controller.state(), State::Ready);
        QVERIFY(!controller.user().has_value());
        controller.sign_up(QStringLiteral("after_cancel"), QStringLiteral("correct horse battery staple"));
        QTRY_COMPARE(controller.state(), State::Authenticated);
    }

    /// Reconnects after provider denial without reporting a second transport error.
    void rejected_browser_sign_in_reconnects()
    {
        AuthenticationTestHarness harness(true);
        QVERIFY(harness.start());
        harness.provider->reject_exchange = true;
        TlsClient socket;
        AuthenticationController controller(&socket, [&harness](const QUrl& url) { return harness.open_browser(url); });
        QSignalSpy authentication_failed(&controller, &AuthenticationController::authentication_failed);
        QSignalSpy connection_failed(&controller, &AuthenticationController::connection_failed);
        QVERIFY(connect_controller(harness, controller));
        controller.sign_in_with_provider(QStringLiteral("fake"));

        QTRY_COMPARE(authentication_failed.count(), 1);
        QTRY_COMPARE(controller.state(), State::Ready);
        QCOMPARE(connection_failed.count(), 0);
        QVERIFY(!controller.user().has_value());
    }

    /// Clears the in-memory identity when the authenticated connection ends.
    void disconnect_clears_session()
    {
        AuthenticationTestHarness harness;
        QVERIFY(harness.start());
        TlsClient socket;
        AuthenticationController controller(&socket);
        QSignalSpy connection_failed(&controller, &AuthenticationController::connection_failed);
        QVERIFY(connect_controller(harness, controller));
        controller.sign_up(QStringLiteral("Alice"), QStringLiteral("correct horse battery staple"));
        QTRY_COMPARE(controller.state(), State::Authenticated);
        QVERIFY(!harness.server_connected.isEmpty());
        const quint64 id = harness.server_connected.at(0).at(0).toULongLong();

        harness.server.disconnect_client(id);

        QTRY_COMPARE(connection_failed.count(), 1);
        QCOMPARE(controller.state(), State::Disconnected);
        QVERIFY(!controller.user().has_value());
        QCOMPARE(controller.session_expires_at(), 0);
    }
};

QTEST_GUILESS_MAIN(AuthenticationControllerTest)
#include "test_authentication_controller.moc"

#include "client/authentication_page.h"

#include <QCheckBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalSpy>
#include <QTabWidget>
#include <QTest>

using tcp_chat::client::AuthenticationPage;

namespace {

/// Returns a required named child widget.
template <typename T>
T* field(AuthenticationPage& page, const QString& name)
{
    auto* widget = page.findChild<T*>(name);
    if (widget == nullptr) {
        qFatal("Missing authentication widget: %s", qPrintable(name));
    }
    return widget;
}

} // namespace

/// Verifies local validation, credential clearing, provider actions, and keyboard controls.
class AuthenticationPageTest final : public QObject {
    Q_OBJECT

private slots:
    /// Starts with separate sign-in/signup modes and masked password fields.
    void defaults_to_sign_in()
    {
        AuthenticationPage page;
        auto* tabs = field<QTabWidget>(page, QStringLiteral("authenticationModes"));
        QCOMPARE(tabs->currentIndex(), 0);
        QVERIFY(!field<QPushButton>(page, QStringLiteral("loginSubmit"))->isHidden());
        QVERIFY(field<QPushButton>(page, QStringLiteral("signupSubmit"))->isHidden());
        QCOMPARE(field<QLineEdit>(page, QStringLiteral("loginPassword"))->echoMode(), QLineEdit::Password);
        QCOMPARE(field<QLineEdit>(page, QStringLiteral("signupPassword"))->echoMode(), QLineEdit::Password);
        QVERIFY(field<QPushButton>(page, QStringLiteral("cancelAuthentication"))->isHidden());

        tabs->setCurrentIndex(1);
        QVERIFY(field<QPushButton>(page, QStringLiteral("loginSubmit"))->isHidden());
        QVERIFY(!field<QPushButton>(page, QStringLiteral("signupSubmit"))->isHidden());
    }

    /// Rejects invalid login fields without emitting a network request.
    void validates_login()
    {
        AuthenticationPage page;
        QSignalSpy login(&page, &AuthenticationPage::log_in_requested);
        field<QLineEdit>(page, QStringLiteral("loginUsername"))->setText(QStringLiteral("x"));
        field<QLineEdit>(page, QStringLiteral("loginPassword"))->setText(QStringLiteral("short"));
        field<QPushButton>(page, QStringLiteral("loginSubmit"))->click();
        QCOMPARE(login.count(), 0);
        QVERIFY(!field<QLabel>(page, QStringLiteral("authenticationError"))->text().isEmpty());

        field<QLineEdit>(page, QStringLiteral("loginUsername"))->setText(QStringLiteral(" Alice "));
        field<QLineEdit>(page, QStringLiteral("loginPassword"))->setText(QStringLiteral("correct horse battery staple"));
        field<QLineEdit>(page, QStringLiteral("loginPassword"))->setFocus();
        QTest::keyClick(field<QLineEdit>(page, QStringLiteral("loginPassword")), Qt::Key_Return);
        QCOMPARE(login.count(), 1);
        QCOMPARE(login.at(0).at(0).toString(), QStringLiteral("Alice"));
        QCOMPARE(login.at(0).at(1).toString(), QStringLiteral("correct horse battery staple"));
        QVERIFY(page.is_busy());
        QVERIFY(field<QLineEdit>(page, QStringLiteral("loginPassword"))->text().isEmpty());
        QVERIFY(!field<QLineEdit>(page, QStringLiteral("loginUsername"))->isEnabled());
    }

    /// Requires matching signup passwords and emits trimmed account fields.
    void validates_signup()
    {
        AuthenticationPage page;
        field<QTabWidget>(page, QStringLiteral("authenticationModes"))->setCurrentIndex(1);
        QSignalSpy signup(&page, &AuthenticationPage::sign_up_requested);
        field<QLineEdit>(page, QStringLiteral("signupUsername"))->setText(QStringLiteral(" Alice "));
        field<QLineEdit>(page, QStringLiteral("signupDisplayName"))->setText(QStringLiteral(" Alice Example "));
        field<QLineEdit>(page, QStringLiteral("signupPassword"))->setText(QStringLiteral("correct horse battery staple"));
        field<QLineEdit>(page, QStringLiteral("signupConfirmation"))->setText(QStringLiteral("different password"));
        field<QPushButton>(page, QStringLiteral("signupSubmit"))->click();
        QCOMPARE(signup.count(), 0);
        QCOMPARE(field<QLabel>(page, QStringLiteral("authenticationError"))->text(), QStringLiteral("The passwords do not match."));

        field<QLineEdit>(page, QStringLiteral("signupConfirmation"))->setText(QStringLiteral("correct horse battery staple"));
        field<QLineEdit>(page, QStringLiteral("signupConfirmation"))->setFocus();
        QTest::keyClick(field<QLineEdit>(page, QStringLiteral("signupConfirmation")), Qt::Key_Return);
        QCOMPARE(signup.count(), 1);
        QCOMPARE(signup.at(0).at(0).toString(), QStringLiteral("Alice"));
        QCOMPARE(signup.at(0).at(1).toString(), QStringLiteral("correct horse battery staple"));
        QCOMPARE(signup.at(0).at(2).toString(), QStringLiteral("Alice Example"));
        QVERIFY(field<QLineEdit>(page, QStringLiteral("signupPassword"))->text().isEmpty());
        QVERIFY(field<QLineEdit>(page, QStringLiteral("signupConfirmation"))->text().isEmpty());
    }

    /// Emits canonical provider identifiers once and allows explicit cancellation.
    void provider_actions_and_cancellation()
    {
        AuthenticationPage page;
        QSignalSpy oauth(&page, &AuthenticationPage::oauth_requested);
        QSignalSpy cancelled(&page, &AuthenticationPage::cancel_requested);
        field<QPushButton>(page, QStringLiteral("googleSignIn"))->click();
        field<QPushButton>(page, QStringLiteral("googleSignIn"))->click();
        QCOMPARE(oauth.count(), 1);
        QCOMPARE(oauth.at(0).at(0).toString(), QStringLiteral("google"));
        field<QPushButton>(page, QStringLiteral("cancelAuthentication"))->click();
        QCOMPARE(cancelled.count(), 1);

        page.set_busy(false);
        field<QPushButton>(page, QStringLiteral("githubSignIn"))->click();
        QCOMPARE(oauth.count(), 2);
        QCOMPARE(oauth.at(1).at(0).toString(), QStringLiteral("github"));
    }

    /// Clears passwords on server errors and supports the password visibility toggle.
    void errors_reset_and_password_visibility()
    {
        AuthenticationPage page;
        auto* login_password  = field<QLineEdit>(page, QStringLiteral("loginPassword"));
        auto* signup_password = field<QLineEdit>(page, QStringLiteral("signupPassword"));
        auto* confirmation    = field<QLineEdit>(page, QStringLiteral("signupConfirmation"));
        login_password->setText(QStringLiteral("secret-password"));
        signup_password->setText(QStringLiteral("secret-password"));
        confirmation->setText(QStringLiteral("secret-password"));
        field<QCheckBox>(page, QStringLiteral("showPasswords"))->setChecked(true);
        QCOMPARE(login_password->echoMode(), QLineEdit::Normal);
        QCOMPARE(signup_password->echoMode(), QLineEdit::Normal);
        QCOMPARE(confirmation->echoMode(), QLineEdit::Normal);

        page.show_error(QStringLiteral("<b>Sign-in failed</b>"));
        QVERIFY(!page.is_busy());
        QVERIFY(login_password->text().isEmpty());
        QVERIFY(signup_password->text().isEmpty());
        QVERIFY(confirmation->text().isEmpty());
        auto* error = field<QLabel>(page, QStringLiteral("authenticationError"));
        QCOMPARE(error->textFormat(), Qt::PlainText);
        QCOMPARE(error->text(), QStringLiteral("<b>Sign-in failed</b>"));

        page.reset();
        QCOMPARE(field<QTabWidget>(page, QStringLiteral("authenticationModes"))->currentIndex(), 0);
        QVERIFY(!field<QCheckBox>(page, QStringLiteral("showPasswords"))->isChecked());
        QCOMPARE(login_password->echoMode(), QLineEdit::Password);
        QVERIFY(error->isHidden());
    }
};

QTEST_MAIN(AuthenticationPageTest)
#include "test_authentication_page.moc"

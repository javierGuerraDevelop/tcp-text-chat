#include "client/main_window.h"
#include "client/theme_manager.h"

#include <QComboBox>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QSettings>
#include <QSignalSpy>
#include <QStackedWidget>
#include <QTabWidget>
#include <QTemporaryDir>
#include <QTest>

#include <memory>

using tcp_chat::client::MainWindow;
using tcp_chat::client::ThemeManager;

/// Verifies application page transitions and keyboard-accessible controls.
class MainWindowTest final : public QObject {
    Q_OBJECT

private slots:
    /// Shows the welcome page and a theme selector that applies the user's choice.
    void welcome_and_theme_selection()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        auto settings = std::make_unique<QSettings>(directory.filePath(QStringLiteral("preferences.ini")), QSettings::IniFormat);
        ThemeManager manager(*qApp, nullptr, std::move(settings));
        MainWindow window(manager);

        QCOMPARE(window.current_page(), MainWindow::Page::Welcome);
        auto* selector = window.findChild<QComboBox*>(QStringLiteral("themeSelector"));
        QVERIFY(selector);
        QCOMPARE(selector->accessibleName(), QStringLiteral("Theme"));
        QCOMPARE(selector->currentData().toInt(), static_cast<int>(ThemeManager::Preference::Auto));

        selector->setCurrentIndex(selector->findData(static_cast<int>(ThemeManager::Preference::Dark)));
        QCOMPARE(manager.preference(), ThemeManager::Preference::Dark);
        QCOMPARE(qApp->palette().color(QPalette::Window), QColor(QStringLiteral("#121721")));
    }

    /// Switches between the chat empty state and the connecting loading state.
    void navigation_states()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        ThemeManager manager(*qApp, nullptr, std::make_unique<QSettings>(directory.filePath(QStringLiteral("preferences.ini")), QSettings::IniFormat));
        MainWindow window(manager);
        auto* pages = window.findChild<QStackedWidget*>();
        QVERIFY(pages);

        window.show_page(MainWindow::Page::Connecting);
        QCOMPARE(pages->currentIndex(), static_cast<int>(MainWindow::Page::Connecting));
        auto* progress = window.findChild<QProgressBar*>(QStringLiteral("connectionProgress"));
        QVERIFY(progress);
        QVERIFY(!progress->isHidden());

        window.show_page(MainWindow::Page::Chat);
        QCOMPARE(pages->currentIndex(), static_cast<int>(MainWindow::Page::Chat));
        auto* empty = window.findChild<QLabel*>(QStringLiteral("emptyChatLabel"));
        QVERIFY(empty);
        QVERIFY(!empty->isHidden());
        QVERIFY(progress->isVisibleTo(pages->widget(static_cast<int>(MainWindow::Page::Connecting))));
        QVERIFY(!progress->isVisibleTo(pages->currentWidget()));
    }

    /// Cancels connection with the keyboard and returns to the welcome page.
    void cancel_is_keyboard_accessible()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        ThemeManager manager(*qApp, nullptr, std::make_unique<QSettings>(directory.filePath(QStringLiteral("preferences.ini")), QSettings::IniFormat));
        MainWindow window(manager);
        window.show_page(MainWindow::Page::Connecting);
        QSignalSpy cancelled(&window, &MainWindow::cancel_requested);
        auto* cancel = window.findChild<QPushButton*>(QStringLiteral("cancelConnection"));
        QVERIFY(cancel);
        QCOMPARE(cancel->focusPolicy(), Qt::StrongFocus);

        cancel->setFocus(Qt::OtherFocusReason);
        QTest::keyClick(cancel, Qt::Key_Space);

        QCOMPARE(cancelled.count(), 1);
        QCOMPARE(window.current_page(), MainWindow::Page::Welcome);
    }

    /// Presents errors as plain text and supports keyboard dismissal.
    void error_is_plain_text_and_dismissible()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        ThemeManager manager(*qApp, nullptr, std::make_unique<QSettings>(directory.filePath(QStringLiteral("preferences.ini")), QSettings::IniFormat));
        MainWindow window(manager);
        window.show_error(QStringLiteral("  <b>Connection failed</b>  "));
        auto* message = window.findChild<QLabel*>(QStringLiteral("errorMessage"));
        QVERIFY(message);
        QCOMPARE(message->text(), QStringLiteral("<b>Connection failed</b>"));
        QCOMPARE(message->textFormat(), Qt::PlainText);
        QCOMPARE(window.current_page(), MainWindow::Page::Error);

        auto* dismiss = window.findChild<QPushButton*>(QStringLiteral("dismissError"));
        QVERIFY(dismiss);
        QSignalSpy retry(&window, &MainWindow::retry_requested);
        dismiss->setFocus(Qt::OtherFocusReason);
        QTest::keyClick(dismiss, Qt::Key_Return);
        QCOMPARE(window.current_page(), MainWindow::Page::Connecting);
        QCOMPARE(retry.count(), 1);

        window.show_error(QString());
        QVERIFY(!message->text().isEmpty());
    }

    /// Renders both themes and optionally saves the images for visual inspection.
    void renders_light_and_dark_themes()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        ThemeManager manager(*qApp, nullptr, std::make_unique<QSettings>(directory.filePath(QStringLiteral("preferences.ini")), QSettings::IniFormat));
        MainWindow window(manager);
        window.resize(960, 640);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));

        const QImage light = window.grab().toImage();
        QCOMPARE(light.size(), window.size());
        QVERIFY(light.pixelColor(10, 10) != light.pixelColor(light.width() - 10, light.height() - 10));

        auto* selector = window.findChild<QComboBox*>(QStringLiteral("themeSelector"));
        QVERIFY(selector);
        selector->setCurrentIndex(selector->findData(static_cast<int>(ThemeManager::Preference::Dark)));
        const QImage dark = window.grab().toImage();
        QCOMPARE(dark.size(), window.size());
        QVERIFY(dark.pixelColor(10, 10) != light.pixelColor(10, 10));

        const QString capture_directory = qEnvironmentVariable("TCP_CHAT_UI_CAPTURE_DIR");
        if (!capture_directory.isEmpty()) {
            QVERIFY(light.save(capture_directory + QStringLiteral("/welcome-light.png")));
            QVERIFY(dark.save(capture_directory + QStringLiteral("/welcome-dark.png")));
        }

        auto* modes = window.findChild<QTabWidget*>(QStringLiteral("authenticationModes"));
        QVERIFY(modes);
        modes->setCurrentIndex(1);
        QCoreApplication::processEvents();
        const QImage signup = window.grab().toImage();
        QCOMPARE(signup.size(), window.size());
        QVERIFY(window.findChild<QWidget*>(QStringLiteral("signupConfirmation"))->isVisible());
        if (!capture_directory.isEmpty()) {
            QVERIFY(signup.save(capture_directory + QStringLiteral("/signup-dark.png")));
        }

        auto* pages = window.findChild<QStackedWidget*>();
        QVERIFY(pages);
        for (int index = 0; index < pages->count(); ++index) {
            window.show_page(static_cast<MainWindow::Page>(index));
            QCoreApplication::processEvents();
            auto* title = pages->currentWidget()->findChild<QLabel*>(QStringLiteral("pageTitle"));
            QVERIFY(title);
            const int required_height = title->heightForWidth(title->width());
            QVERIFY(required_height >= 0);
            QVERIFY2(title->height() >= required_height, qPrintable(title->text()));
        }
    }
};

QTEST_MAIN(MainWindowTest)
#include "test_main_window.moc"

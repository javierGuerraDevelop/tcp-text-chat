#include "client/theme_manager.h"

#include <QApplication>
#include <QSettings>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

#include <memory>

using tcp_chat::client::ColorSchemeSource;
using tcp_chat::client::ThemeManager;

namespace {

/// Supplies deterministic system appearance changes without platform settings.
class TestColorSchemeSource final : public ColorSchemeSource {
public:
    /// Returns the last supplied system appearance.
    Qt::ColorScheme color_scheme() const override
    {
        return color_scheme_;
    }

    /// Publishes a new system appearance.
    void set_color_scheme(Qt::ColorScheme color_scheme)
    {
        color_scheme_ = color_scheme;
        emit color_scheme_changed(color_scheme);
    }

private:
    Qt::ColorScheme color_scheme_ = Qt::ColorScheme::Unknown;
};

/// Creates an isolated settings file and its deterministic system appearance source.
std::unique_ptr<QSettings> settings_for(const QTemporaryDir& directory)
{
    return std::make_unique<QSettings>(directory.filePath(QStringLiteral("preferences.ini")), QSettings::IniFormat);
}

} // namespace

/// Verifies theme resolution, persistence, and application-wide appearance updates.
class ThemeManagerTest final : public QObject {
    Q_OBJECT

private slots:
    /// Uses light colors when the platform does not report a preference.
    void unknown_system_scheme_defaults_to_light()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        auto source = std::make_unique<TestColorSchemeSource>();
        ThemeManager manager(*qApp, std::move(source), settings_for(directory));

        QCOMPARE(manager.preference(), ThemeManager::Preference::Auto);
        QCOMPARE(manager.color_scheme(), Qt::ColorScheme::Light);
        QCOMPARE(qApp->palette().color(QPalette::Window), QColor(QStringLiteral("#f4f6fb")));
    }

    /// Applies a complete dark palette and resolves every semantic stylesheet token.
    void dark_theme_updates_application()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        auto source = std::make_unique<TestColorSchemeSource>();
        ThemeManager manager(*qApp, std::move(source), settings_for(directory));
        QSignalSpy changed(&manager, &ThemeManager::appearance_changed);

        manager.set_preference(ThemeManager::Preference::Dark);

        QCOMPARE(changed.count(), 1);
        QCOMPARE(manager.color_scheme(), Qt::ColorScheme::Dark);
        QCOMPARE(qApp->palette().color(QPalette::Window), QColor(QStringLiteral("#121721")));
        QCOMPARE(qApp->palette().color(QPalette::Text), QColor(QStringLiteral("#f2f5fa")));
        QCOMPARE(qApp->palette().color(QPalette::Disabled, QPalette::Text), QColor(QStringLiteral("#a6b0c2")));
        QVERIFY(qApp->styleSheet().contains(QStringLiteral("background-color: #121721")));
        QVERIFY(!qApp->styleSheet().contains(QLatin1Char('%')));
    }

    /// Follows injected system changes only while Auto is selected.
    void auto_theme_follows_system_changes()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        auto source  = std::make_unique<TestColorSchemeSource>();
        auto* system = source.get();
        system->set_color_scheme(Qt::ColorScheme::Light);
        ThemeManager manager(*qApp, std::move(source), settings_for(directory));
        QSignalSpy changed(&manager, &ThemeManager::appearance_changed);

        system->set_color_scheme(Qt::ColorScheme::Dark);
        QCOMPARE(manager.color_scheme(), Qt::ColorScheme::Dark);
        QCOMPARE(changed.count(), 1);

        manager.set_preference(ThemeManager::Preference::Light);
        system->set_color_scheme(Qt::ColorScheme::Dark);
        QCOMPARE(manager.color_scheme(), Qt::ColorScheme::Light);
        QCOMPARE(changed.count(), 2);

        manager.set_preference(ThemeManager::Preference::Auto);
        QCOMPARE(manager.color_scheme(), Qt::ColorScheme::Dark);
        QCOMPARE(changed.count(), 3);
    }

    /// Persists a stable preference string and restores it with a new settings object.
    void preference_survives_recreation()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        {
            ThemeManager manager(*qApp, std::make_unique<TestColorSchemeSource>(), settings_for(directory));
            manager.set_preference(ThemeManager::Preference::Dark);
        }

        QSettings saved(directory.filePath(QStringLiteral("preferences.ini")), QSettings::IniFormat);
        QCOMPARE(saved.value(QStringLiteral("appearance/theme")).toString(), QStringLiteral("dark"));
        ThemeManager restored(*qApp, std::make_unique<TestColorSchemeSource>(), settings_for(directory));
        QCOMPARE(restored.preference(), ThemeManager::Preference::Dark);
        QCOMPARE(restored.color_scheme(), Qt::ColorScheme::Dark);
    }

    /// Treats an invalid stored value as Auto instead of selecting an arbitrary theme.
    void invalid_preference_defaults_to_auto()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        {
            QSettings saved(directory.filePath(QStringLiteral("preferences.ini")), QSettings::IniFormat);
            saved.setValue(QStringLiteral("appearance/theme"), QStringLiteral("high-contrast-neon"));
        }
        auto source = std::make_unique<TestColorSchemeSource>();
        source->set_color_scheme(Qt::ColorScheme::Dark);
        ThemeManager manager(*qApp, std::move(source), settings_for(directory));

        QCOMPARE(manager.preference(), ThemeManager::Preference::Auto);
        QCOMPARE(manager.color_scheme(), Qt::ColorScheme::Dark);
    }
};

QTEST_MAIN(ThemeManagerTest)
#include "test_theme_manager.moc"

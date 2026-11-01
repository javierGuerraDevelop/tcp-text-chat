#include "theme_manager.h"

#include <QApplication>
#include <QFile>
#include <QGuiApplication>
#include <QLoggingCategory>
#include <QSettings>
#include <QStyleHints>

#include <array>
#include <utility>

namespace tcp_chat::client {
namespace {

    Q_LOGGING_CATEGORY(theme_log, "tcp_chat.ui.theme")

    /// Contains the semantic colors shared by the palette and stylesheet.
    struct ThemeColors {
        QColor window;
        QColor surface;
        QColor secondary_surface;
        QColor border;
        QColor text;
        QColor muted_text;
        QColor accent;
        QColor accent_hover;
        QColor on_accent;
        QColor error;
        QColor hover;
    };

    /// Returns the complete color set for a resolved appearance.
    ThemeColors colors_for(Qt::ColorScheme scheme)
    {
        if (scheme == Qt::ColorScheme::Dark) {
            return {
                QColor(QStringLiteral("#121721")),
                QColor(QStringLiteral("#1b2230")),
                QColor(QStringLiteral("#242e40")),
                QColor(QStringLiteral("#344158")),
                QColor(QStringLiteral("#f2f5fa")),
                QColor(QStringLiteral("#a6b0c2")),
                QColor(QStringLiteral("#a5b4fc")),
                QColor(QStringLiteral("#c7d2fe")),
                QColor(QStringLiteral("#172033")),
                QColor(QStringLiteral("#fda29b")),
                QColor(QStringLiteral("#2c3850")),
            };
        }

        return {
            QColor(QStringLiteral("#f4f6fb")),
            QColor(QStringLiteral("#ffffff")),
            QColor(QStringLiteral("#eef1f7")),
            QColor(QStringLiteral("#d9dfeb")),
            QColor(QStringLiteral("#172033")),
            QColor(QStringLiteral("#5b6577")),
            QColor(QStringLiteral("#4f46e5")),
            QColor(QStringLiteral("#4338ca")),
            QColor(QStringLiteral("#ffffff")),
            QColor(QStringLiteral("#b42318")),
            QColor(QStringLiteral("#e4e9f2")),
        };
    }

    /// Creates a palette with readable enabled, disabled, and selection states.
    QPalette palette_for(const ThemeColors& colors)
    {
        QPalette palette;
        palette.setColor(QPalette::Window, colors.window);
        palette.setColor(QPalette::WindowText, colors.text);
        palette.setColor(QPalette::Base, colors.surface);
        palette.setColor(QPalette::AlternateBase, colors.secondary_surface);
        palette.setColor(QPalette::Text, colors.text);
        palette.setColor(QPalette::Button, colors.secondary_surface);
        palette.setColor(QPalette::ButtonText, colors.text);
        palette.setColor(QPalette::BrightText, colors.error);
        palette.setColor(QPalette::Link, colors.accent);
        palette.setColor(QPalette::Highlight, colors.accent);
        palette.setColor(QPalette::HighlightedText, colors.on_accent);
        palette.setColor(QPalette::PlaceholderText, colors.muted_text);
        palette.setColor(QPalette::ToolTipBase, colors.surface);
        palette.setColor(QPalette::ToolTipText, colors.text);
        palette.setColor(QPalette::Disabled, QPalette::WindowText, colors.muted_text);
        palette.setColor(QPalette::Disabled, QPalette::Text, colors.muted_text);
        palette.setColor(QPalette::Disabled, QPalette::ButtonText, colors.muted_text);
        palette.setColor(QPalette::Disabled, QPalette::HighlightedText, colors.muted_text);
        return palette;
    }

    /// Substitutes semantic tokens into the shared widget stylesheet.
    QString stylesheet_for(const ThemeColors& colors)
    {
        QFile file(QStringLiteral(":/tcp_chat/theme.qss"));
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            qCWarning(theme_log) << "Unable to load the application stylesheet";
            return { };
        }

        QString style           = QString::fromUtf8(file.readAll());
        const auto replacements = std::array {
            std::pair { QStringLiteral("%WINDOW%"), colors.window.name() },
            std::pair { QStringLiteral("%SURFACE%"), colors.surface.name() },
            std::pair { QStringLiteral("%SECONDARY_SURFACE%"), colors.secondary_surface.name() },
            std::pair { QStringLiteral("%BORDER%"), colors.border.name() },
            std::pair { QStringLiteral("%TEXT%"), colors.text.name() },
            std::pair { QStringLiteral("%MUTED_TEXT%"), colors.muted_text.name() },
            std::pair { QStringLiteral("%ACCENT%"), colors.accent.name() },
            std::pair { QStringLiteral("%ACCENT_HOVER%"), colors.accent_hover.name() },
            std::pair { QStringLiteral("%ON_ACCENT%"), colors.on_accent.name() },
            std::pair { QStringLiteral("%ERROR%"), colors.error.name() },
            std::pair { QStringLiteral("%HOVER%"), colors.hover.name() },
        };
        for (const auto& [token, color] : replacements)
            style.replace(token, color);
        return style;
    }

    /// Converts a preference into its stable settings representation.
    QString preference_name(ThemeManager::Preference preference)
    {
        switch (preference) {
        case ThemeManager::Preference::Auto:
            return QStringLiteral("auto");
        case ThemeManager::Preference::Light:
            return QStringLiteral("light");
        case ThemeManager::Preference::Dark:
            return QStringLiteral("dark");
        }
        return QStringLiteral("auto");
    }

    /// Parses only the supported settings values, rejecting corruption as Auto.
    ThemeManager::Preference preference_from_settings(const QSettings& settings)
    {
        const QString name = settings.value(QStringLiteral("appearance/theme"), QStringLiteral("auto")).toString();
        if (name == QStringLiteral("light"))
            return ThemeManager::Preference::Light;
        if (name == QStringLiteral("dark"))
            return ThemeManager::Preference::Dark;
        return ThemeManager::Preference::Auto;
    }

} // namespace

SystemColorSchemeSource::SystemColorSchemeSource(QObject* parent)
    : ColorSchemeSource(parent)
{
    connect(QGuiApplication::styleHints(), &QStyleHints::colorSchemeChanged,
        this, &ColorSchemeSource::color_scheme_changed);
}

Qt::ColorScheme SystemColorSchemeSource::color_scheme() const
{
    return QGuiApplication::styleHints()->colorScheme();
}

ThemeManager::ThemeManager(QApplication& application, QObject* parent)
    : ThemeManager(application, std::make_unique<SystemColorSchemeSource>(), std::make_unique<QSettings>(), parent)
{
}

ThemeManager::ThemeManager(QApplication& application, std::unique_ptr<ColorSchemeSource> color_scheme_source, std::unique_ptr<QSettings> settings, QObject* parent)
    : QObject(parent)
    , application_(application)
    , color_scheme_source_(std::move(color_scheme_source))
    , settings_(std::move(settings))
{
    if (!color_scheme_source_)
        color_scheme_source_ = std::make_unique<SystemColorSchemeSource>();
    if (!settings_)
        settings_ = std::make_unique<QSettings>();

    color_scheme_source_->setParent(this);
    settings_->setParent(this);
    preference_ = preference_from_settings(*settings_);
    connect(color_scheme_source_.get(), &ColorSchemeSource::color_scheme_changed, this, [this]() {
        if (preference_ == Preference::Auto)
            apply();
    });

    QApplication::setStyle(QStringLiteral("Fusion"));
    apply();
}

ThemeManager::~ThemeManager() = default;

ThemeManager::Preference ThemeManager::preference() const
{
    return preference_;
}

Qt::ColorScheme ThemeManager::color_scheme() const
{
    return color_scheme_;
}

void ThemeManager::set_preference(Preference preference)
{
    if (preference_ == preference)
        return;

    preference_ = preference;
    settings_->setValue(QStringLiteral("appearance/theme"), preference_name(preference));
    settings_->sync();
    if (settings_->status() != QSettings::NoError)
        qCWarning(theme_log) << "Unable to save the theme preference";
    apply();
}

void ThemeManager::apply()
{
    color_scheme_ = preference_ == Preference::Auto
        ? color_scheme_source_->color_scheme()
        : (preference_ == Preference::Dark ? Qt::ColorScheme::Dark : Qt::ColorScheme::Light);
    if (color_scheme_ == Qt::ColorScheme::Unknown)
        color_scheme_ = Qt::ColorScheme::Light;

    const ThemeColors colors = colors_for(color_scheme_);
    application_.setPalette(palette_for(colors));
    application_.setStyleSheet(stylesheet_for(colors));
    emit appearance_changed();
}

} // namespace tcp_chat::client

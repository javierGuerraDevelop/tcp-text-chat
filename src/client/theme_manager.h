#pragma once

#include <QObject>
#include <QPalette>

#include <memory>

class QApplication;
class QSettings;

namespace tcp_chat::client {

/// Supplies the operating system color scheme without exposing platform APIs to consumers.
class ColorSchemeSource : public QObject {
    Q_OBJECT

public:
    using QObject::QObject;

    /// Returns the current system preference, or Unknown when none is reported.
    virtual Qt::ColorScheme color_scheme() const = 0;

signals:
    /// Emits when the operating system appearance changes.
    void color_scheme_changed(Qt::ColorScheme color_scheme);
};

/// Reads Qt's system color scheme and its live change notifications.
class SystemColorSchemeSource final : public ColorSchemeSource {
    Q_OBJECT

public:
    /// Connects to the current GUI application's style hints.
    explicit SystemColorSchemeSource(QObject* parent = nullptr);

    /// Returns the color scheme reported by QStyleHints.
    Qt::ColorScheme color_scheme() const override;
};

/// Applies semantic application themes and persists only the user's theme preference.
class ThemeManager final : public QObject {
    Q_OBJECT

public:
    /// Selects a fixed appearance or live following of the system appearance.
    enum class Preference {
        Auto,
        Light,
        Dark,
    };
    Q_ENUM(Preference)

    /// Creates a theme manager using Qt system appearance and the default QSettings location.
    explicit ThemeManager(QApplication& application, QObject* parent = nullptr);

    /// Creates a theme manager with injected dependencies and takes ownership of both.
    ThemeManager(QApplication& application, std::unique_ptr<ColorSchemeSource> color_scheme_source, std::unique_ptr<QSettings> settings, QObject* parent = nullptr);
    ~ThemeManager() override;

    /// Returns the persisted preference, defaulting to Auto when it is missing or invalid.
    Preference preference() const;

    /// Returns the currently applied color scheme; an unknown system scheme resolves to Light.
    Qt::ColorScheme color_scheme() const;

    /// Applies and saves a new preference.
    void set_preference(Preference preference);

signals:
    /// Emits after the application palette and stylesheet have been updated.
    void appearance_changed();

private:
    /// Applies the current preference and the latest system color scheme.
    void apply();

    QApplication& application_;
    std::unique_ptr<ColorSchemeSource> color_scheme_source_;
    std::unique_ptr<QSettings> settings_;
    Preference preference_        = Preference::Auto;
    Qt::ColorScheme color_scheme_ = Qt::ColorScheme::Light;
};

} // namespace tcp_chat::client

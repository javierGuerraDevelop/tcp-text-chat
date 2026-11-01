#pragma once

#include "theme_manager.h"

#include <QMainWindow>

class QComboBox;
class QLabel;
class QStackedWidget;

namespace tcp_chat::client {

/// Owns the client navigation and its welcome, connection, chat, and error states.
class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    /// Identifies the single application page currently presented to the user.
    enum class Page {
        Welcome,
        Connecting,
        Chat,
        Error,
    };
    Q_ENUM(Page)

    /// Creates the window; the theme manager must outlive it and all child widgets are Qt-owned.
    explicit MainWindow(ThemeManager& theme_manager, QWidget* parent = nullptr);

    /// Shows a top-level application state without performing network operations.
    void show_page(Page page);

    /// Shows a recoverable error using plain, caller-sanitized text.
    void show_error(const QString& message);

    /// Returns the visible application state.
    Page current_page() const;

signals:
    /// Emits when the user cancels the connecting state.
    void cancel_requested();

private:
    /// Builds the theme preference control and connects it to the theme manager.
    QComboBox* create_theme_selector(QWidget* parent);

    ThemeManager& theme_manager_;
    QComboBox* const theme_selector_;
    QStackedWidget* const pages_;
    QLabel* const error_message_;
};

} // namespace tcp_chat::client

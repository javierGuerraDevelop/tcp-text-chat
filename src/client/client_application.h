#pragma once

#include "authentication_controller.h"

#include <QObject>

namespace tcp_chat::client {

class MainWindow;

/// Connects user intents and authentication state without transferring session ownership to widgets.
class ClientApplication final : public QObject {
    Q_OBJECT

public:
    /// Creates application composition; the window and controller must outlive it.
    ClientApplication(MainWindow& window, AuthenticationController& controller,
        TlsClientConfiguration configuration, QObject* parent = nullptr);

    /// Shows the connecting state and starts the configured TLS connection.
    void start();

private:
    /// Maps controller state onto the corresponding window and form state.
    void update_state(AuthenticationController::State state);

    MainWindow& window_;
    AuthenticationController& controller_;
    TlsClientConfiguration configuration_;
};

} // namespace tcp_chat::client

#pragma once

#include "authentication_controller.h"

#include <QObject>

namespace tcp_chat::client {

class MainWindow;
class ChatController;

/// Connects user intents and controller state without transferring session ownership to widgets.
class ClientApplication final : public QObject {
    Q_OBJECT

public:
    /// Creates application composition; the window and controllers must outlive it.
    ClientApplication(MainWindow& window, AuthenticationController& controller, ChatController& chat,
        TlsClientConfiguration configuration, QObject* parent = nullptr);

    /// Starts a new connection or resumes the in-memory session after network loss.
    void start();

private:
    /// Maps controller state onto the corresponding window and form state.
    void update_state(AuthenticationController::State state);

    MainWindow& window_;
    AuthenticationController& controller_;
    ChatController& chat_;
    TlsClientConfiguration configuration_;
};

} // namespace tcp_chat::client

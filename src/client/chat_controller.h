#pragma once

#include "authentication_controller.h"
#include "chat_model.h"

#include <QHash>

namespace tcp_chat::client {

/// Coordinates shared-room history, live messages, and idempotent sends on the GUI thread.
class ChatController final : public QObject {
    Q_OBJECT

public:
    static constexpr qsizetype maximum_pending_sends = 16;

    /// Creates a controller; the transport, authentication, and model must outlive it.
    explicit ChatController(TlsClient* client, AuthenticationController* authentication, ChatModel* model, QObject* parent = nullptr);

    /// Queues a validated message and returns its idempotency key when accepted.
    std::optional<QString> send_message(const QString& body);
    /// Retries a failed message with its original idempotency key.
    bool retry_message(const QString& client_message_id);
    /// Requests the next older page when one is available.
    void load_older_history();
    /// Returns whether any history request is in flight.
    bool is_loading_history() const;
    /// Returns whether an older page can be requested.
    bool has_older_history() const;

signals:
    /// Publishes initial, older-page, and catch-up loading activity.
    void history_loading_changed(bool loading);
    /// Publishes availability of older persisted messages.
    void older_history_available_changed(bool available);
    /// Emits after initial history or reconnect catch-up completes successfully.
    void history_loaded();
    /// Reports a safe send or history error without message contents.
    void operation_failed(const QString& message);

private:
    enum class HistoryMode {
        None,
        Latest,
        Before,
        After,
    };

    /// Starts history and outgoing-message alignment for a newly authenticated session.
    void authenticated(const protocol::UserIdentity& user);
    /// Suspends sends and marks in-flight messages retryable during authentication changes.
    void authentication_state_changed(AuthenticationController::State state);
    /// Handles correlated history responses, send acknowledgements, and live events.
    void message_received(const protocol::Envelope& envelope);
    /// Sends one new or retry request with a stable client message ID.
    std::optional<QString> send_with_id(const QString& client_message_id, const QString& body);
    /// Starts a latest, older-page, or reconnect history request.
    void request_history(HistoryMode mode);
    /// Finishes a history response and continues multi-page catch-up.
    void history_received(const protocol::Envelope& envelope);
    /// Publishes loading state changes.
    void set_history_loading(bool loading);
    /// Publishes older-page availability changes.
    void set_has_older_history(bool available);
    /// Marks all accepted sends as failed without changing their idempotency keys.
    void fail_pending_sends();

    TlsClient* const client_;
    AuthenticationController* const authentication_;
    ChatModel* const model_;
    QHash<QString, QString> send_requests_;
    QString history_request_id_;
    HistoryMode history_mode_ = HistoryMode::None;
    quint64 next_request_id_  = 1;
    bool active_              = false;
    bool history_loading_     = false;
    bool has_older_history_   = false;
};

} // namespace tcp_chat::client

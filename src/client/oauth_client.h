#pragma once

#include "tcp_chat/auth_protocol.h"
#include "tls_client.h"

#include <QTimer>
#include <QUrl>

#include <functional>

namespace tcp_chat::client {

/// Coordinates browser OAuth over an established TLS client without persisting tokens.
class OAuthClient : public QObject {
    Q_OBJECT

public:
    /// Creates an idle coordinator; the TLS client must outlive it.
    explicit OAuthClient(TlsClient* client, std::function<bool(const QUrl&)> browser_opener = { }, QObject* parent = nullptr);

    /// Starts one browser sign-in on an established, unauthenticated connection.
    std::optional<QString> start(const QString& provider);
    /// Cancels polling and disconnects to invalidate the server-side flow.
    void cancel();
    /// Returns whether a browser flow or completion is in progress.
    bool is_busy() const;

signals:
    /// Emits when the system browser has been asked to open the authorization URL.
    void pending();
    /// Delivers a newly issued in-memory chat session after handoff redemption.
    void authenticated(const tcp_chat::protocol::AuthenticationResult& result);
    /// Reports a safe terminal sign-in error.
    void failed(const QString& message);

private:
    enum class State {
        Idle,
        Starting,
        Polling,
        Completing,
    };

    /// Handles correlated OAuth and final authentication results.
    void message_received(const tcp_chat::protocol::Envelope& envelope);
    /// Polls an active flow using its opaque handle.
    void poll();
    /// Stops local work, wipes the handoff, and reports a generic failure.
    void fail(const QString& message);

    TlsClient* const client_;
    std::function<bool(const QUrl&)> browser_opener_;
    QTimer poll_timer_;
    State state_ = State::Idle;
    QString request_id_;
    QString flow_handle_;
    QString handoff_;
    quint64 next_request_id_ = 1;
};

} // namespace tcp_chat::client

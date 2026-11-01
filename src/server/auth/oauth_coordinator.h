#pragma once

#include "oauth_provider.h"

#include <QHash>
#include <QObject>

#include <functional>
#include <memory>

namespace tcp_chat::auth {

/// Bounds browser-flow lifetime, exchange work, and one-time session handoffs.
struct OAuthCoordinatorOptions {
    int maximum_flows                  = 32;
    int maximum_flows_per_connection   = 1;
    int maximum_pending_exchanges      = 8;
    qint64 flow_lifetime_ms            = 300000;
    qint64 handoff_lifetime_ms         = 60000;
    qint64 terminal_result_lifetime_ms = 60000;
    std::function<qint64()> clock;
};

/// Contains the browser destination and opaque handle for one pending sign-in.
struct OAuthStartResult {
    QString flow_handle;
    QUrl authorization_url;
    qint64 expires_at = 0;
};

/// Describes the public state of a browser sign-in.
enum class OAuthFlowStatus {
    Pending,
    Ready,
    Failed,
};

/// Returns pending state, a short-lived handoff, or a generic terminal failure.
struct OAuthStatusResult {
    OAuthFlowStatus status = OAuthFlowStatus::Pending;
    QString handoff;
    qint64 expires_at = 0;
};

/// Coordinates bounded OAuth flows and handoffs on the authentication service thread.
class OAuthCoordinator : public QObject {
    Q_OBJECT

public:
    /// Creates a coordinator with the exact externally reachable HTTPS callback URI.
    explicit OAuthCoordinator(QUrl redirect_uri, OAuthCoordinatorOptions options = OAuthCoordinatorOptions { }, QObject* parent = nullptr);

    /// Returns an invalid option or callback URI, or nullopt when usable.
    std::optional<QString> configuration_error() const;
    /// Registers a provider with a unique canonical identifier.
    bool add_provider(std::shared_ptr<OAuthProvider> provider, QString* error);
    /// Starts a flow owned by one connected chat client.
    std::optional<OAuthStartResult> start(quint64 connection_id, const QString& provider_id, QString* error);
    /// Returns an owned flow's status without exposing provider details.
    std::optional<OAuthStatusResult> status(quint64 connection_id, const QString& flow_handle);
    /// Consumes callback state before starting an asynchronous provider exchange.
    void authorization_received(const QString& state, const QString& code, const QString& error);
    /// Completes account provisioning or retries a generated username conflict.
    void account_resolved(quint64 flow_id, qint64 user_id, bool username_conflict);
    /// Atomically consumes an owned, unexpired handoff and returns its user ID.
    std::optional<qint64> redeem(quint64 connection_id, const QString& flow_handle, const QString& handoff);
    /// Cancels every flow owned by a disconnected client.
    void cancel_connection(quint64 connection_id);
    /// Removes expired flows, exchanges, terminal results, and handoffs using the injected clock.
    void check_expirations();
    /// Returns the latest active-flow deadline for a connection, or zero if none exists.
    qint64 connection_deadline(quint64 connection_id) const;

signals:
    /// Requests atomic account lookup/provisioning with a server-generated candidate username.
    void account_resolution_requested(quint64 flow_id, const QString& provider, const QString& subject,
        const QString& username, const QString& normalized_username, const QString& display_name);

private:
    enum class Phase {
        Callback,
        Exchange,
        Provisioning,
        Ready,
        Failed,
    };

    /// Holds sensitive material only for the bounded lifetime of a flow.
    struct Flow {
        quint64 id            = 0;
        quint64 connection_id = 0;
        QString provider;
        QString subject;
        QByteArray verifier;
        QByteArray nonce;
        QString username;
        qint64 user_id = 0;
        QString handoff;
        QByteArray handoff_digest;
        qint64 expires_at         = 0;
        Phase phase               = Phase::Callback;
        int provisioning_attempts = 0;
        ~Flow();
    };

    /// Validates provider identity claims after provider-specific token validation.
    void exchange_finished(const OAuthExchangeResult& result);
    /// Marks a flow failed for a bounded polling interval.
    void fail_flow(Flow& flow, qint64 current);
    /// Emits a storage request with a fresh, valid candidate username.
    bool request_account(Flow& flow);
    /// Returns the current injected or system timestamp in milliseconds.
    qint64 now() const;

    QUrl redirect_uri_;
    OAuthCoordinatorOptions options_;
    QHash<QString, std::shared_ptr<OAuthProvider>> providers_;
    QHash<QByteArray, std::shared_ptr<Flow>> flows_;
    QHash<QByteArray, QByteArray> states_;
    quint64 next_flow_id_ = 1;
};

} // namespace tcp_chat::auth

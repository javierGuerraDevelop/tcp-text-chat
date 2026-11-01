#pragma once

#include <QByteArray>
#include <QMetaType>
#include <QObject>
#include <QString>
#include <QUrl>

#include <optional>

namespace tcp_chat::auth {

/// Configures one canonical provider without containing a client secret.
struct OAuthProviderConfiguration {
    QString id;
    QUrl authorization_endpoint;
    QString client_id;
    QString issuer;
    QString audience;
    bool use_nonce = false;
};

/// Contains the public parameters needed to construct an authorization URL.
struct OAuthAuthorizationRequest {
    QByteArray state;
    QByteArray code_challenge;
    QByteArray nonce;
    QUrl redirect_uri;
};

/// Contains the secrets needed for one provider exchange on the coordinator thread.
struct OAuthExchange {
    QByteArray code;
    QByteArray verifier;
    QUrl redirect_uri;
    QByteArray expected_nonce;
};

/// Contains validated public identity claims, never provider access or refresh tokens.
struct OAuthIdentity {
    QString provider;
    QString subject;
    QString issuer;
    QString audience;
    QByteArray nonce;

    bool operator==(const OAuthIdentity&) const = default;
};

/// Returns either a provider-validated identity or a safe, generic failure.
struct OAuthExchangeResult {
    quint64 flow_id = 0;
    std::optional<OAuthIdentity> identity;
    QString error;
};

/// Defines an asynchronous authorization-code exchange and provider identity validation.
class OAuthProvider : public QObject {
    Q_OBJECT

public:
    /// Creates a provider with immutable public configuration.
    explicit OAuthProvider(OAuthProviderConfiguration configuration, QObject* parent = nullptr);

    /// Returns the provider's canonical configuration.
    const OAuthProviderConfiguration& configuration() const;
    /// Returns a configuration error, or nullopt when authorization can be configured safely.
    std::optional<QString> configuration_error() const;
    /// Builds an authorization URL with state, S256 PKCE, exact redirect, and optional nonce.
    std::optional<QUrl> authorization_url(const OAuthAuthorizationRequest& request) const;
    /// Starts an exchange after validating its bounded inputs and exact HTTPS redirect.
    void exchange(quint64 flow_id, OAuthExchange exchange);

signals:
    /// Completes an exchange without exposing provider tokens to the coordinator.
    void exchange_finished(const tcp_chat::auth::OAuthExchangeResult& result);

protected:
    /// Exchanges a code and validates its token signature and PKCE verifier before publishing identity claims.
    virtual void perform_exchange(quint64 flow_id, OAuthExchange exchange) = 0;
    /// Queues a result so callers never re-enter flow handling during an exchange call.
    void finish_exchange(OAuthExchangeResult result);

private:
    OAuthProviderConfiguration configuration_;
};

} // namespace tcp_chat::auth

Q_DECLARE_METATYPE(tcp_chat::auth::OAuthExchangeResult)

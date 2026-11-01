#pragma once

#include "auth/oauth_crypto.h"
#include "auth/oauth_provider.h"

/// Models fixed provider code/signature validation without network access or credentials.
class FakeOAuthProvider : public tcp_chat::auth::OAuthProvider {
public:
    enum class ClaimMode {
        Valid,
        WrongIssuer,
        WrongAudience,
        WrongNonce,
    };

    using tcp_chat::auth::OAuthProvider::OAuthProvider;

    QByteArray expected_challenge;
    QUrl expected_redirect;
    ClaimMode claim_mode = ClaimMode::Valid;
    bool reject_exchange = false;
    int exchanges        = 0;

protected:
    /// Accepts only the fixed code and expected PKCE/redirect, then returns selected claims.
    void perform_exchange(quint64 flow_id, tcp_chat::auth::OAuthExchange exchange) override
    {
        ++exchanges;
        const auto challenge = tcp_chat::auth::pkce_s256_challenge(QString::fromLatin1(exchange.verifier));
        if (reject_exchange || exchange.code != QByteArrayLiteral("valid-code") || !challenge.has_value()
            || *challenge != expected_challenge || exchange.redirect_uri != expected_redirect) {
            finish_exchange(tcp_chat::auth::OAuthExchangeResult { flow_id, std::nullopt, QStringLiteral("Exchange denied") });
            return;
        }
        tcp_chat::auth::OAuthIdentity identity;
        identity.provider = configuration().id;
        identity.subject  = QStringLiteral("provider-subject-123");
        identity.issuer   = configuration().issuer;
        identity.audience = configuration().audience.isEmpty() ? configuration().client_id : configuration().audience;
        identity.nonce    = exchange.expected_nonce;
        if (claim_mode == ClaimMode::WrongIssuer) {
            identity.issuer = QStringLiteral("https://attacker.invalid");
        } else if (claim_mode == ClaimMode::WrongAudience) {
            identity.audience = QStringLiteral("another-client");
        } else if (claim_mode == ClaimMode::WrongNonce) {
            identity.nonce = QByteArrayLiteral("wrong-nonce");
        }
        finish_exchange(tcp_chat::auth::OAuthExchangeResult { flow_id, identity, QString() });
    }
};

/// Returns a deterministic public configuration for the fake OIDC-capable provider.
inline tcp_chat::auth::OAuthProviderConfiguration fake_provider_configuration()
{
    tcp_chat::auth::OAuthProviderConfiguration configuration;
    configuration.id                     = QStringLiteral("fake");
    configuration.authorization_endpoint = QUrl(QStringLiteral("https://provider.invalid/authorize"));
    configuration.client_id              = QStringLiteral("test-client");
    configuration.issuer                 = QStringLiteral("https://issuer.invalid");
    configuration.use_nonce              = true;
    return configuration;
}

#pragma once

#include "oauth_provider.h"

#include <QHash>
#include <QJsonObject>
#include <QSslConfiguration>

#include <memory>

class QNetworkAccessManager;
class QNetworkReply;
class QNetworkRequest;

namespace tcp_chat::auth {

/// Selects the stable identifier representation returned by a UserInfo endpoint.
enum class UserInfoSubjectType {
    StringId,
    NumericId,
};

/// Configures server-only credentials and bounded HTTPS provider communication.
struct HttpOAuthProviderOptions {
    OAuthProviderConfiguration configuration;
    QUrl token_endpoint;
    QUrl userinfo_endpoint;
    QByteArray client_secret;
    UserInfoSubjectType subject_type    = UserInfoSubjectType::StringId;
    QSslConfiguration tls_configuration = QSslConfiguration::defaultConfiguration();
    int request_timeout_ms              = 10000;
    qsizetype maximum_response_bytes    = 65536;
};

/// Exchanges authorization codes and resolves identities through authenticated HTTPS UserInfo APIs.
class HttpOAuthProvider : public OAuthProvider {
    Q_OBJECT

public:
    /// Creates a provider whose credentials never enter the public provider configuration.
    explicit HttpOAuthProvider(HttpOAuthProviderOptions options, QObject* parent = nullptr);
    /// Aborts owned network work and wipes retained credential buffers.
    ~HttpOAuthProvider() override;

    /// Validates endpoints, credentials, TLS verification, and network bounds.
    std::optional<QString> configuration_error() const override;

protected:
    /// Starts the asynchronous token exchange on the provider's QObject thread.
    void perform_exchange(quint64 flow_id, OAuthExchange exchange) override;

private:
    /// Owns one exchange's bounded sensitive state until the identity is resolved.
    struct Pending {
        QNetworkReply* reply = nullptr;
        QByteArray request_body;
        QByteArray response;
        QByteArray access_token;
        bool too_large = false;
        ~Pending();
    };

    /// Sends the code, verifier, exact redirect, and server credentials to the token endpoint.
    void post_token(quint64 flow_id, const OAuthExchange& exchange);
    /// Uses a short-lived access token only for the provider's UserInfo request.
    void get_userinfo(quint64 flow_id, const std::shared_ptr<Pending>& pending);
    /// Applies TLS, timeout, redirect, and request-header policy.
    QNetworkRequest request(const QUrl& endpoint, const QByteArray& access_token = { }) const;
    /// Accumulates a response up to the configured bound and aborts excess data.
    void read_response(quint64 flow_id);
    /// Handles token responses and starts UserInfo lookup after validation.
    void token_finished(quint64 flow_id);
    /// Extracts the stable provider subject without retaining the access token.
    void userinfo_finished(quint64 flow_id);
    /// Parses a bounded successful JSON response and wipes its owned encoded buffer.
    bool response_json(Pending& pending, QJsonObject* object) const;
    /// Completes a failed exchange without exposing provider response details.
    void fail(quint64 flow_id);

    HttpOAuthProviderOptions options_;
    QNetworkAccessManager* const network_;
    QHash<quint64, std::shared_ptr<Pending>> pending_;
};

} // namespace tcp_chat::auth

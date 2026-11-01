#include "oauth_provider_factory.h"

#include <sodium.h>

namespace tcp_chat::auth {
namespace {

    /// Wipes one environment-derived credential after provider construction.
    void wipe(QByteArray& value)
    {
        if (!value.isEmpty()) {
            sodium_memzero(value.data(), static_cast<size_t>(value.size()));
            value.clear();
        }
    }

} // namespace

HttpOAuthProviderOptions google_oauth_provider_options(const QString& client_id, QByteArray client_secret)
{
    HttpOAuthProviderOptions options;
    options.configuration.id                     = QStringLiteral("google");
    options.configuration.authorization_endpoint = QUrl(QStringLiteral("https://accounts.google.com/o/oauth2/v2/auth"));
    options.configuration.client_id              = client_id;
    options.configuration.authorization_scope    = QStringLiteral("https://www.googleapis.com/auth/userinfo.profile");
    options.configuration.identity_source        = OAuthIdentitySource::UserInfo;
    options.token_endpoint                       = QUrl(QStringLiteral("https://oauth2.googleapis.com/token"));
    options.userinfo_endpoint                    = QUrl(QStringLiteral("https://www.googleapis.com/oauth2/v2/userinfo"));
    options.client_secret                        = std::move(client_secret);
    options.subject_type                         = UserInfoSubjectType::StringId;
    return options;
}

HttpOAuthProviderOptions github_oauth_provider_options(const QString& client_id, QByteArray client_secret)
{
    HttpOAuthProviderOptions options;
    options.configuration.id                     = QStringLiteral("github");
    options.configuration.authorization_endpoint = QUrl(QStringLiteral("https://github.com/login/oauth/authorize"));
    options.configuration.client_id              = client_id;
    options.configuration.authorization_scope    = QStringLiteral("read:user");
    options.configuration.identity_source        = OAuthIdentitySource::UserInfo;
    options.token_endpoint                       = QUrl(QStringLiteral("https://github.com/login/oauth/access_token"));
    options.userinfo_endpoint                    = QUrl(QStringLiteral("https://api.github.com/user"));
    options.client_secret                        = std::move(client_secret);
    options.subject_type                         = UserInfoSubjectType::NumericId;
    return options;
}

std::optional<QString> load_oauth_providers_from_environment(QList<std::shared_ptr<OAuthProvider>>* providers)
{
    if (providers == nullptr) {
        return QStringLiteral("An OAuth provider destination is required");
    }
    QList<std::shared_ptr<OAuthProvider>> loaded;
    const QList<QPair<QByteArray, QByteArray>> variables = {
        { QByteArrayLiteral("TCP_CHAT_GOOGLE_CLIENT_ID"), QByteArrayLiteral("TCP_CHAT_GOOGLE_CLIENT_SECRET") },
        { QByteArrayLiteral("TCP_CHAT_GITHUB_CLIENT_ID"), QByteArrayLiteral("TCP_CHAT_GITHUB_CLIENT_SECRET") },
    };
    for (const auto& pair : variables) {
        const bool id_set     = qEnvironmentVariableIsSet(pair.first.constData());
        const bool secret_set = qEnvironmentVariableIsSet(pair.second.constData());
        if (!id_set && !secret_set) {
            continue;
        }
        QByteArray secret   = qgetenv(pair.second.constData());
        const QByteArray id = qgetenv(pair.first.constData());
        if (!id_set || !secret_set || id.isEmpty() || secret.isEmpty()) {
            wipe(secret);
            return QStringLiteral("%1 and %2 must both be set and nonempty").arg(QString::fromLatin1(pair.first), QString::fromLatin1(pair.second));
        }
        std::shared_ptr<HttpOAuthProvider> provider;
        if (pair.first == QByteArrayLiteral("TCP_CHAT_GOOGLE_CLIENT_ID")) {
            provider = std::make_shared<HttpOAuthProvider>(google_oauth_provider_options(QString::fromUtf8(id), secret));
        } else {
            provider = std::make_shared<HttpOAuthProvider>(github_oauth_provider_options(QString::fromUtf8(id), secret));
        }
        wipe(secret);
        if (const auto error = provider->configuration_error(); error.has_value()) {
            return QStringLiteral("%1 has an invalid OAuth configuration: %2").arg(QString::fromLatin1(pair.first), *error);
        }
        loaded.append(std::move(provider));
    }
    *providers = std::move(loaded);
    return std::nullopt;
}

} // namespace tcp_chat::auth

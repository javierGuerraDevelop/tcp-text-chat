#pragma once

#include "http_oauth_provider.h"

namespace tcp_chat::auth {

/// Returns Google OAuth 2.0 UserInfo settings with a server-owned secret.
HttpOAuthProviderOptions google_oauth_provider_options(const QString& client_id, QByteArray client_secret);
/// Returns GitHub OAuth 2.0 UserInfo settings with a server-owned secret.
HttpOAuthProviderOptions github_oauth_provider_options(const QString& client_id, QByteArray client_secret);
/// Loads complete provider credential pairs from the environment without logging their values.
std::optional<QString> load_oauth_providers_from_environment(QList<std::shared_ptr<OAuthProvider>>* providers);

} // namespace tcp_chat::auth

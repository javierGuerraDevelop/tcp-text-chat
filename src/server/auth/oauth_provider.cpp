#include "oauth_provider.h"

#include "oauth_crypto.h"

#include <QMetaObject>
#include <QUrlQuery>

namespace tcp_chat::auth {
namespace {

    /// Accepts only stable, lowercase provider identifiers for registry and database keys.
    bool valid_provider_id(const QString& id)
    {
        if (id.isEmpty() || id.size() > 32 || id.front() < QLatin1Char('a') || id.front() > QLatin1Char('z')) {
            return false;
        }
        return std::all_of(id.cbegin(), id.cend(), [](QChar character) {
            return (character >= QLatin1Char('a') && character <= QLatin1Char('z'))
                || (character >= QLatin1Char('0') && character <= QLatin1Char('9')) || character == QLatin1Char('_')
                || character == QLatin1Char('-');
        });
    }

    /// Restricts provider and callback URLs to HTTPS without embedded credentials or fragments.
    bool valid_https_url(const QUrl& url, bool allow_query = false)
    {
        return url.isValid() && url.scheme() == QStringLiteral("https") && !url.host().isEmpty() && url.userInfo().isEmpty()
            && !url.hasFragment() && (allow_query || !url.hasQuery());
    }

    /// Restricts public configuration strings to bounded, printable values.
    bool valid_configuration_text(const QString& value, qsizetype maximum)
    {
        return !value.isEmpty() && value.size() <= maximum
            && std::none_of(value.cbegin(), value.cend(), [](QChar character) { return character.isSpace() || !character.isPrint(); });
    }

} // namespace

OAuthProvider::OAuthProvider(OAuthProviderConfiguration configuration, QObject* parent)
    : QObject(parent)
    , configuration_(std::move(configuration))
{
}

const OAuthProviderConfiguration& OAuthProvider::configuration() const
{
    return configuration_;
}

std::optional<QString> OAuthProvider::configuration_error() const
{
    if (!valid_provider_id(configuration_.id) || !valid_https_url(configuration_.authorization_endpoint)
        || !valid_configuration_text(configuration_.client_id, 256)
        || !valid_configuration_text(configuration_.audience.isEmpty() ? configuration_.client_id : configuration_.audience, 256)) {
        return QStringLiteral("OAuth provider identity, endpoint, or audience is invalid");
    }
    if (configuration_.use_nonce && !valid_https_url(QUrl(configuration_.issuer))) {
        return QStringLiteral("An OpenID provider requires an HTTPS issuer");
    }
    if (!configuration_.issuer.isEmpty() && !valid_https_url(QUrl(configuration_.issuer))) {
        return QStringLiteral("OAuth provider issuer is invalid");
    }
    return std::nullopt;
}

std::optional<QUrl> OAuthProvider::authorization_url(const OAuthAuthorizationRequest& request) const
{
    if (configuration_error().has_value() || !valid_https_url(request.redirect_uri)
        || !digest_oauth_token(QString::fromLatin1(request.state)).has_value()
        || request.code_challenge.size() != 43
        || (configuration_.use_nonce && !digest_oauth_token(QString::fromLatin1(request.nonce)).has_value())
        || (!configuration_.use_nonce && !request.nonce.isEmpty())) {
        return std::nullopt;
    }

    QUrl url = configuration_.authorization_endpoint;
    QUrlQuery query;
    query.addQueryItem(QStringLiteral("response_type"), QStringLiteral("code"));
    query.addQueryItem(QStringLiteral("client_id"), configuration_.client_id);
    query.addQueryItem(QStringLiteral("redirect_uri"), request.redirect_uri.toString(QUrl::FullyEncoded));
    query.addQueryItem(QStringLiteral("state"), QString::fromLatin1(request.state));
    query.addQueryItem(QStringLiteral("code_challenge"), QString::fromLatin1(request.code_challenge));
    query.addQueryItem(QStringLiteral("code_challenge_method"), QStringLiteral("S256"));
    if (configuration_.use_nonce) {
        query.addQueryItem(QStringLiteral("scope"), QStringLiteral("openid profile"));
        query.addQueryItem(QStringLiteral("nonce"), QString::fromLatin1(request.nonce));
    } else {
        query.addQueryItem(QStringLiteral("scope"), QStringLiteral("read:user"));
    }
    url.setQuery(query);
    return url;
}

void OAuthProvider::exchange(quint64 flow_id, OAuthExchange exchange)
{
    if (flow_id == 0 || exchange.code.isEmpty() || exchange.code.size() > 2048
        || !pkce_s256_challenge(QString::fromLatin1(exchange.verifier)).has_value()
        || !valid_https_url(exchange.redirect_uri)
        || (configuration_.use_nonce && !digest_oauth_token(QString::fromLatin1(exchange.expected_nonce)).has_value())
        || (!configuration_.use_nonce && !exchange.expected_nonce.isEmpty())) {
        finish_exchange(OAuthExchangeResult { flow_id, std::nullopt, QStringLiteral("OAuth exchange input is invalid") });
        return;
    }
    perform_exchange(flow_id, std::move(exchange));
}

void OAuthProvider::finish_exchange(OAuthExchangeResult result)
{
    QMetaObject::invokeMethod(this, [this, result = std::move(result)]() mutable { emit exchange_finished(result); }, Qt::QueuedConnection);
}

} // namespace tcp_chat::auth

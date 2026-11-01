#include "oauth_crypto.h"

#include "session_token.h"

#include <QCryptographicHash>

#include <sodium.h>

#include <algorithm>

namespace tcp_chat::auth {

std::optional<OAuthToken> generate_oauth_token()
{
    const auto token = generate_session_token();
    if (!token.has_value()) {
        return std::nullopt;
    }
    return OAuthToken { token->value, token->digest };
}

std::optional<QByteArray> digest_oauth_token(const QString& token)
{
    return digest_session_token(token);
}

std::optional<QByteArray> pkce_s256_challenge(const QString& verifier)
{
    if (verifier.size() < 43 || verifier.size() > 128) {
        return std::nullopt;
    }
    const bool valid = std::all_of(verifier.cbegin(), verifier.cend(), [](QChar character) {
        return character.isLetterOrNumber() || character == QLatin1Char('-') || character == QLatin1Char('.')
            || character == QLatin1Char('_') || character == QLatin1Char('~');
    });
    if (!valid) {
        return std::nullopt;
    }
    const QByteArray encoded = verifier.toLatin1();
    if (encoded.size() != verifier.size()) {
        return std::nullopt;
    }
    const QByteArray digest = QCryptographicHash::hash(encoded, QCryptographicHash::Sha256);
    return digest.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
}

bool constant_time_equal(QByteArrayView left, QByteArrayView right)
{
    return left.size() == right.size()
        && sodium_memcmp(left.data(), right.data(), static_cast<size_t>(left.size())) == 0;
}

} // namespace tcp_chat::auth

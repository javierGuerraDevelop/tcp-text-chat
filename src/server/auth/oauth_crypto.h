#pragma once

#include <QByteArray>
#include <QString>

#include <optional>

namespace tcp_chat::auth {

/// Contains an opaque OAuth credential and the digest used for in-memory lookup.
struct OAuthToken {
    QString value;
    QByteArray digest;
};

/// Generates an independent 32-byte credential with strict Base64URL encoding.
std::optional<OAuthToken> generate_oauth_token();
/// Validates and digests an opaque OAuth credential without retaining it.
std::optional<QByteArray> digest_oauth_token(const QString& token);
/// Computes the RFC 7636 S256 challenge for a valid ASCII verifier.
std::optional<QByteArray> pkce_s256_challenge(const QString& verifier);
/// Compares two byte strings without an early-exit comparison.
bool constant_time_equal(QByteArrayView left, QByteArrayView right);

} // namespace tcp_chat::auth

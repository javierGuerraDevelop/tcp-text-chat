#pragma once

#include <QByteArray>
#include <QString>

#include <optional>

namespace tcp_chat::auth {

inline constexpr qsizetype session_token_bytes        = 32;
inline constexpr qsizetype session_token_encoded_size = 43;

/// Contains a new bearer token and the digest suitable for persistence.
struct GeneratedSessionToken {
    QString value;
    QByteArray digest;
};

/// Generates an opaque 32-byte token and its 32-byte generic-hash digest.
std::optional<GeneratedSessionToken> generate_session_token();

/// Validates a Base64URL token and returns the digest of its decoded bytes.
std::optional<QByteArray> digest_session_token(const QString& token);

} // namespace tcp_chat::auth

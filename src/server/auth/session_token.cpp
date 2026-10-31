#include "session_token.h"

#include <sodium.h>

#include <cstddef>
#include <utility>

namespace tcp_chat::auth {
namespace {

    static_assert(crypto_generichash_BYTES == session_token_bytes);

    /// Initializes libsodium once and reports whether it is usable.
    bool sodium_available()
    {
        static const bool available = sodium_init() >= 0;
        return available;
    }

    /// Clears a byte array with sodium_memzero when leaving its scope.
    class SodiumWipe {
    public:
        /// Retains the buffer to wipe at scope exit.
        explicit SodiumWipe(QByteArray& buffer)
            : buffer_(buffer)
        {
        }

        /// Wipes the complete retained buffer.
        ~SodiumWipe()
        {
            if (!buffer_.isEmpty()) {
                sodium_memzero(buffer_.data(), static_cast<size_t>(buffer_.size()));
            }
        }

    private:
        QByteArray& buffer_;
    };

    /// Computes an unkeyed 32-byte generic hash.
    std::optional<QByteArray> digest_bytes(QByteArrayView bytes)
    {
        QByteArray digest(crypto_generichash_BYTES, Qt::Uninitialized);
        if (crypto_generichash(reinterpret_cast<unsigned char*>(digest.data()), static_cast<size_t>(digest.size()),
                reinterpret_cast<const unsigned char*>(bytes.data()), static_cast<unsigned long long>(bytes.size()),
                nullptr, 0)
            != 0) {
            return std::nullopt;
        }
        return digest;
    }

} // namespace

std::optional<GeneratedSessionToken> generate_session_token()
{
    if (!sodium_available()) {
        return std::nullopt;
    }

    QByteArray raw(session_token_bytes, Qt::Uninitialized);
    SodiumWipe raw_wipe(raw);
    randombytes_buf(raw.data(), static_cast<size_t>(raw.size()));
    const QByteArray encoded = raw.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    if (encoded.size() != session_token_encoded_size) {
        return std::nullopt;
    }

    auto digest = digest_bytes(raw);
    if (!digest.has_value()) {
        return std::nullopt;
    }
    return GeneratedSessionToken { QString::fromLatin1(encoded), std::move(*digest) };
}

std::optional<QByteArray> digest_session_token(const QString& token)
{
    if (!sodium_available() || token.size() != session_token_encoded_size) {
        return std::nullopt;
    }

    const QByteArray encoded = token.toLatin1();
    if (encoded.size() != token.size()) {
        return std::nullopt;
    }
    auto decoding = QByteArray::fromBase64Encoding(encoded,
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals | QByteArray::AbortOnBase64DecodingErrors);
    SodiumWipe decoded_wipe(decoding.decoded);
    if (!decoding || decoding.decoded.size() != session_token_bytes) {
        return std::nullopt;
    }
    return digest_bytes(decoding.decoded);
}

} // namespace tcp_chat::auth

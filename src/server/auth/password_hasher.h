#pragma once

#include <QByteArrayView>
#include <QString>

#include <sodium.h>

#include <cstddef>
#include <optional>

namespace tcp_chat::auth {

/// Configures the Argon2id work factor and memory used for new password hashes.
struct Argon2idParameters {
    unsigned long long operations_limit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
    size_t memory_limit                 = crypto_pwhash_MEMLIMIT_INTERACTIVE;
};

/// Describes the outcome of checking a password against an encoded hash.
enum class PasswordVerification {
    Match,
    Mismatch,
    InvalidHash,
    InvalidInput,
    Unavailable,
};

/// Creates and verifies Argon2id password hashes using libsodium.
class PasswordHasher {
public:
    /// Creates a hasher with the given Argon2id parameters.
    explicit PasswordHasher(Argon2idParameters parameters = Argon2idParameters { });

    /// Hashes a password of at most 1024 bytes, or returns nullopt on failure.
    std::optional<QString> hash(QByteArrayView password) const;

    /// Verifies a password of at most 1024 bytes against an encoded Argon2id hash.
    PasswordVerification verify(QByteArrayView password, const QString& encoded_hash) const;

    /// Returns the parameters used for new hashes.
    Argon2idParameters parameters() const;

private:
    Argon2idParameters parameters_;
};

} // namespace tcp_chat::auth

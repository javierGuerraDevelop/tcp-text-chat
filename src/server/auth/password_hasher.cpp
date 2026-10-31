#include "password_hasher.h"

#include <QByteArray>

#include <array>

namespace tcp_chat::auth {
namespace {

    constexpr qsizetype maximum_password_size = 1024;

    /// Initializes libsodium once and reports whether it is usable.
    bool sodium_available()
    {
        static const bool available = sodium_init() >= 0;
        return available;
    }

    /// Checks parameters before passing them to libsodium.
    bool valid_parameters(const Argon2idParameters& parameters)
    {
        return parameters.operations_limit >= crypto_pwhash_OPSLIMIT_MIN
            && parameters.operations_limit <= crypto_pwhash_OPSLIMIT_MAX
            && parameters.memory_limit >= crypto_pwhash_MEMLIMIT_MIN
            && parameters.memory_limit <= crypto_pwhash_MEMLIMIT_MAX;
    }

    /// Returns a non-null pointer even for an empty password view.
    const char* password_data(QByteArrayView password)
    {
        return password.data() == nullptr ? "" : password.data();
    }

} // namespace

PasswordHasher::PasswordHasher(Argon2idParameters parameters)
    : parameters_(parameters)
{
}

std::optional<QString> PasswordHasher::hash(QByteArrayView password) const
{
    if (!sodium_available() || password.size() > maximum_password_size || !valid_parameters(parameters_)) {
        return std::nullopt;
    }

    std::array<char, crypto_pwhash_STRBYTES> encoded { };
    if (crypto_pwhash_str_alg(encoded.data(), password_data(password),
            static_cast<unsigned long long>(password.size()), parameters_.operations_limit,
            parameters_.memory_limit, crypto_pwhash_ALG_ARGON2ID13)
        != 0) {
        return std::nullopt;
    }
    return QString::fromLatin1(encoded.data());
}

PasswordVerification PasswordHasher::verify(QByteArrayView password, const QString& encoded_hash) const
{
    if (!sodium_available()) {
        return PasswordVerification::Unavailable;
    }
    if (password.size() > maximum_password_size || !valid_parameters(parameters_)) {
        return PasswordVerification::InvalidInput;
    }
    if (encoded_hash.isEmpty() || encoded_hash.size() >= static_cast<qsizetype>(crypto_pwhash_STRBYTES)) {
        return PasswordVerification::InvalidHash;
    }

    const QByteArray encoded = encoded_hash.toLatin1();
    if (encoded.size() != encoded_hash.size() || encoded.contains('\0')) {
        return PasswordVerification::InvalidHash;
    }
    if (crypto_pwhash_str_needs_rehash(
            encoded.constData(), parameters_.operations_limit, parameters_.memory_limit)
        < 0) {
        return PasswordVerification::InvalidHash;
    }
    return crypto_pwhash_str_verify(encoded.constData(), password_data(password),
               static_cast<unsigned long long>(password.size()))
            == 0
        ? PasswordVerification::Match
        : PasswordVerification::Mismatch;
}

Argon2idParameters PasswordHasher::parameters() const
{
    return parameters_;
}

} // namespace tcp_chat::auth

#pragma once

#include "tcp_chat/protocol.h"

namespace tcp_chat::protocol {

inline constexpr qsizetype minimum_username_length      = 3;
inline constexpr qsizetype maximum_username_length      = 32;
inline constexpr qsizetype maximum_display_name_length  = 64;
inline constexpr qsizetype minimum_password_bytes       = 8;
inline constexpr qsizetype maximum_password_bytes       = 1024;
inline constexpr qsizetype maximum_session_token_length = 128;
inline constexpr qsizetype issued_session_token_length  = 43;

/// Contains local account creation fields after structural validation.
struct SignUpData {
    QString username;
    QString password;
    std::optional<QString> display_name;

    bool operator==(const SignUpData&) const = default;
};

/// Contains local login fields after structural validation.
struct LogInData {
    QString username;
    QString password;

    bool operator==(const LogInData&) const = default;
};

/// Contains public user identity fields safe to return to a client.
struct UserIdentity {
    qint64 id = 0;
    QString username;
    QString display_name;

    bool operator==(const UserIdentity&) const = default;
};

/// Contains either an authenticated identity or an idempotent logout result.
struct AuthenticationResult {
    std::optional<UserIdentity> user;
    std::optional<QString> session_token;
    std::optional<qint64> expires_at;
    bool revoked = false;

    bool operator==(const AuthenticationResult&) const = default;
};

/// Normalizes a valid username, or returns nullopt when its length or characters are invalid.
std::optional<QString> normalize_username(const QString& username);

/// Validates a trimmed, printable display name within the protocol limit.
bool valid_display_name(const QString& display_name);

/// Decodes a signup envelope without exposing credential contents in errors.
std::optional<SignUpData> sign_up_from_envelope(const Envelope& envelope, ProtocolError* error = nullptr);

/// Decodes a login envelope without exposing credential contents in errors.
std::optional<LogInData> log_in_from_envelope(const Envelope& envelope, ProtocolError* error = nullptr);

/// Decodes the opaque token carried by session authentication and logout.
std::optional<QString> session_token_from_envelope(const Envelope& envelope, ProtocolError* error = nullptr);

/// Contains the flow and one-time handoff needed to finish browser sign-in.
struct OAuthCompletionData {
    QString flow_handle;
    QString handoff;
};

/// Contains a browser-flow state and any credential appropriate to that state.
struct OAuthResult {
    QString flow_handle;
    QString status;
    std::optional<QString> authorization_url;
    std::optional<QString> handoff;
    qint64 expires_at = 0;
};

/// Decodes a bounded canonical provider identifier.
std::optional<QString> oauth_provider_from_envelope(const Envelope& envelope, ProtocolError* error = nullptr);
/// Decodes the opaque flow handle used for status polling.
std::optional<QString> oauth_flow_from_envelope(const Envelope& envelope, ProtocolError* error = nullptr);
/// Decodes a flow handle and its distinct, single-use handoff.
std::optional<OAuthCompletionData> oauth_completion_from_envelope(const Envelope& envelope, ProtocolError* error = nullptr);
/// Encodes a started, pending, ready, or failed OAuth flow.
std::optional<QJsonObject> oauth_result_to_json(const OAuthResult& result, ProtocolError* error = nullptr);
/// Decodes a browser-flow result without treating its handoff as a session token.
std::optional<OAuthResult> oauth_result_from_envelope(const Envelope& envelope, ProtocolError* error = nullptr);

/// Encodes a public authentication result after validating its field combinations.
std::optional<QJsonObject> authentication_result_to_json(const AuthenticationResult& result, ProtocolError* error = nullptr);

/// Decodes a server authentication result for a client.
std::optional<AuthenticationResult> authentication_result_from_envelope(
    const Envelope& envelope, ProtocolError* error = nullptr);

} // namespace tcp_chat::protocol

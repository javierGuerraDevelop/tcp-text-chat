#include "tcp_chat/auth_protocol.h"

#include <QJsonObject>
#include <QUrl>

#include <algorithm>
#include <cmath>

namespace tcp_chat::protocol {
namespace {

    /// Clears any error reported by an earlier payload operation.
    void clear_error(ProtocolError* error)
    {
        if (error != nullptr) {
            error->code = ErrorCode::None;
            error->message.clear();
        }
    }

    /// Reports invalid operation data without including supplied values.
    void set_error(ProtocolError* error, const QString& message)
    {
        if (error != nullptr) {
            error->code    = ErrorCode::InvalidRequest;
            error->message = message;
        }
    }

    /// Checks the envelope type and exact payload field set.
    bool valid_payload(const Envelope& envelope, MessageType type, const QList<QString>& fields, ProtocolError* error)
    {
        if (envelope.type != type) {
            set_error(error, QStringLiteral("Unexpected message type for this operation"));
            return false;
        }
        for (auto it = envelope.payload.constBegin(); it != envelope.payload.constEnd(); ++it) {
            if (!fields.contains(it.key())) {
                set_error(error, QStringLiteral("Payload contains an unknown field"));
                return false;
            }
        }
        return true;
    }

    /// Reads a bounded string field without reproducing its value in diagnostics.
    std::optional<QString> string_field(const QJsonObject& object, const QString& name, qsizetype maximum, ProtocolError* error)
    {
        const QJsonValue value = object.value(name);
        if (!value.isString()) {
            set_error(error, QStringLiteral("A required string field is missing or invalid"));
            return std::nullopt;
        }
        const QString text = value.toString();
        if (text.isEmpty() || text.size() > maximum) {
            set_error(error, QStringLiteral("A string field has an invalid length"));
            return std::nullopt;
        }
        return text;
    }

    /// Validates password length in bytes while preserving its exact contents.
    bool valid_password(const QString& password)
    {
        const qsizetype size = password.toUtf8().size();
        return size >= minimum_password_bytes && size <= maximum_password_bytes;
    }

    /// Validates the fixed-size Base64URL representation of an issued token.
    bool valid_issued_token(const QString& token)
    {
        if (token.size() != issued_session_token_length) {
            return false;
        }
        return std::all_of(token.cbegin(), token.cend(), [](QChar character) {
            return character.isLetterOrNumber() || character == QLatin1Char('_') || character == QLatin1Char('-');
        });
    }

    /// Decodes the public identity object returned by the server.
    std::optional<UserIdentity> user_from_value(const QJsonValue& value, ProtocolError* error)
    {
        if (!value.isObject()) {
            set_error(error, QStringLiteral("User identity must be an object"));
            return std::nullopt;
        }
        const QJsonObject object    = value.toObject();
        const QList<QString> fields = { QStringLiteral("id"), QStringLiteral("username"), QStringLiteral("displayName") };
        for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
            if (!fields.contains(it.key())) {
                set_error(error, QStringLiteral("User identity contains an unknown field"));
                return std::nullopt;
            }
        }

        const auto id_string    = string_field(object, QStringLiteral("id"), 19, error);
        const auto username     = string_field(object, QStringLiteral("username"), maximum_username_length, error);
        const auto display_name = string_field(object, QStringLiteral("displayName"), maximum_display_name_length, error);
        if (!id_string.has_value() || !username.has_value() || !display_name.has_value()) {
            return std::nullopt;
        }
        bool valid_id   = false;
        const qint64 id = id_string->toLongLong(&valid_id);
        if (!valid_id || id <= 0 || QString::number(id) != *id_string || !normalize_username(*username).has_value()
            || !valid_display_name(*display_name)) {
            set_error(error, QStringLiteral("User identity fields are invalid"));
            return std::nullopt;
        }
        return UserIdentity { id, *username, *display_name };
    }

    /// Validates a millisecond timestamp within JSON's exact integer range.
    std::optional<qint64> timestamp_from_value(const QJsonValue& value, ProtocolError* error)
    {
        if (!value.isDouble()) {
            set_error(error, QStringLiteral("Expiry timestamp must be an integer"));
            return std::nullopt;
        }
        const double number = value.toDouble();
        if (!std::isfinite(number) || std::trunc(number) != number || number < 0 || number > 9007199254740991.0) {
            set_error(error, QStringLiteral("Expiry timestamp is outside the supported range"));
            return std::nullopt;
        }
        return static_cast<qint64>(number);
    }

} // namespace

std::optional<QString> normalize_username(const QString& username)
{
    const QString normalized = username.trimmed().normalized(QString::NormalizationForm_KC).toCaseFolded().normalized(QString::NormalizationForm_KC);
    if (normalized.size() < minimum_username_length || normalized.size() > maximum_username_length) {
        return std::nullopt;
    }
    for (qsizetype index = 0; index < normalized.size(); ++index) {
        const QChar character = normalized.at(index);
        if (!character.isLetterOrNumber() && character != QLatin1Char('_') && character != QLatin1Char('-')
            && character != QLatin1Char('.') && (index == 0 || !character.isMark())) {
            return std::nullopt;
        }
    }
    return normalized;
}

bool valid_display_name(const QString& display_name)
{
    if (display_name.isEmpty() || display_name.size() > maximum_display_name_length
        || display_name != display_name.trimmed()) {
        return false;
    }
    return std::all_of(display_name.cbegin(), display_name.cend(), [](QChar character) { return character.isPrint(); });
}

std::optional<SignUpData> sign_up_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if (!valid_payload(envelope, MessageType::AuthSignUp,
            { QStringLiteral("username"), QStringLiteral("password"), QStringLiteral("displayName") }, error)) {
        return std::nullopt;
    }
    const auto username = string_field(envelope.payload, QStringLiteral("username"), 128, error);
    const auto password = string_field(envelope.payload, QStringLiteral("password"), maximum_password_bytes, error);
    if (!username.has_value() || !password.has_value() || !normalize_username(*username).has_value()
        || !valid_password(*password)) {
        set_error(error, QStringLiteral("Signup credentials are invalid"));
        return std::nullopt;
    }

    SignUpData result { username->trimmed(), *password, std::nullopt };
    if (envelope.payload.contains(QStringLiteral("displayName"))) {
        const auto display_name = string_field(envelope.payload, QStringLiteral("displayName"), maximum_display_name_length, error);
        if (!display_name.has_value() || !valid_display_name(*display_name)) {
            set_error(error, QStringLiteral("Display name is invalid"));
            return std::nullopt;
        }
        result.display_name = *display_name;
    }
    return result;
}

std::optional<LogInData> log_in_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if (!valid_payload(envelope, MessageType::AuthLogIn, { QStringLiteral("username"), QStringLiteral("password") }, error)) {
        return std::nullopt;
    }
    const auto username = string_field(envelope.payload, QStringLiteral("username"), 128, error);
    const auto password = string_field(envelope.payload, QStringLiteral("password"), maximum_password_bytes, error);
    if (!username.has_value() || !password.has_value() || !valid_password(*password)) {
        set_error(error, QStringLiteral("Login fields are invalid"));
        return std::nullopt;
    }
    return LogInData { *username, *password };
}

std::optional<QString> session_token_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if ((envelope.type != MessageType::AuthSession && envelope.type != MessageType::AuthLogOut)
        || !valid_payload(envelope, envelope.type, { QStringLiteral("sessionToken") }, error)) {
        if (error != nullptr && error->code == ErrorCode::None) {
            set_error(error, QStringLiteral("Unexpected message type for session authentication"));
        }
        return std::nullopt;
    }
    return string_field(envelope.payload, QStringLiteral("sessionToken"), maximum_session_token_length, error);
}

std::optional<QJsonObject> authentication_result_to_json(const AuthenticationResult& result, ProtocolError* error)
{
    clear_error(error);
    if (result.revoked) {
        if (result.user.has_value() || result.session_token.has_value() || result.expires_at.has_value()) {
            set_error(error, QStringLiteral("Logout result cannot contain an authenticated session"));
            return std::nullopt;
        }
        return QJsonObject { { QStringLiteral("revoked"), true } };
    }
    if (!result.user.has_value() || !result.expires_at.has_value() || *result.expires_at < 0
        || !normalize_username(result.user->username).has_value() || !valid_display_name(result.user->display_name)
        || result.user->id <= 0 || (result.session_token.has_value() && !valid_issued_token(*result.session_token))) {
        set_error(error, QStringLiteral("Authentication result fields are invalid"));
        return std::nullopt;
    }

    QJsonObject object {
        { QStringLiteral("user"),
            QJsonObject { { QStringLiteral("id"), QString::number(result.user->id) },
                { QStringLiteral("username"), result.user->username },
                { QStringLiteral("displayName"), result.user->display_name } } },
        { QStringLiteral("expiresAt"), static_cast<double>(*result.expires_at) },
    };
    if (result.session_token.has_value()) {
        object.insert(QStringLiteral("sessionToken"), *result.session_token);
    }
    return object;
}

std::optional<AuthenticationResult> authentication_result_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if (!valid_payload(envelope, MessageType::AuthResult,
            { QStringLiteral("user"), QStringLiteral("sessionToken"), QStringLiteral("expiresAt"), QStringLiteral("revoked") },
            error)) {
        return std::nullopt;
    }

    if (envelope.payload.contains(QStringLiteral("revoked"))) {
        if (envelope.payload.size() != 1 || !envelope.payload.value(QStringLiteral("revoked")).isBool()
            || !envelope.payload.value(QStringLiteral("revoked")).toBool()) {
            set_error(error, QStringLiteral("Logout result is invalid"));
            return std::nullopt;
        }
        return AuthenticationResult { std::nullopt, std::nullopt, std::nullopt, true };
    }

    const auto user       = user_from_value(envelope.payload.value(QStringLiteral("user")), error);
    const auto expires_at = timestamp_from_value(envelope.payload.value(QStringLiteral("expiresAt")), error);
    if (!user.has_value() || !expires_at.has_value()) {
        return std::nullopt;
    }

    AuthenticationResult result;
    result.user       = *user;
    result.expires_at = *expires_at;
    if (envelope.payload.contains(QStringLiteral("sessionToken"))) {
        const auto token = string_field(envelope.payload, QStringLiteral("sessionToken"), issued_session_token_length, error);
        if (!token.has_value() || !valid_issued_token(*token)) {
            set_error(error, QStringLiteral("Issued session token is invalid"));
            return std::nullopt;
        }
        result.session_token = *token;
    }
    return result;
}

std::optional<QString> oauth_provider_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if (!valid_payload(envelope, MessageType::AuthOAuthStart, { QStringLiteral("provider") }, error)) {
        return std::nullopt;
    }
    const auto provider = string_field(envelope.payload, QStringLiteral("provider"), 32, error);
    if (!provider.has_value() || provider->front() < QLatin1Char('a') || provider->front() > QLatin1Char('z')
        || !std::all_of(provider->cbegin(), provider->cend(), [](QChar character) {
               return (character >= QLatin1Char('a') && character <= QLatin1Char('z'))
                   || (character >= QLatin1Char('0') && character <= QLatin1Char('9')) || character == QLatin1Char('_')
                   || character == QLatin1Char('-');
           })) {
        set_error(error, QStringLiteral("OAuth provider is invalid"));
        return std::nullopt;
    }
    return provider;
}

std::optional<QString> oauth_flow_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if (!valid_payload(envelope, MessageType::AuthOAuthStatus, { QStringLiteral("flow") }, error)) {
        return std::nullopt;
    }
    const auto flow = string_field(envelope.payload, QStringLiteral("flow"), issued_session_token_length, error);
    if (!flow.has_value() || !valid_issued_token(*flow)) {
        set_error(error, QStringLiteral("OAuth flow handle is invalid"));
        return std::nullopt;
    }
    return flow;
}

std::optional<OAuthCompletionData> oauth_completion_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if (!valid_payload(envelope, MessageType::AuthOAuthComplete, { QStringLiteral("flow"), QStringLiteral("handoff") }, error)) {
        return std::nullopt;
    }
    const auto flow    = string_field(envelope.payload, QStringLiteral("flow"), issued_session_token_length, error);
    const auto handoff = string_field(envelope.payload, QStringLiteral("handoff"), issued_session_token_length, error);
    if (!flow.has_value() || !handoff.has_value() || !valid_issued_token(*flow) || !valid_issued_token(*handoff)) {
        set_error(error, QStringLiteral("OAuth completion credentials are invalid"));
        return std::nullopt;
    }
    return OAuthCompletionData { *flow, *handoff };
}

std::optional<QJsonObject> oauth_result_to_json(const OAuthResult& result, ProtocolError* error)
{
    clear_error(error);
    const bool started = result.status == QStringLiteral("started");
    const bool ready   = result.status == QStringLiteral("ready");
    if (!valid_issued_token(result.flow_handle) || result.expires_at < 0 || result.expires_at > 9007199254740991LL
        || (!started && !ready && result.status != QStringLiteral("pending") && result.status != QStringLiteral("failed"))
        || result.authorization_url.has_value() != started || result.handoff.has_value() != ready
        || (ready && !valid_issued_token(*result.handoff))) {
        set_error(error, QStringLiteral("OAuth result fields are invalid"));
        return std::nullopt;
    }
    if (started) {
        const QUrl url(*result.authorization_url);
        if (!url.isValid() || url.toString().size() > 2048 || url.scheme() != QStringLiteral("https")
            || url.host().isEmpty() || !url.userInfo().isEmpty() || url.hasFragment()) {
            set_error(error, QStringLiteral("OAuth authorization URL is invalid"));
            return std::nullopt;
        }
    }
    QJsonObject object {
        { QStringLiteral("flow"), result.flow_handle },
        { QStringLiteral("status"), result.status },
        { QStringLiteral("expiresAt"), static_cast<double>(result.expires_at) },
    };
    if (started) {
        object.insert(QStringLiteral("authorizationUrl"), *result.authorization_url);
    }
    if (ready) {
        object.insert(QStringLiteral("handoff"), *result.handoff);
    }
    return object;
}

std::optional<OAuthResult> oauth_result_from_envelope(const Envelope& envelope, ProtocolError* error)
{
    clear_error(error);
    if (!valid_payload(envelope, MessageType::AuthOAuthResult,
            { QStringLiteral("flow"), QStringLiteral("status"), QStringLiteral("authorizationUrl"),
                QStringLiteral("handoff"), QStringLiteral("expiresAt") },
            error)) {
        return std::nullopt;
    }
    OAuthResult result;
    const auto flow       = string_field(envelope.payload, QStringLiteral("flow"), issued_session_token_length, error);
    const auto status     = string_field(envelope.payload, QStringLiteral("status"), 16, error);
    const auto expires_at = timestamp_from_value(envelope.payload.value(QStringLiteral("expiresAt")), error);
    if (!flow.has_value() || !status.has_value() || !expires_at.has_value()) {
        return std::nullopt;
    }
    result.flow_handle = *flow;
    result.status      = *status;
    result.expires_at  = *expires_at;
    if (envelope.payload.contains(QStringLiteral("authorizationUrl"))) {
        result.authorization_url = string_field(envelope.payload, QStringLiteral("authorizationUrl"), 2048, error).value_or(QString());
    }
    if (envelope.payload.contains(QStringLiteral("handoff"))) {
        result.handoff = string_field(envelope.payload, QStringLiteral("handoff"), issued_session_token_length, error).value_or(QString());
    }
    if (!oauth_result_to_json(result, error).has_value()) {
        return std::nullopt;
    }
    return result;
}

} // namespace tcp_chat::protocol

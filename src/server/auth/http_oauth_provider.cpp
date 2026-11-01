#include "http_oauth_provider.h"

#include "common/strict_json.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslSocket>
#include <QUrlQuery>

#include <sodium.h>

#include <algorithm>
#include <cmath>

namespace tcp_chat::auth {
namespace {

    /// Wipes one owned sensitive byte buffer without relying on compiler-preserving clears.
    void wipe(QByteArray& value)
    {
        if (!value.isEmpty()) {
            sodium_memzero(value.data(), static_cast<size_t>(value.size()));
            value.clear();
        }
    }

    /// Restricts provider tokens to bounded visible ASCII safe for an Authorization header.
    bool valid_access_token(const QByteArray& token)
    {
        return !token.isEmpty() && token.size() <= 8192
            && std::all_of(token.cbegin(), token.cend(), [](char character) {
                   const unsigned char byte = static_cast<unsigned char>(character);
                   return byte >= 0x21 && byte <= 0x7e;
               });
    }

    /// Requires an exact HTTPS endpoint without embedded credentials, query, or fragment.
    bool valid_endpoint(const QUrl& endpoint)
    {
        return endpoint.isValid() && endpoint.scheme() == QStringLiteral("https") && !endpoint.host().isEmpty()
            && endpoint.userInfo().isEmpty() && !endpoint.hasQuery() && !endpoint.hasFragment();
    }

} // namespace

HttpOAuthProvider::Pending::~Pending()
{
    wipe(request_body);
    wipe(response);
    wipe(access_token);
}

HttpOAuthProvider::HttpOAuthProvider(HttpOAuthProviderOptions options, QObject* parent)
    : OAuthProvider(options.configuration, parent)
    , options_(std::move(options))
    , network_(new QNetworkAccessManager(this))
{
    options_.client_secret.detach();
}

HttpOAuthProvider::~HttpOAuthProvider()
{
    pending_.clear();
    wipe(options_.client_secret);
}

std::optional<QString> HttpOAuthProvider::configuration_error() const
{
    if (const auto error = OAuthProvider::configuration_error(); error.has_value()) {
        return error;
    }
    if (options_.configuration.identity_source != OAuthIdentitySource::UserInfo || !valid_endpoint(options_.token_endpoint)
        || !valid_endpoint(options_.userinfo_endpoint)) {
        return QStringLiteral("UserInfo provider endpoints must use exact HTTPS URLs");
    }
    if (options_.client_secret.isEmpty() || options_.client_secret.size() > 4096 || options_.request_timeout_ms <= 0
        || options_.request_timeout_ms > 60000 || options_.maximum_response_bytes < 1024
        || options_.maximum_response_bytes > 1024 * 1024 || options_.tls_configuration.peerVerifyMode() == QSslSocket::VerifyNone) {
        return QStringLiteral("UserInfo provider credentials, TLS, or network limits are invalid");
    }
    return std::nullopt;
}

void HttpOAuthProvider::perform_exchange(quint64 flow_id, OAuthExchange exchange)
{
    if (configuration_error().has_value() || pending_.contains(flow_id)) {
        finish_exchange(OAuthExchangeResult { flow_id, std::nullopt, QStringLiteral("OAuth provider is unavailable") });
        return;
    }
    post_token(flow_id, exchange);
}

QNetworkRequest HttpOAuthProvider::request(const QUrl& endpoint, const QByteArray& access_token) const
{
    QNetworkRequest request(endpoint);
    QSslConfiguration tls = options_.tls_configuration;
    tls.setProtocol(QSsl::TlsV1_2OrLater);
    request.setSslConfiguration(tls);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setTransferTimeout(options_.request_timeout_ms);
    request.setRawHeader(QByteArrayLiteral("Accept"), QByteArrayLiteral("application/json"));
    request.setRawHeader(QByteArrayLiteral("User-Agent"), QByteArrayLiteral("tcp-text-chat"));
    if (!access_token.isEmpty()) {
        request.setRawHeader(QByteArrayLiteral("Authorization"), QByteArrayLiteral("Bearer ") + access_token);
    }
    return request;
}

void HttpOAuthProvider::post_token(quint64 flow_id, const OAuthExchange& exchange)
{
    auto pending = std::make_shared<Pending>();
    QUrlQuery form;
    form.addQueryItem(QStringLiteral("client_id"), configuration().client_id);
    form.addQueryItem(QStringLiteral("client_secret"), QString::fromUtf8(options_.client_secret));
    form.addQueryItem(QStringLiteral("code"), QString::fromUtf8(exchange.code));
    form.addQueryItem(QStringLiteral("redirect_uri"), exchange.redirect_uri.toString(QUrl::FullyEncoded));
    form.addQueryItem(QStringLiteral("grant_type"), QStringLiteral("authorization_code"));
    form.addQueryItem(QStringLiteral("code_verifier"), QString::fromLatin1(exchange.verifier));
    pending->request_body = form.query(QUrl::FullyEncoded).toUtf8();
    pending_.insert(flow_id, pending);
    QNetworkRequest token_request = request(options_.token_endpoint);
    token_request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));
    pending->reply = network_->post(token_request, pending->request_body);
    connect(pending->reply, &QNetworkReply::readyRead, this, [this, flow_id] { read_response(flow_id); });
    connect(pending->reply, &QNetworkReply::finished, this, [this, flow_id] { token_finished(flow_id); });
}

void HttpOAuthProvider::get_userinfo(quint64 flow_id, const std::shared_ptr<Pending>& pending)
{
    pending->reply = network_->get(request(options_.userinfo_endpoint, pending->access_token));
    connect(pending->reply, &QNetworkReply::readyRead, this, [this, flow_id] { read_response(flow_id); });
    connect(pending->reply, &QNetworkReply::finished, this, [this, flow_id] { userinfo_finished(flow_id); });
}

void HttpOAuthProvider::read_response(quint64 flow_id)
{
    const auto pending = pending_.value(flow_id);
    if (!pending || pending->reply == nullptr) {
        return;
    }
    if (pending->response.size() + pending->reply->bytesAvailable() > options_.maximum_response_bytes) {
        pending->too_large = true;
        pending->reply->abort();
        return;
    }
    pending->response.append(pending->reply->readAll());
}

bool HttpOAuthProvider::response_json(Pending& pending, QJsonObject* object) const
{
    if (pending.reply == nullptr || pending.reply->error() != QNetworkReply::NoError) {
        return false;
    }
    if (!pending.too_large && pending.reply->bytesAvailable() > options_.maximum_response_bytes - pending.response.size()) {
        pending.too_large = true;
    } else if (!pending.too_large) {
        pending.response.append(pending.reply->readAll());
    }
    bool valid = !pending.too_large && pending.response.size() <= options_.maximum_response_bytes
        && pending.reply->error() == QNetworkReply::NoError
        && pending.reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 200;
    const QString content_type = pending.reply->header(QNetworkRequest::ContentTypeHeader).toString();
    valid                      = valid
        && (content_type.compare(QStringLiteral("application/json"), Qt::CaseInsensitive) == 0
            || content_type.startsWith(QStringLiteral("application/json;"), Qt::CaseInsensitive));
    valid = valid && protocol::detail::is_strict_json(pending.response);
    QJsonParseError parse_error;
    const QJsonDocument document = QJsonDocument::fromJson(pending.response, &parse_error);
    valid                        = valid && parse_error.error == QJsonParseError::NoError && document.isObject();
    if (valid) {
        *object = document.object();
    }
    wipe(pending.response);
    return valid;
}

void HttpOAuthProvider::token_finished(quint64 flow_id)
{
    const auto pending = pending_.value(flow_id);
    if (!pending) {
        return;
    }
    QJsonObject object;
    if (!response_json(*pending, &object)) {
        fail(flow_id);
        return;
    }
    pending->reply->deleteLater();
    pending->reply = nullptr;
    wipe(pending->request_body);

    const QByteArray access_token = object.value(QStringLiteral("access_token")).toString().toUtf8();
    const QString token_type      = object.value(QStringLiteral("token_type")).toString();
    if (!valid_access_token(access_token) || token_type.compare(QStringLiteral("bearer"), Qt::CaseInsensitive) != 0) {
        fail(flow_id);
        return;
    }
    pending->access_token = access_token;
    get_userinfo(flow_id, pending);
}

void HttpOAuthProvider::userinfo_finished(quint64 flow_id)
{
    const auto pending = pending_.take(flow_id);
    if (!pending) {
        return;
    }
    QJsonObject object;
    const bool valid = response_json(*pending, &object);
    pending->reply->deleteLater();
    pending->reply = nullptr;
    if (!valid) {
        fail(flow_id);
        return;
    }

    OAuthIdentity identity;
    identity.provider = configuration().id;
    if (options_.subject_type == UserInfoSubjectType::StringId) {
        identity.subject = object.value(QStringLiteral("id")).toString();
        if (identity.subject.isEmpty() || identity.subject.size() > 256 || identity.subject.trimmed() != identity.subject
            || std::any_of(identity.subject.cbegin(), identity.subject.cend(),
                [](QChar character) { return character.isSpace() || !character.isPrint() || character.unicode() > 0x7f; })) {
            fail(flow_id);
            return;
        }
    } else {
        const QJsonValue id = object.value(QStringLiteral("id"));
        const double number = id.toDouble();
        if (!id.isDouble() || !std::isfinite(number) || std::trunc(number) != number || number <= 0 || number > 9007199254740991.0) {
            fail(flow_id);
            return;
        }
        identity.subject = QString::number(static_cast<qint64>(number));
    }
    finish_exchange(OAuthExchangeResult { flow_id, identity, QString() });
}

void HttpOAuthProvider::fail(quint64 flow_id)
{
    const auto pending = pending_.take(flow_id);
    if (pending && pending->reply != nullptr) {
        pending->reply->abort();
        pending->reply->deleteLater();
    }
    finish_exchange(OAuthExchangeResult { flow_id, std::nullopt, QStringLiteral("OAuth provider sign-in failed") });
}

} // namespace tcp_chat::auth

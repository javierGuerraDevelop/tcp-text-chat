#include "auth/http_oauth_provider.h"
#include "auth/oauth_coordinator.h"
#include "auth/oauth_crypto.h"
#include "auth/oauth_provider_factory.h"

#include "oauth_http_test_server.h"

#include <QSignalSpy>
#include <QTest>
#include <QUrlQuery>

using namespace tcp_chat::auth;
using tcp_chat::testing::OAuthHttpResponse;
using tcp_chat::testing::OAuthHttpTestServer;

namespace {

/// Owns a local HTTPS provider and its configured client.
class ProviderHarness {
public:
    /// Configures production-shaped options with loopback endpoints and selectable test-CA trust.
    explicit ProviderHarness(HttpOAuthProviderOptions options, bool trust_server = true)
    {
        if (!server.start()) {
            return;
        }
        options.token_endpoint    = server.endpoint(QStringLiteral("/token"));
        options.userinfo_endpoint = server.endpoint(QStringLiteral("/userinfo"));
        if (trust_server) {
            options.tls_configuration.setCaCertificates(QSslCertificate::fromPath(
                QStringLiteral(TCP_CHAT_SOURCE_DIR "/tests/tls_fixtures/trusted_ca.crt"), QSsl::Pem));
        }
        provider = std::make_shared<HttpOAuthProvider>(options);
        qRegisterMetaType<OAuthExchangeResult>("tcp_chat::auth::OAuthExchangeResult");
        const QString provider_id = options.configuration.id;
        server.handler            = [provider_id](const tcp_chat::testing::OAuthHttpRequest& request) {
            if (request.target == QByteArrayLiteral("/token")) {
                return OAuthHttpResponse { 200, QByteArrayLiteral("application/json"),
                    QByteArrayLiteral("{\"access_token\":\"test-access-token\",\"token_type\":\"Bearer\","
                                      "\"refresh_token\":\"discard-refresh\",\"id_token\":\"not-an-identity\"}") };
            }
            if (request.headers.value(QByteArrayLiteral("authorization")) != QByteArrayLiteral("Bearer test-access-token")) {
                return OAuthHttpResponse { 401 };
            }
            if (provider_id == QStringLiteral("google")) {
                return OAuthHttpResponse { 200, QByteArrayLiteral("application/json"),
                    QByteArrayLiteral("{\"id\":\"google-user-123\",\"email\":\"not-used@example.invalid\"}") };
            }
            return OAuthHttpResponse { 200, QByteArrayLiteral("application/json"), QByteArrayLiteral("{\"id\":12345}") };
        };
    }

    /// Returns whether the local provider and configuration are ready.
    bool ready() const
    {
        return provider != nullptr && !provider->configuration_error().has_value();
    }

    /// Runs one valid authorization-code exchange through both HTTPS requests.
    std::optional<OAuthExchangeResult> exchange()
    {
        QSignalSpy completed(provider.get(), &OAuthProvider::exchange_finished);
        OAuthExchange request;
        request.code         = QByteArrayLiteral("valid-code");
        request.verifier     = QByteArrayLiteral("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        request.redirect_uri = QUrl(QStringLiteral("https://chat.example.invalid/oauth/callback"));
        provider->exchange(7, request);
        if (completed.isEmpty() && !completed.wait(5000)) {
            return std::nullopt;
        }
        return qvariant_cast<OAuthExchangeResult>(completed.at(0).at(0));
    }

    OAuthHttpTestServer server;
    std::shared_ptr<HttpOAuthProvider> provider;
};

/// Returns one decoded form field from a token request.
QString form_value(const tcp_chat::testing::OAuthHttpRequest& request, const QString& name)
{
    return QUrlQuery(QString::fromUtf8(request.body)).queryItemValue(name);
}

} // namespace

/// Verifies production OAuth providers against bounded local HTTPS endpoints.
class HttpOAuthProviderTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks Google code exchange, PKCE, scope, and stable string identity.
    void googleUserInfo();
    /// Checks GitHub code exchange, PKCE, scope, and numeric identity.
    void githubUserInfo();
    /// Checks safe errors for provider denial and bad responses.
    void rejectsProviderFailures();
    /// Checks strict token and UserInfo response validation.
    void rejectsMalformedResponses();
    /// Checks redirects, oversized responses, timeouts, and untrusted certificates.
    void enforcesNetworkSecurity();
    /// Checks endpoint, credential, TLS, and identity-source validation.
    void validatesConfiguration();
    /// Checks a real HTTP provider through coordinator state and handoff redemption.
    void integratesWithCoordinator();
};

void HttpOAuthProviderTest::googleUserInfo()
{
    ProviderHarness harness(google_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret")));
    QVERIFY(harness.ready());
    const auto result = harness.exchange();
    QVERIFY(result.has_value());
    QVERIFY(result->identity.has_value());
    QCOMPARE(result->identity->provider, QStringLiteral("google"));
    QCOMPARE(result->identity->subject, QStringLiteral("google-user-123"));
    QVERIFY(result->identity->issuer.isEmpty());
    QVERIFY(result->identity->audience.isEmpty());
    QVERIFY(result->identity->nonce.isEmpty());
    QCOMPARE(harness.server.requests.size(), 2);
    const auto& token = harness.server.requests.at(0);
    QCOMPARE(token.method, QByteArrayLiteral("POST"));
    QVERIFY2(form_value(token, QStringLiteral("client_id")) == QStringLiteral("test-client"), token.body.constData());
    QCOMPARE(form_value(token, QStringLiteral("client_secret")), QStringLiteral("test-secret"));
    QCOMPARE(form_value(token, QStringLiteral("code")), QStringLiteral("valid-code"));
    QCOMPARE(form_value(token, QStringLiteral("grant_type")), QStringLiteral("authorization_code"));
    QCOMPARE(form_value(token, QStringLiteral("redirect_uri")), QStringLiteral("https://chat.example.invalid/oauth/callback"));
    QCOMPARE(form_value(token, QStringLiteral("code_verifier")), QStringLiteral("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    QCOMPARE(harness.server.requests.at(1).method, QByteArrayLiteral("GET"));
    QVERIFY(harness.server.requests.at(1).body.isEmpty());

    OAuthAuthorizationRequest request;
    request.state          = QByteArrayLiteral("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    request.code_challenge = request.state;
    request.redirect_uri   = QUrl(QStringLiteral("https://chat.example.invalid/oauth/callback"));
    const auto url         = harness.provider->authorization_url(request);
    QVERIFY(url.has_value());
    const QUrlQuery query(*url);
    QCOMPARE(query.queryItemValue(QStringLiteral("scope")), QStringLiteral("https://www.googleapis.com/auth/userinfo.profile"));
    QVERIFY(!query.hasQueryItem(QStringLiteral("nonce")));
    QVERIFY(!query.hasQueryItem(QStringLiteral("access_type")));
    QVERIFY(!url->toString().contains(QStringLiteral("test-secret")));
}

void HttpOAuthProviderTest::githubUserInfo()
{
    ProviderHarness harness(github_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret")));
    QVERIFY(harness.ready());
    const auto result = harness.exchange();
    QVERIFY(result.has_value());
    QVERIFY(result->identity.has_value());
    QCOMPARE(result->identity->provider, QStringLiteral("github"));
    QCOMPARE(result->identity->subject, QStringLiteral("12345"));
    QVERIFY(result->identity->issuer.isEmpty());
    QVERIFY(result->identity->audience.isEmpty());
    QCOMPARE(harness.server.requests.size(), 2);
    QCOMPARE(form_value(harness.server.requests.at(0), QStringLiteral("client_secret")), QStringLiteral("test-secret"));
    QCOMPARE(form_value(harness.server.requests.at(0), QStringLiteral("code_verifier")), QStringLiteral("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));

    OAuthAuthorizationRequest request;
    request.state          = QByteArrayLiteral("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    request.code_challenge = request.state;
    request.redirect_uri   = QUrl(QStringLiteral("https://chat.example.invalid/oauth/callback"));
    const auto url         = harness.provider->authorization_url(request);
    QVERIFY(url.has_value());
    QCOMPARE(QUrlQuery(*url).queryItemValue(QStringLiteral("scope")), QStringLiteral("read:user"));
    QVERIFY(!QUrlQuery(*url).hasQueryItem(QStringLiteral("nonce")));
}

void HttpOAuthProviderTest::rejectsProviderFailures()
{
    ProviderHarness harness(google_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret")));
    QVERIFY(harness.ready());
    harness.server.handler = [](const tcp_chat::testing::OAuthHttpRequest&) {
        return OAuthHttpResponse { 401, QByteArrayLiteral("application/json"), QByteArrayLiteral("{\"error\":\"invalid_grant\"}") };
    };
    const auto result = harness.exchange();
    QVERIFY(result.has_value());
    QVERIFY(!result->identity.has_value());
    QCOMPARE(result->error, QStringLiteral("OAuth provider sign-in failed"));
    QVERIFY(!result->error.contains(QStringLiteral("invalid_grant")));
    QCOMPARE(harness.server.requests.size(), 1);
}

void HttpOAuthProviderTest::rejectsMalformedResponses()
{
    const QList<QPair<OAuthHttpResponse, OAuthHttpResponse>> cases = {
        { { 200, QByteArrayLiteral("application/json"), QByteArrayLiteral("not-json") }, { } },
        { { 200, QByteArrayLiteral("text/plain"), QByteArrayLiteral("{}") }, { } },
        { { 200, QByteArrayLiteral("application/json"),
              QByteArrayLiteral("{\"access_token\":\"one\",\"access_token\":\"two\",\"token_type\":\"Bearer\"}") },
            { } },
        { { 200, QByteArrayLiteral("application/json"), QByteArrayLiteral("{\"access_token\":\"\",\"token_type\":\"Bearer\"}") }, { } },
        { { 200, QByteArrayLiteral("application/json"), QByteArrayLiteral("{\"access_token\":\"token\",\"token_type\":\"Basic\"}") }, { } },
        { { }, { 200, QByteArrayLiteral("application/json"), QByteArrayLiteral("{\"id\":\"\"}") } },
        { { }, { 200, QByteArrayLiteral("application/json"), QByteArrayLiteral("{\"id\":12345}") } },
    };
    for (const auto& test : cases) {
        ProviderHarness harness(google_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret")));
        QVERIFY(harness.ready());
        harness.server.handler = [test](const tcp_chat::testing::OAuthHttpRequest& request) {
            if (request.target == QByteArrayLiteral("/token") && test.first.body.isEmpty()) {
                return OAuthHttpResponse { 200, QByteArrayLiteral("application/json"),
                    QByteArrayLiteral("{\"access_token\":\"test-access-token\",\"token_type\":\"Bearer\"}") };
            }
            return request.target == QByteArrayLiteral("/token") && !test.first.body.isEmpty() ? test.first : test.second;
        };
        const auto result = harness.exchange();
        QVERIFY(result.has_value());
        QVERIFY(!result->identity.has_value());
    }

    ProviderHarness github(github_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret")));
    QVERIFY(github.ready());
    github.server.handler = [](const tcp_chat::testing::OAuthHttpRequest& request) {
        if (request.target == QByteArrayLiteral("/token")) {
            return OAuthHttpResponse { 200, QByteArrayLiteral("application/json"),
                QByteArrayLiteral("{\"access_token\":\"test-access-token\",\"token_type\":\"Bearer\"}") };
        }
        return OAuthHttpResponse { 200, QByteArrayLiteral("application/json"), QByteArrayLiteral("{\"id\":\"12345\"}") };
    };
    QVERIFY(!github.exchange()->identity.has_value());
}

void HttpOAuthProviderTest::enforcesNetworkSecurity()
{
    ProviderHarness oversized(google_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret")));
    QVERIFY(oversized.ready());
    oversized.server.handler = [](const tcp_chat::testing::OAuthHttpRequest&) {
        return OAuthHttpResponse { 200, QByteArrayLiteral("application/json"), QByteArray(70000, 'x') };
    };
    QVERIFY(!oversized.exchange()->identity.has_value());

    ProviderHarness redirect(google_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret")));
    QVERIFY(redirect.ready());
    redirect.server.handler = [](const tcp_chat::testing::OAuthHttpRequest&) {
        OAuthHttpResponse response { 302 };
        response.headers.insert(QByteArrayLiteral("Location"), QByteArrayLiteral("https://attacker.invalid/token"));
        return response;
    };
    QVERIFY(!redirect.exchange()->identity.has_value());
    QCOMPARE(redirect.server.requests.size(), 1);

    auto timeout_options               = google_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret"));
    timeout_options.request_timeout_ms = 1;
    ProviderHarness timeout(timeout_options);
    QVERIFY(timeout.ready());
    timeout.server.stall = true;
    QVERIFY(!timeout.exchange()->identity.has_value());

    auto untrusted_options              = google_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret"));
    untrusted_options.tls_configuration = QSslConfiguration::defaultConfiguration();
    ProviderHarness untrusted(untrusted_options, false);
    QVERIFY(untrusted.ready());
    QVERIFY(!untrusted.exchange()->identity.has_value());
    QCOMPARE(untrusted.server.requests.size(), 0);
}

void HttpOAuthProviderTest::validatesConfiguration()
{
    auto options = google_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret"));
    HttpOAuthProvider provider(options);
    QVERIFY(!provider.configuration_error().has_value());
    options.token_endpoint = QUrl(QStringLiteral("http://insecure.invalid/token"));
    HttpOAuthProvider insecure(options);
    QVERIFY(insecure.configuration_error().has_value());
    options = google_oauth_provider_options(QStringLiteral("test-client"), QByteArray());
    HttpOAuthProvider missing_secret(options);
    QVERIFY(missing_secret.configuration_error().has_value());
    options = google_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret"));
    options.tls_configuration.setPeerVerifyMode(QSslSocket::VerifyNone);
    HttpOAuthProvider unverified(options);
    QVERIFY(unverified.configuration_error().has_value());
    options                         = google_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret"));
    options.configuration.use_nonce = true;
    HttpOAuthProvider unexpected_nonce(options);
    QVERIFY(unexpected_nonce.configuration_error().has_value());
}

void HttpOAuthProviderTest::integratesWithCoordinator()
{
    ProviderHarness harness(google_oauth_provider_options(QStringLiteral("test-client"), QByteArrayLiteral("test-secret")));
    QVERIFY(harness.ready());
    const QUrl callback(QStringLiteral("https://chat.example.invalid/oauth/callback"));
    OAuthCoordinator coordinator(callback);
    QString error;
    QVERIFY(coordinator.add_provider(harness.provider, &error));
    const auto started = coordinator.start(9, QStringLiteral("google"), &error);
    QVERIFY(started.has_value());
    const QUrlQuery authorization(started->authorization_url);
    const QString state = authorization.queryItemValue(QStringLiteral("state"));
    QSignalSpy accounts(&coordinator, &OAuthCoordinator::account_resolution_requested);
    coordinator.authorization_received(state, QStringLiteral("valid-code"), QString());
    QTRY_COMPARE(accounts.size(), 1);
    QCOMPARE(harness.server.requests.size(), 2);
    QCOMPARE(form_value(harness.server.requests.at(0), QStringLiteral("redirect_uri")), callback.toString());
    QCOMPARE(pkce_s256_challenge(form_value(harness.server.requests.at(0), QStringLiteral("code_verifier"))),
        std::optional<QByteArray> { authorization.queryItemValue(QStringLiteral("code_challenge")).toLatin1() });
    coordinator.account_resolved(accounts.at(0).at(0).toULongLong(), 42, false);
    const auto ready = coordinator.status(9, started->flow_handle);
    QVERIFY(ready.has_value());
    QCOMPARE(ready->status, OAuthFlowStatus::Ready);
    QCOMPARE(coordinator.redeem(9, started->flow_handle, ready->handoff), std::optional<qint64> { 42 });
    coordinator.authorization_received(state, QStringLiteral("valid-code"), QString());
    QCOMPARE(harness.server.requests.size(), 2);
}

QTEST_GUILESS_MAIN(HttpOAuthProviderTest)

#include "test_http_oauth_provider.moc"

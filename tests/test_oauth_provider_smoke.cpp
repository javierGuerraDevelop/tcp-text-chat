#include "auth/oauth_provider_factory.h"

#include <QSignalSpy>
#include <QTest>

using namespace tcp_chat::auth;

/// Exercises a manually authorized real provider exchange only when explicitly configured.
class OAuthProviderSmokeTest : public QObject {
    Q_OBJECT

private slots:
    /// Requires an explicit opt-in before any external network access.
    void initTestCase();
    /// Exchanges a fresh manually obtained code and verifies a nonempty provider identity.
    void exchangesRealAuthorizationCode();
};

void OAuthProviderSmokeTest::initTestCase()
{
    if (qEnvironmentVariable("TCP_CHAT_OAUTH_SMOKE") != QStringLiteral("1")) {
        QSKIP("Set TCP_CHAT_OAUTH_SMOKE=1 and explicit smoke credentials to enable external requests");
    }
}

void OAuthProviderSmokeTest::exchangesRealAuthorizationCode()
{
    const QString selected    = qEnvironmentVariable("TCP_CHAT_OAUTH_SMOKE_PROVIDER");
    const QByteArray code     = qgetenv("TCP_CHAT_OAUTH_SMOKE_CODE");
    const QByteArray verifier = qgetenv("TCP_CHAT_OAUTH_SMOKE_VERIFIER");
    const QUrl redirect       = QUrl(QString::fromUtf8(qgetenv("TCP_CHAT_OAUTH_SMOKE_REDIRECT_URI")));
    if ((selected != QStringLiteral("google") && selected != QStringLiteral("github")) || code.isEmpty() || verifier.isEmpty()
        || !redirect.isValid()) {
        QSKIP("Set the smoke provider, fresh code, PKCE verifier, and exact redirect URI");
    }

    QList<std::shared_ptr<OAuthProvider>> providers;
    QVERIFY2(!load_oauth_providers_from_environment(&providers).has_value(), "Provider credential configuration is incomplete or invalid");
    std::shared_ptr<OAuthProvider> provider;
    for (const auto& candidate : providers) {
        if (candidate->configuration().id == selected) {
            provider = candidate;
        }
    }
    QVERIFY(provider != nullptr);
    QSignalSpy completed(provider.get(), &OAuthProvider::exchange_finished);
    OAuthExchange request;
    request.code         = code;
    request.verifier     = verifier;
    request.redirect_uri = redirect;
    provider->exchange(1, request);
    QVERIFY(completed.wait(30000) || !completed.isEmpty());
    const auto result = qvariant_cast<OAuthExchangeResult>(completed.at(0).at(0));
    QVERIFY2(result.identity.has_value(), "The provider did not accept the one-time smoke exchange");
    QVERIFY(!result.identity->subject.isEmpty());
    QCOMPARE(result.identity->provider, selected);
}

QTEST_GUILESS_MAIN(OAuthProviderSmokeTest)

#include "test_oauth_provider_smoke.moc"

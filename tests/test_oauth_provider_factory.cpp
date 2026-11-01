#include "auth/oauth_provider_factory.h"

#include <QTest>
#include <QUrlQuery>

using namespace tcp_chat::auth;

namespace {

/// Restores all provider variables after a test and clears them on demand.
class ProviderEnvironment {
public:
    /// Saves current values and removes provider configuration for isolation.
    ProviderEnvironment()
    {
        for (const auto& name : names_) {
            values_.append(qgetenv(name.constData()));
            present_.append(qEnvironmentVariableIsSet(name.constData()));
        }
        clear();
    }

    /// Restores each original variable without printing its contents.
    ~ProviderEnvironment()
    {
        for (qsizetype index = 0; index < names_.size(); ++index) {
            if (present_.at(index)) {
                qputenv(names_.at(index).constData(), values_.at(index));
            } else {
                qunsetenv(names_.at(index).constData());
            }
        }
    }

    /// Clears all provider variables between error cases.
    void clear()
    {
        for (const auto& name : names_) {
            qunsetenv(name.constData());
        }
    }

private:
    const QList<QByteArray> names_ = {
        QByteArrayLiteral("TCP_CHAT_GOOGLE_CLIENT_ID"),
        QByteArrayLiteral("TCP_CHAT_GOOGLE_CLIENT_SECRET"),
        QByteArrayLiteral("TCP_CHAT_GITHUB_CLIENT_ID"),
        QByteArrayLiteral("TCP_CHAT_GITHUB_CLIENT_SECRET"),
    };
    QList<QByteArray> values_;
    QList<bool> present_;
};

} // namespace

/// Verifies environment-only production provider configuration.
class OAuthProviderFactoryTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks absent variables and incomplete or empty pairs.
    void validatesCredentialPairs();
    /// Checks production endpoints, scopes, and non-secret authorization URLs.
    void loadsProductionProviders();
    /// Checks invalid IDs and missing output destinations without leaking values.
    void reportsSafeConfigurationErrors();
};

void OAuthProviderFactoryTest::validatesCredentialPairs()
{
    ProviderEnvironment environment;
    QList<std::shared_ptr<OAuthProvider>> providers;
    QVERIFY(!load_oauth_providers_from_environment(&providers).has_value());
    QVERIFY(providers.isEmpty());

    qputenv("TCP_CHAT_GOOGLE_CLIENT_ID", QByteArrayLiteral("test-client"));
    auto error = load_oauth_providers_from_environment(&providers);
    QVERIFY(error.has_value());
    QVERIFY(error->contains(QStringLiteral("TCP_CHAT_GOOGLE_CLIENT_SECRET")));
    environment.clear();
    qputenv("TCP_CHAT_GITHUB_CLIENT_SECRET", QByteArrayLiteral("test-secret"));
    error = load_oauth_providers_from_environment(&providers);
    QVERIFY(error.has_value());
    QVERIFY(error->contains(QStringLiteral("TCP_CHAT_GITHUB_CLIENT_ID")));
    environment.clear();
    qputenv("TCP_CHAT_GOOGLE_CLIENT_ID", QByteArray());
    qputenv("TCP_CHAT_GOOGLE_CLIENT_SECRET", QByteArray());
    error = load_oauth_providers_from_environment(&providers);
    QVERIFY(error.has_value());
    QVERIFY(providers.isEmpty());
}

void OAuthProviderFactoryTest::loadsProductionProviders()
{
    ProviderEnvironment environment;
    qputenv("TCP_CHAT_GOOGLE_CLIENT_ID", QByteArrayLiteral("google-client"));
    qputenv("TCP_CHAT_GOOGLE_CLIENT_SECRET", QByteArrayLiteral("google-test-secret"));
    qputenv("TCP_CHAT_GITHUB_CLIENT_ID", QByteArrayLiteral("github-client"));
    qputenv("TCP_CHAT_GITHUB_CLIENT_SECRET", QByteArrayLiteral("github-test-secret"));
    QList<std::shared_ptr<OAuthProvider>> providers;
    QVERIFY(!load_oauth_providers_from_environment(&providers).has_value());
    QCOMPARE(providers.size(), 2);
    QCOMPARE(providers.at(0)->configuration().id, QStringLiteral("google"));
    QCOMPARE(providers.at(1)->configuration().id, QStringLiteral("github"));
    QCOMPARE(providers.at(0)->configuration().identity_source, OAuthIdentitySource::UserInfo);
    QCOMPARE(providers.at(1)->configuration().identity_source, OAuthIdentitySource::UserInfo);
    QCOMPARE(providers.at(0)->configuration().authorization_endpoint, QUrl(QStringLiteral("https://accounts.google.com/o/oauth2/v2/auth")));
    QCOMPARE(providers.at(1)->configuration().authorization_endpoint, QUrl(QStringLiteral("https://github.com/login/oauth/authorize")));

    OAuthAuthorizationRequest request;
    request.state          = QByteArrayLiteral("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    request.code_challenge = request.state;
    request.redirect_uri   = QUrl(QStringLiteral("https://chat.example.invalid/oauth/callback"));
    const auto google      = providers.at(0)->authorization_url(request);
    const auto github      = providers.at(1)->authorization_url(request);
    QVERIFY(google.has_value());
    QVERIFY(github.has_value());
    QCOMPARE(QUrlQuery(*google).queryItemValue(QStringLiteral("scope")), QStringLiteral("https://www.googleapis.com/auth/userinfo.profile"));
    QCOMPARE(QUrlQuery(*github).queryItemValue(QStringLiteral("scope")), QStringLiteral("read:user"));
    QVERIFY(!google->toString().contains(QStringLiteral("google-test-secret")));
    QVERIFY(!github->toString().contains(QStringLiteral("github-test-secret")));
}

void OAuthProviderFactoryTest::reportsSafeConfigurationErrors()
{
    ProviderEnvironment environment;
    qputenv("TCP_CHAT_GOOGLE_CLIENT_ID", QByteArrayLiteral("bad client"));
    qputenv("TCP_CHAT_GOOGLE_CLIENT_SECRET", QByteArrayLiteral("test-secret"));
    QList<std::shared_ptr<OAuthProvider>> providers;
    const auto error = load_oauth_providers_from_environment(&providers);
    QVERIFY(error.has_value());
    QVERIFY(error->contains(QStringLiteral("TCP_CHAT_GOOGLE_CLIENT_ID")));
    QVERIFY(!error->contains(QStringLiteral("bad client")));
    QVERIFY(!error->contains(QStringLiteral("test-secret")));
    QVERIFY(load_oauth_providers_from_environment(nullptr).has_value());
}

QTEST_GUILESS_MAIN(OAuthProviderFactoryTest)

#include "test_oauth_provider_factory.moc"

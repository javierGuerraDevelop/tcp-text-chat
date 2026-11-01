#include "auth/oauth_coordinator.h"

#include "oauth_test_provider.h"
#include "tcp_chat/auth_protocol.h"

#include <QSignalSpy>
#include <QTest>
#include <QUrlQuery>

using namespace tcp_chat::auth;

/// Verifies OAuth provider parameters, state, identity, expiry, and handoff handling.
class OAuthCoordinatorTest : public QObject {
    Q_OBJECT

    QString error;

private slots:
    /// Checks the published RFC 7636 S256 example.
    void pkceVector();
    /// Checks exact authorization parameters and callback binding.
    void authorizationRequest();
    /// Checks wrong issuer, audience, nonce, and provider exchange denial.
    void rejectsInvalidIdentity();
    /// Checks successful provisioning, owner binding, and atomic redemption.
    void redeemsHandoffOnce();
    /// Checks denial, unknown state, and callback replay.
    void rejectsCallbackReplayAndDenial();
    /// Checks fake-clock expiration and late provider replies.
    void expiresFlowsAndHandoffs();
    /// Checks disconnect cancellation and global flow bounds.
    void boundsAndCancelsFlows();
    /// Checks generated username conflicts are retried without identity merging.
    void retriesUsernameConflicts();
};

void OAuthCoordinatorTest::pkceVector()
{
    const auto challenge = pkce_s256_challenge(QStringLiteral("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    QVERIFY(challenge.has_value());
    QCOMPARE(*challenge, QByteArrayLiteral("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
    QVERIFY(!pkce_s256_challenge(QStringLiteral("short")).has_value());
    const auto token = generate_oauth_token();
    QVERIFY(token.has_value());
    QCOMPARE(token->value.size(), 43);
    QVERIFY(digest_oauth_token(token->value).has_value());
    QVERIFY(constant_time_equal(token->digest, token->digest));
    QVERIFY(!constant_time_equal(token->digest, QByteArray(32, '\0')));
}

void OAuthCoordinatorTest::authorizationRequest()
{
    OAuthCoordinator coordinator(QUrl(QStringLiteral("https://localhost:4443/oauth/callback")));
    auto provider = std::make_shared<FakeOAuthProvider>(fake_provider_configuration());
    QString error;
    QVERIFY(coordinator.add_provider(provider, &error));
    const auto started = coordinator.start(7, QStringLiteral("fake"), &error);
    QVERIFY(started.has_value());
    const QUrlQuery query(started->authorization_url);
    QCOMPARE(query.queryItemValue(QStringLiteral("response_type")), QStringLiteral("code"));
    QCOMPARE(query.queryItemValue(QStringLiteral("client_id")), QStringLiteral("test-client"));
    QCOMPARE(query.queryItemValue(QStringLiteral("redirect_uri")), QStringLiteral("https://localhost:4443/oauth/callback"));
    QCOMPARE(query.queryItemValue(QStringLiteral("code_challenge_method")), QStringLiteral("S256"));
    QVERIFY(!query.queryItemValue(QStringLiteral("nonce")).isEmpty());
    QCOMPARE(started->expires_at - QDateTime::currentMSecsSinceEpoch() <= 300000, true);
    QVERIFY(!coordinator.start(7, QStringLiteral("fake"), &error).has_value());
    QVERIFY(!coordinator.start(7, QStringLiteral("unknown"), &error).has_value());

    OAuthProviderConfiguration invalid = fake_provider_configuration();
    invalid.authorization_endpoint     = QUrl(QStringLiteral("http://provider.invalid/authorize"));
    FakeOAuthProvider insecure(invalid);
    QVERIFY(insecure.configuration_error().has_value());
    QVERIFY(!insecure.authorization_url(OAuthAuthorizationRequest { }).has_value());
}

void OAuthCoordinatorTest::rejectsInvalidIdentity()
{
    const QList<FakeOAuthProvider::ClaimMode> modes = { FakeOAuthProvider::ClaimMode::WrongIssuer,
        FakeOAuthProvider::ClaimMode::WrongAudience, FakeOAuthProvider::ClaimMode::WrongNonce };
    for (const auto mode : modes) {
        qint64 current = 1000;
        OAuthCoordinatorOptions options;
        options.clock = [&current] { return current; };
        OAuthCoordinator coordinator(QUrl(QStringLiteral("https://localhost:4443/oauth/callback")), options);
        auto provider        = std::make_shared<FakeOAuthProvider>(fake_provider_configuration());
        provider->claim_mode = mode;
        QVERIFY(coordinator.add_provider(provider, &error));
        QSignalSpy accounts(&coordinator, &OAuthCoordinator::account_resolution_requested);
        const auto started = coordinator.start(1, QStringLiteral("fake"), &error);
        QVERIFY(started.has_value());
        const QUrlQuery query(started->authorization_url);
        provider->expected_challenge = query.queryItemValue(QStringLiteral("code_challenge")).toLatin1();
        provider->expected_redirect  = QUrl(QStringLiteral("https://localhost:4443/oauth/callback"));
        coordinator.authorization_received(query.queryItemValue(QStringLiteral("state")), QStringLiteral("valid-code"), QString());
        QTRY_VERIFY(coordinator.status(1, started->flow_handle).has_value());
        QTRY_COMPARE(coordinator.status(1, started->flow_handle)->status, OAuthFlowStatus::Failed);
        QCOMPARE(accounts.size(), 0);
    }

    OAuthCoordinator coordinator(QUrl(QStringLiteral("https://localhost:4443/oauth/callback")));
    auto provider             = std::make_shared<FakeOAuthProvider>(fake_provider_configuration());
    provider->reject_exchange = true;
    QVERIFY(coordinator.add_provider(provider, &error));
    const auto started = coordinator.start(1, QStringLiteral("fake"), &error);
    QVERIFY(started.has_value());
    coordinator.authorization_received(QUrlQuery(started->authorization_url).queryItemValue(QStringLiteral("state")),
        QStringLiteral("wrong-code"), QString());
    QTRY_COMPARE(coordinator.status(1, started->flow_handle)->status, OAuthFlowStatus::Failed);
}

void OAuthCoordinatorTest::redeemsHandoffOnce()
{
    qint64 current = 1000;
    OAuthCoordinatorOptions options;
    options.clock = [&current] { return current; };
    OAuthCoordinator coordinator(QUrl(QStringLiteral("https://localhost:4443/oauth/callback")), options);
    auto provider = std::make_shared<FakeOAuthProvider>(fake_provider_configuration());
    QVERIFY(coordinator.add_provider(provider, &error));
    QSignalSpy accounts(&coordinator, &OAuthCoordinator::account_resolution_requested);
    const auto started = coordinator.start(10, QStringLiteral("fake"), &error);
    QVERIFY(started.has_value());
    const QUrlQuery query(started->authorization_url);
    provider->expected_challenge = query.queryItemValue(QStringLiteral("code_challenge")).toLatin1();
    provider->expected_redirect  = QUrl(QStringLiteral("https://localhost:4443/oauth/callback"));
    coordinator.authorization_received(query.queryItemValue(QStringLiteral("state")), QStringLiteral("valid-code"), QString());
    QTRY_COMPARE(accounts.size(), 1);
    QCOMPARE(accounts.at(0).at(1).toString(), QStringLiteral("fake"));
    QCOMPARE(accounts.at(0).at(2).toString(), QStringLiteral("provider-subject-123"));
    const QString username = accounts.at(0).at(3).toString();
    QVERIFY(tcp_chat::protocol::normalize_username(username).has_value());
    coordinator.account_resolved(accounts.at(0).at(0).toULongLong(), 42, false);
    const auto ready = coordinator.status(10, started->flow_handle);
    QVERIFY(ready.has_value());
    QCOMPARE(ready->status, OAuthFlowStatus::Ready);
    QVERIFY(!ready->handoff.isEmpty());
    QVERIFY(!coordinator.redeem(11, started->flow_handle, ready->handoff).has_value());
    const auto wrong = generate_oauth_token();
    QVERIFY(!coordinator.redeem(10, started->flow_handle, wrong->value).has_value());
    QCOMPARE(coordinator.redeem(10, started->flow_handle, ready->handoff), std::optional<qint64> { 42 });
    QVERIFY(!coordinator.redeem(10, started->flow_handle, ready->handoff).has_value());
    QVERIFY(!coordinator.status(10, started->flow_handle).has_value());
}

void OAuthCoordinatorTest::rejectsCallbackReplayAndDenial()
{
    OAuthCoordinator coordinator(QUrl(QStringLiteral("https://localhost:4443/oauth/callback")));
    auto provider = std::make_shared<FakeOAuthProvider>(fake_provider_configuration());
    QVERIFY(coordinator.add_provider(provider, &error));
    const auto started = coordinator.start(1, QStringLiteral("fake"), &error);
    QVERIFY(started.has_value());
    const QString state = QUrlQuery(started->authorization_url).queryItemValue(QStringLiteral("state"));
    coordinator.authorization_received(state, QString(), QStringLiteral("access_denied"));
    coordinator.authorization_received(state, QStringLiteral("valid-code"), QString());
    coordinator.authorization_received(QStringLiteral("unknown"), QStringLiteral("valid-code"), QString());
    QCOMPARE(provider->exchanges, 0);
    QCOMPARE(coordinator.status(1, started->flow_handle)->status, OAuthFlowStatus::Failed);
}

void OAuthCoordinatorTest::expiresFlowsAndHandoffs()
{
    qint64 current = 1000;
    OAuthCoordinatorOptions options;
    options.flow_lifetime_ms    = 500;
    options.handoff_lifetime_ms = 50;
    options.clock               = [&current] { return current; };
    OAuthCoordinator coordinator(QUrl(QStringLiteral("https://localhost:4443/oauth/callback")), options);
    auto provider = std::make_shared<FakeOAuthProvider>(fake_provider_configuration());
    QVERIFY(coordinator.add_provider(provider, &error));
    QSignalSpy accounts(&coordinator, &OAuthCoordinator::account_resolution_requested);
    const auto expired = coordinator.start(1, QStringLiteral("fake"), &error);
    QVERIFY(expired.has_value());
    current = 1500;
    coordinator.check_expirations();
    QVERIFY(!coordinator.status(1, expired->flow_handle).has_value());

    current            = 2000;
    const auto started = coordinator.start(1, QStringLiteral("fake"), &error);
    QVERIFY(started.has_value());
    const QUrlQuery query(started->authorization_url);
    provider->expected_challenge = query.queryItemValue(QStringLiteral("code_challenge")).toLatin1();
    provider->expected_redirect  = QUrl(QStringLiteral("https://localhost:4443/oauth/callback"));
    coordinator.authorization_received(query.queryItemValue(QStringLiteral("state")), QStringLiteral("valid-code"), QString());
    QTRY_COMPARE(accounts.size(), 1);
    coordinator.account_resolved(accounts.at(0).at(0).toULongLong(), 42, false);
    const auto ready = coordinator.status(1, started->flow_handle);
    QVERIFY(ready.has_value());
    QCOMPARE(ready->expires_at, 2050);
    current = 2050;
    QVERIFY(!coordinator.redeem(1, started->flow_handle, ready->handoff).has_value());

    current         = 3000;
    const auto late = coordinator.start(2, QStringLiteral("fake"), &error);
    QVERIFY(late.has_value());
    coordinator.authorization_received(QUrlQuery(late->authorization_url).queryItemValue(QStringLiteral("state")),
        QStringLiteral("valid-code"), QString());
    current = 3500;
    coordinator.check_expirations();
    QTRY_COMPARE(provider->exchanges, 2);
    QCOMPARE(accounts.size(), 1);
}

void OAuthCoordinatorTest::boundsAndCancelsFlows()
{
    OAuthCoordinatorOptions options;
    options.maximum_flows = 1;
    OAuthCoordinator coordinator(QUrl(QStringLiteral("https://localhost:4443/oauth/callback")), options);
    auto provider = std::make_shared<FakeOAuthProvider>(fake_provider_configuration());
    QVERIFY(coordinator.add_provider(provider, &error));
    const auto started = coordinator.start(1, QStringLiteral("fake"), &error);
    QVERIFY(started.has_value());
    QCOMPARE(coordinator.connection_deadline(1), started->expires_at);
    QVERIFY(!coordinator.start(2, QStringLiteral("fake"), &error).has_value());
    coordinator.cancel_connection(1);
    QVERIFY(!coordinator.status(1, started->flow_handle).has_value());
    QCOMPARE(coordinator.connection_deadline(1), 0);
    QVERIFY(coordinator.start(2, QStringLiteral("fake"), &error).has_value());
}

void OAuthCoordinatorTest::retriesUsernameConflicts()
{
    OAuthCoordinator coordinator(QUrl(QStringLiteral("https://localhost:4443/oauth/callback")));
    auto provider = std::make_shared<FakeOAuthProvider>(fake_provider_configuration());
    QVERIFY(coordinator.add_provider(provider, &error));
    QSignalSpy accounts(&coordinator, &OAuthCoordinator::account_resolution_requested);
    const auto started = coordinator.start(1, QStringLiteral("fake"), &error);
    QVERIFY(started.has_value());
    const QUrlQuery query(started->authorization_url);
    provider->expected_challenge = query.queryItemValue(QStringLiteral("code_challenge")).toLatin1();
    provider->expected_redirect  = QUrl(QStringLiteral("https://localhost:4443/oauth/callback"));
    coordinator.authorization_received(query.queryItemValue(QStringLiteral("state")), QStringLiteral("valid-code"), QString());
    QTRY_COMPARE(accounts.size(), 1);
    const quint64 id = accounts.at(0).at(0).toULongLong();
    for (int attempt = 0; attempt < 4; ++attempt) {
        coordinator.account_resolved(id, 0, true);
    }
    QCOMPARE(accounts.size(), 5);
    coordinator.account_resolved(id, 0, true);
    QCOMPARE(coordinator.status(1, started->flow_handle)->status, OAuthFlowStatus::Failed);
}

QTEST_GUILESS_MAIN(OAuthCoordinatorTest)

#include "test_oauth_coordinator.moc"

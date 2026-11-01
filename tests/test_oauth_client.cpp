#include "auth/authentication_service.h"
#include "client/oauth_client.h"
#include "oauth_test_provider.h"

#include <QSignalSpy>
#include <QSslSocket>
#include <QTemporaryDir>
#include <QTest>
#include <QUrlQuery>

Q_DECLARE_METATYPE(tcp_chat::protocol::AuthenticationResult)
Q_DECLARE_METATYPE(tcp_chat::protocol::Envelope)

namespace {

using tcp_chat::auth::AuthenticationService;
using tcp_chat::auth::AuthenticationServiceOptions;
using tcp_chat::auth::OAuthCallbackServerOptions;
using tcp_chat::client::OAuthClient;
using tcp_chat::client::TlsClient;
using tcp_chat::client::TlsClientConfiguration;
using tcp_chat::protocol::Envelope;
using tcp_chat::protocol::MessageType;
using tcp_chat::server::TlsServer;
using tcp_chat::server::TlsServerConfiguration;

/// Returns an isolated non-production TLS fixture path.
QString fixture(const QString& filename)
{
    return QStringLiteral(TCP_CHAT_SOURCE_DIR "/tests/tls_fixtures/") + filename;
}

/// Performs an asynchronous verified HTTPS callback on the test event loop.
class Browser {
public:
    /// Starts a provider-approved callback with the fixed fake authorization code.
    bool open(const QUrl& authorization, const std::shared_ptr<FakeOAuthProvider>& provider)
    {
        const QUrlQuery parameters(authorization);
        provider->expected_challenge = parameters.queryItemValue(QStringLiteral("code_challenge")).toLatin1();
        const QUrl callback(parameters.queryItemValue(QStringLiteral("redirect_uri")));
        provider->expected_redirect = callback;
        QUrlQuery callback_parameters;
        callback_parameters.addQueryItem(QStringLiteral("state"), parameters.queryItemValue(QStringLiteral("state")));
        callback_parameters.addQueryItem(QStringLiteral("code"), QStringLiteral("valid-code"));
        QUrl target = callback;
        target.setQuery(callback_parameters);
        socket                = std::make_unique<QSslSocket>();
        QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
        ssl.setCaCertificates(QSslCertificate::fromPath(fixture(QStringLiteral("trusted_ca.crt")), QSsl::Pem));
        socket->setSslConfiguration(ssl);
        socket->setPeerVerifyName(target.host());
        response.clear();
        QObject::connect(socket.get(), &QSslSocket::encrypted, socket.get(), [this, target] {
            const QByteArray request = "GET " + target.path().toLatin1() + "?" + target.query(QUrl::FullyEncoded).toLatin1()
                + " HTTP/1.1\r\nHost: " + target.authority().toLatin1() + "\r\n\r\n";
            socket->write(request);
        });
        QObject::connect(socket.get(), &QSslSocket::readyRead, socket.get(), [this] {
            response.append(socket->readAll());
            if (response.contains("\r\n\r\n")) {
                socket->disconnectFromHost();
            }
        });
        socket->connectToHostEncrypted(target.host(), static_cast<quint16>(target.port(443)));
        return true;
    }

    std::unique_ptr<QSslSocket> socket;
    QByteArray response;
};

/// Owns a real TLS/SQLite authentication flow with fake provider and browser adapters.
class OAuthHarness {
public:
    /// Creates deterministic service options before starting the database worker.
    OAuthHarness()
        : provider(std::make_shared<FakeOAuthProvider>(fake_provider_configuration()))
        , service(&server, make_options())
        , oauth(&client, [this](const QUrl& url) { return browser.open(url, provider); })
    {
        qRegisterMetaType<tcp_chat::protocol::AuthenticationResult>("tcp_chat::protocol::AuthenticationResult");
        qRegisterMetaType<Envelope>("tcp_chat::protocol::Envelope");
    }

    /// Starts all services and waits for both sides of the chat TLS connection.
    bool start()
    {
        TlsServerConfiguration server_options;
        server_options.address                = QHostAddress::LocalHost;
        server_options.certificate_chain_file = fixture(QStringLiteral("trusted_server.crt"));
        server_options.private_key_file       = fixture(QStringLiteral("trusted_server.key"));
        server_options.handshake_timeout      = std::chrono::milliseconds(3000);
        if (server.start(server_options).has_value()
            || service.start(temporary.filePath(QStringLiteral("chat.sqlite")), QStringLiteral(TCP_CHAT_SOURCE_DIR "/migrations"))
                .has_value()
            || !ready.wait(5000) || !ready.at(0).at(0).toBool()) {
            return false;
        }
        TlsClientConfiguration client_options;
        client_options.host                = QStringLiteral("localhost");
        client_options.port                = server.serverPort();
        client_options.ca_certificate_file = fixture(QStringLiteral("trusted_ca.crt"));
        client_options.handshake_timeout   = std::chrono::milliseconds(3000);
        if (client.connect_to_host(client_options).has_value() || !connected.wait(5000)) {
            return false;
        }
        return !server_connected.isEmpty() || server_connected.wait(5000);
    }

    /// Reconnects and waits until the service has registered the new connection.
    bool reconnect()
    {
        client.disconnect_from_host();
        if (disconnected.isEmpty() && !disconnected.wait(5000)) {
            return false;
        }
        TlsClientConfiguration options;
        options.host                = QStringLiteral("localhost");
        options.port                = server.serverPort();
        options.ca_certificate_file = fixture(QStringLiteral("trusted_ca.crt"));
        options.handshake_timeout   = std::chrono::milliseconds(3000);
        const int count             = server_connected.size();
        if (client.connect_to_host(options).has_value() || !connected.wait(5000)) {
            return false;
        }
        return server_connected.size() > count || server_connected.wait(5000);
    }

    /// Sends one envelope and returns its correlated response.
    std::optional<Envelope> request(MessageType type, const QJsonObject& payload)
    {
        messages.clear();
        Envelope envelope;
        envelope.type       = type;
        envelope.request_id = QStringLiteral("direct-request");
        envelope.payload    = payload;
        if (client.send(envelope).has_value() || !messages.wait(5000)) {
            return std::nullopt;
        }
        return qvariant_cast<Envelope>(messages.last().at(0));
    }

    QTemporaryDir temporary;
    qint64 current_time = 1000000;
    TlsServer server;
    std::shared_ptr<FakeOAuthProvider> provider;
    AuthenticationService service;
    Browser browser;
    TlsClient client;
    OAuthClient oauth;
    QSignalSpy ready { &service, &AuthenticationService::ready };
    QSignalSpy connected { &client, &TlsClient::connected };
    QSignalSpy server_connected { &server, &TlsServer::client_connected };
    QSignalSpy disconnected { &client, &TlsClient::disconnected };
    QSignalSpy messages { &client, &TlsClient::message_received };
    QSignalSpy authenticated { &oauth, &OAuthClient::authenticated };
    QSignalSpy failed { &oauth, &OAuthClient::failed };

private:
    /// Configures deterministic time, cheap password work, and a separate HTTPS callback listener.
    AuthenticationServiceOptions make_options()
    {
        AuthenticationServiceOptions options;
        options.hash_parameters                        = { 1, 1024 * 1024 };
        options.authentication_timeout_ms              = 5000;
        options.clock                                  = [this] { return current_time; };
        options.oauth_callback                         = OAuthCallbackServerOptions { };
        options.oauth_callback->expected_authority     = QStringLiteral("localhost");
        options.oauth_callback->certificate_chain_file = fixture(QStringLiteral("trusted_server.crt"));
        options.oauth_callback->private_key_file       = fixture(QStringLiteral("trusted_server.key"));
        options.oauth_callback->request_timeout        = std::chrono::milliseconds(3000);
        options.oauth_providers                        = { provider };
        options.oauth.clock                            = options.clock;
        options.oauth.flow_lifetime_ms                 = 30000;
        options.oauth.handoff_lifetime_ms              = 5000;
        return options;
    }
};

} // namespace

/// Verifies browser OAuth through real TLS, persistence, resumption, and logout.
class OAuthClientTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks complete sign-in, identity reuse, normal sessions, and local-login rejection.
    void completesBrowserSignInAndResume();
    /// Checks provider denial and disconnect-based cancellation.
    void rejectsDeniedSignIn();
};

void OAuthClientTest::completesBrowserSignInAndResume()
{
    OAuthHarness harness;
    QVERIFY(harness.start());
    QVERIFY(!harness.oauth.start(QStringLiteral("fake")).has_value());
    QTRY_VERIFY(harness.browser.response.startsWith("HTTP/1.1 200"));
    QTRY_COMPARE(harness.authenticated.size(), 1);
    const auto result = qvariant_cast<tcp_chat::protocol::AuthenticationResult>(harness.authenticated.at(0).at(0));
    QVERIFY(result.user.has_value());
    QVERIFY(result.session_token.has_value());
    QVERIFY(result.user->username.startsWith(QStringLiteral("user_")));
    QCOMPARE(harness.failed.size(), 0);

    QVERIFY(harness.reconnect());
    QVERIFY(!harness.oauth.start(QStringLiteral("fake")).has_value());
    QTRY_COMPARE(harness.authenticated.size(), 2);
    const auto repeat = qvariant_cast<tcp_chat::protocol::AuthenticationResult>(harness.authenticated.at(1).at(0));
    QCOMPARE(repeat.user->id, result.user->id);
    QCOMPARE(repeat.user->username, result.user->username);
    QVERIFY(repeat.session_token != result.session_token);

    QVERIFY(harness.reconnect());
    const auto resumed = harness.request(MessageType::AuthSession, QJsonObject { { QStringLiteral("sessionToken"), *result.session_token } });
    QVERIFY(resumed.has_value());
    const auto session = tcp_chat::protocol::authentication_result_from_envelope(*resumed);
    QVERIFY(session.has_value());
    QCOMPARE(session->user->id, result.user->id);
    QVERIFY(!session->session_token.has_value());
    const auto logged_out = harness.request(MessageType::AuthLogOut, QJsonObject { { QStringLiteral("sessionToken"), *result.session_token } });
    QVERIFY(logged_out.has_value());
    QVERIFY(tcp_chat::protocol::authentication_result_from_envelope(*logged_out)->revoked);

    QVERIFY(harness.reconnect());
    const auto local = harness.request(MessageType::AuthLogIn,
        QJsonObject { { QStringLiteral("username"), result.user->username }, { QStringLiteral("password"), QStringLiteral("not-a-local-password") } });
    QVERIFY(local.has_value());
    QCOMPARE(local->type, MessageType::Error);
    QCOMPARE(local->payload.value(QStringLiteral("code")).toString(), QStringLiteral("invalid_credentials"));
}

void OAuthClientTest::rejectsDeniedSignIn()
{
    OAuthHarness harness;
    QVERIFY(harness.start());
    harness.provider->reject_exchange = true;
    QVERIFY(!harness.oauth.start(QStringLiteral("fake")).has_value());
    QTRY_COMPARE(harness.failed.size(), 1);
    QTRY_COMPARE(harness.disconnected.size(), 1);
    QCOMPARE(harness.authenticated.size(), 0);
    QVERIFY(!harness.oauth.is_busy());
}

QTEST_GUILESS_MAIN(OAuthClientTest)

#include "test_oauth_client.moc"

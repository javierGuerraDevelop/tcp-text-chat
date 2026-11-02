#pragma once

#include "auth/authentication_service.h"
#include "client/tls_client.h"
#include "oauth_test_provider.h"

#include <QSignalSpy>
#include <QSslSocket>
#include <QTemporaryDir>
#include <QUrlQuery>

#include <memory>

/// Returns an isolated non-production TLS fixture path.
inline QString authentication_fixture(const QString& filename)
{
    return QStringLiteral(TCP_CHAT_SOURCE_DIR "/tests/tls_fixtures/") + filename;
}

/// Performs a verified HTTPS OAuth callback on the test event loop.
class AuthenticationTestBrowser {
public:
    /// Completes a provider-approved fake callback without logging its query parameters.
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
        ssl.setCaCertificates(QSslCertificate::fromPath(authentication_fixture(QStringLiteral("trusted_ca.crt")), QSsl::Pem));
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

/// Returns a fake provider configuration registered under a selected public identifier.
inline tcp_chat::auth::OAuthProviderConfiguration authentication_provider_configuration(const QString& id)
{
    auto configuration = fake_provider_configuration();
    configuration.id   = id;
    return configuration;
}

/// Owns a real TLS/SQLite authentication service with optional fake-provider OAuth.
class AuthenticationTestHarness {
public:
    /// Creates deterministic authentication settings and inexpensive test-only password work.
    explicit AuthenticationTestHarness(bool enable_oauth = false, const QString& provider_id = QStringLiteral("fake"))
        : provider(std::make_shared<FakeOAuthProvider>(authentication_provider_configuration(provider_id)))
        , service(&server, make_options(enable_oauth))
    {
        qRegisterMetaType<tcp_chat::protocol::AuthenticationResult>("tcp_chat::protocol::AuthenticationResult");
        qRegisterMetaType<tcp_chat::protocol::Envelope>("tcp_chat::protocol::Envelope");
        qRegisterMetaType<tcp_chat::protocol::UserIdentity>("tcp_chat::protocol::UserIdentity");
    }

    /// Starts persistence and the loopback TLS listener, waiting only for asynchronous readiness.
    bool start()
    {
        tcp_chat::server::TlsServerConfiguration options;
        options.address                = QHostAddress::LocalHost;
        options.certificate_chain_file = authentication_fixture(QStringLiteral("trusted_server.crt"));
        options.private_key_file       = authentication_fixture(QStringLiteral("trusted_server.key"));
        options.handshake_timeout      = std::chrono::milliseconds(3000);
        if (server.start(options).has_value()
            || service.start(temporary.filePath(QStringLiteral("chat.sqlite")), QStringLiteral(TCP_CHAT_SOURCE_DIR "/migrations")).has_value()) {
            return false;
        }
        return ready.wait(5000) && ready.at(0).at(0).toBool();
    }

    /// Returns a verified TLS configuration for the loopback listener.
    tcp_chat::client::TlsClientConfiguration client_options() const
    {
        tcp_chat::client::TlsClientConfiguration options;
        options.host                = QStringLiteral("localhost");
        options.port                = server.serverPort();
        options.ca_certificate_file = authentication_fixture(QStringLiteral("trusted_ca.crt"));
        options.handshake_timeout   = std::chrono::milliseconds(3000);
        return options;
    }

    /// Opens the fake provider callback through the real HTTPS callback listener.
    bool open_browser(const QUrl& url)
    {
        return browser.open(url, provider);
    }

    QTemporaryDir temporary;
    qint64 current_time = 1000000;
    tcp_chat::server::TlsServer server;
    std::shared_ptr<FakeOAuthProvider> provider;
    tcp_chat::auth::AuthenticationService service;
    AuthenticationTestBrowser browser;
    QSignalSpy ready { &service, &tcp_chat::auth::AuthenticationService::ready };
    QSignalSpy server_connected { &server, &tcp_chat::server::TlsServer::client_connected };

private:
    /// Creates service options whose clocks read this harness's mutable timestamp.
    tcp_chat::auth::AuthenticationServiceOptions make_options(bool enable_oauth)
    {
        tcp_chat::auth::AuthenticationServiceOptions options;
        options.hash_parameters           = { 1, 1024 * 1024 };
        options.session_lifetime_ms       = 10000;
        options.authentication_timeout_ms = 30000;
        options.clock                     = [this] { return current_time; };
        if (enable_oauth) {
            options.oauth_callback                         = tcp_chat::auth::OAuthCallbackServerOptions { };
            options.oauth_callback->expected_authority     = QStringLiteral("localhost");
            options.oauth_callback->certificate_chain_file = authentication_fixture(QStringLiteral("trusted_server.crt"));
            options.oauth_callback->private_key_file       = authentication_fixture(QStringLiteral("trusted_server.key"));
            options.oauth_callback->request_timeout        = std::chrono::milliseconds(3000);
            options.oauth_providers                        = { provider };
            options.oauth.clock                            = options.clock;
            options.oauth.flow_lifetime_ms                 = 30000;
            options.oauth.handoff_lifetime_ms              = 5000;
        }
        return options;
    }
};

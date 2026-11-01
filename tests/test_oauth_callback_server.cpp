#include "auth/oauth_callback_server.h"

#include <QSignalSpy>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QTcpSocket>
#include <QTest>

using tcp_chat::auth::OAuthCallbackServer;
using tcp_chat::auth::OAuthCallbackServerOptions;

namespace {

/// Returns an isolated non-production TLS fixture path.
QString fixture(const QString& filename)
{
    return QStringLiteral(TCP_CHAT_SOURCE_DIR "/tests/tls_fixtures/") + filename;
}

/// Creates a loopback HTTPS listener with a verified test certificate.
OAuthCallbackServerOptions options()
{
    OAuthCallbackServerOptions result;
    result.expected_authority     = QStringLiteral("localhost");
    result.certificate_chain_file = fixture(QStringLiteral("trusted_server.crt"));
    result.private_key_file       = fixture(QStringLiteral("trusted_server.key"));
    result.request_timeout        = std::chrono::milliseconds(3000);
    return result;
}

/// Sends one request using normal CA and hostname verification.
QByteArray request(quint16 port, const QByteArray& target, const QByteArray& method = QByteArrayLiteral("GET"),
    const QByteArray& host = QByteArray())
{
    QSslSocket socket;
    QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
    ssl.setCaCertificates(QSslCertificate::fromPath(fixture(QStringLiteral("trusted_ca.crt")), QSsl::Pem));
    socket.setSslConfiguration(ssl);
    socket.setPeerVerifyName(QStringLiteral("localhost"));
    QByteArray response;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    timeout.setInterval(3000);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    QObject::connect(&socket, &QSslSocket::disconnected, &loop, &QEventLoop::quit);
    QObject::connect(&socket, &QSslSocket::readyRead, &loop, [&socket, &response] { response.append(socket.readAll()); });
    QObject::connect(&socket, &QSslSocket::encrypted, &loop, [&] {
        const QByteArray authority = host.isEmpty() ? "localhost:" + QByteArray::number(port) : host;
        socket.write(method + " " + target + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n");
        socket.flush();
    });
    socket.connectToHostEncrypted(QStringLiteral("localhost"), port);
    timeout.start();
    loop.exec();
    response.append(socket.readAll());
    return response;
}

} // namespace

/// Verifies strict OAuth callback parsing over encrypted loopback connections.
class OAuthCallbackServerTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks authorization codes and provider denial without reflecting parameters.
    void acceptsCodeAndDenial();
    /// Checks duplicate, unknown, missing, and malformed parameters.
    void rejectsMalformedRequests();
    /// Checks method, host, path, request bounds, and plaintext rejection.
    void rejectsInvalidTransportRequests();
};

void OAuthCallbackServerTest::acceptsCodeAndDenial()
{
    OAuthCallbackServer server;
    QVERIFY(!server.start(options()).has_value());
    const QSignalSpy callback(&server, &OAuthCallbackServer::authorization_received);
    QByteArray response = request(server.serverPort(), QByteArrayLiteral("/oauth/callback?state=state-123&code=secret-code"));
    QVERIFY(response.startsWith("HTTP/1.1 200"));
    QVERIFY(!response.contains("secret-code"));
    QVERIFY(!response.contains("state-123"));
    QCOMPARE(callback.size(), 1);
    QCOMPARE(callback.at(0).at(0).toString(), QStringLiteral("state-123"));
    QCOMPARE(callback.at(0).at(1).toString(), QStringLiteral("secret-code"));

    response = request(server.serverPort(), QByteArrayLiteral("/oauth/callback?state=state-123&error=access_denied"));
    QVERIFY(response.startsWith("HTTP/1.1 200"));
    QCOMPARE(callback.size(), 2);
    QCOMPARE(callback.at(1).at(1).toString(), QString());
    QCOMPARE(callback.at(1).at(2).toString(), QStringLiteral("access_denied"));
    QCOMPARE(server.callback_url().scheme(), QStringLiteral("https"));
    QCOMPARE(server.callback_url().path(), QStringLiteral("/oauth/callback"));
}

void OAuthCallbackServerTest::rejectsMalformedRequests()
{
    OAuthCallbackServer server;
    QVERIFY(!server.start(options()).has_value());
    const QSignalSpy callback(&server, &OAuthCallbackServer::authorization_received);
    const QList<QByteArray> targets = {
        QByteArrayLiteral("/oauth/callback?state=abc&code=one&code=two"),
        QByteArrayLiteral("/oauth/callback?state=abc&code=one&unknown=value"),
        QByteArrayLiteral("/oauth/callback?code=one"),
        QByteArrayLiteral("/oauth/callback?state=abc&code=one&error=denied"),
        QByteArrayLiteral("/oauth/callback?state=abc&code=%ZZ"),
        QByteArrayLiteral("/oauth/callback?state=abc&code=hello+world"),
        QByteArrayLiteral("/oauth/callback?state=abc"),
        QByteArrayLiteral("/oauth/%63allback?state=abc&code=one"),
    };
    for (const auto& target : targets) {
        QVERIFY(request(server.serverPort(), target).startsWith("HTTP/1.1 400"));
    }
    QCOMPARE(callback.size(), 0);
}

void OAuthCallbackServerTest::rejectsInvalidTransportRequests()
{
    OAuthCallbackServer server;
    QVERIFY(!server.start(options()).has_value());
    const QSignalSpy callback(&server, &OAuthCallbackServer::authorization_received);
    QVERIFY(request(server.serverPort(), QByteArrayLiteral("/oauth/callback?state=abc&code=one"), QByteArrayLiteral("POST"))
            .startsWith("HTTP/1.1 405"));
    QVERIFY(request(server.serverPort(), QByteArrayLiteral("/oauth/callback?state=abc&code=one"), QByteArrayLiteral("GET"),
        QByteArrayLiteral("attacker.invalid"))
            .startsWith("HTTP/1.1 400"));
    QVERIFY(request(server.serverPort(), QByteArrayLiteral("/other?state=abc&code=one")).startsWith("HTTP/1.1 400"));

    QTcpSocket plaintext;
    QSignalSpy closed(&plaintext, &QTcpSocket::disconnected);
    QObject::connect(&plaintext, &QTcpSocket::connected, &plaintext, [&plaintext] {
        plaintext.write(QByteArrayLiteral("GET /oauth/callback?state=abc&code=one HTTP/1.1\r\n\r\n"));
        plaintext.flush();
    });
    plaintext.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(closed.wait(3000) || !closed.isEmpty());
    QCOMPARE(callback.size(), 0);

    QVERIFY(request(server.serverPort(), QByteArrayLiteral("/oauth/callback?state=abc&code=") + QByteArray(9000, 'x'))
            .startsWith("HTTP/1.1 400"));
    QCOMPARE(callback.size(), 0);
}

QTEST_GUILESS_MAIN(OAuthCallbackServerTest)

#include "test_oauth_callback_server.moc"

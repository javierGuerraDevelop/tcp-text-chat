#include "auth/authentication_service.h"
#include "auth/session_token.h"
#include "client/tls_client.h"

#include <QJsonObject>
#include <QSignalSpy>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <QTest>

#include <optional>

Q_DECLARE_METATYPE(tcp_chat::protocol::Envelope)
Q_DECLARE_METATYPE(tcp_chat::protocol::UserIdentity)

namespace {

using tcp_chat::auth::AuthenticationService;
using tcp_chat::auth::AuthenticationServiceOptions;
using tcp_chat::client::TlsClient;
using tcp_chat::client::TlsClientConfiguration;
using tcp_chat::protocol::AuthenticationResult;
using tcp_chat::protocol::Envelope;
using tcp_chat::protocol::ErrorCode;
using tcp_chat::protocol::MessageType;
using tcp_chat::server::TlsServer;
using tcp_chat::server::TlsServerConfiguration;

/// Returns an isolated non-production TLS fixture path.
QString fixture(const QString& filename)
{
    return QStringLiteral(TCP_CHAT_SOURCE_DIR "/tests/tls_fixtures/") + filename;
}

/// Creates a loopback TLS server configuration.
TlsServerConfiguration server_options()
{
    TlsServerConfiguration options;
    options.address                = QHostAddress::LocalHost;
    options.certificate_chain_file = fixture(QStringLiteral("trusted_server.crt"));
    options.private_key_file       = fixture(QStringLiteral("trusted_server.key"));
    options.handshake_timeout      = std::chrono::milliseconds(3000);
    return options;
}

/// Creates a verified client configuration for the local test listener.
TlsClientConfiguration client_options(quint16 port)
{
    TlsClientConfiguration options;
    options.host                = QStringLiteral("localhost");
    options.port                = port;
    options.ca_certificate_file = fixture(QStringLiteral("trusted_ca.crt"));
    options.handshake_timeout   = std::chrono::milliseconds(3000);
    return options;
}

/// Owns a database-backed authentication service and one connected client.
class AuthenticationHarness {
public:
    /// Creates the service with deterministic time and inexpensive password work.
    AuthenticationHarness()
        : service(&server, make_options())
    {
        qRegisterMetaType<Envelope>("tcp_chat::protocol::Envelope");
        qRegisterMetaType<tcp_chat::protocol::UserIdentity>("tcp_chat::protocol::UserIdentity");
    }

    /// Starts persistence, TLS, and the client, waiting only for asynchronous readiness.
    bool start()
    {
        if (server.start(server_options()).has_value()) {
            return false;
        }
        if (service.start(temporary.filePath(QStringLiteral("chat.sqlite")),
                       QStringLiteral(TCP_CHAT_SOURCE_DIR "/migrations"))
                .has_value()) {
            return false;
        }
        if (!ready.wait(5000) || ready.at(0).at(0).toBool() == false) {
            return false;
        }
        if (client.connect_to_host(client_options(server.serverPort())).has_value()) {
            return false;
        }
        if (!connected.wait(5000)) {
            return false;
        }
        return !server_connected.isEmpty() || server_connected.wait(5000);
    }

    /// Sends one envelope and waits for its correlated response.
    bool request(MessageType type, const QJsonObject& payload, const QString& id = QStringLiteral("request-1"))
    {
        messages.clear();
        Envelope envelope;
        envelope.type       = type;
        envelope.request_id = id;
        envelope.payload    = payload;
        if (client.send(envelope).has_value()) {
            return false;
        }
        return !messages.isEmpty() || messages.wait(5000);
    }

    /// Returns the most recent client envelope.
    Envelope response() const
    {
        return qvariant_cast<Envelope>(messages.last().at(0));
    }

    /// Returns the response's stable error code, or an empty string for non-errors.
    QString error_code() const
    {
        const Envelope envelope = response();
        return envelope.type == MessageType::Error ? envelope.payload.value(QStringLiteral("code")).toString() : QString();
    }

    /// Decodes the most recent successful authentication response.
    std::optional<AuthenticationResult> result() const
    {
        return tcp_chat::protocol::authentication_result_from_envelope(response());
    }

    /// Reconnects the client so a new connection is unauthenticated.
    bool reconnect()
    {
        const int old_disconnections = disconnected.size();
        client.disconnect_from_host();
        if (disconnected.size() == old_disconnections && !disconnected.wait(5000)) {
            return false;
        }
        const int old_connections = connected.size();
        if (client.connect_to_host(client_options(server.serverPort())).has_value()) {
            return false;
        }
        return connected.size() > old_connections || connected.wait(5000);
    }

    /// Advances the injected clock without waiting for wall time.
    void advance(qint64 milliseconds)
    {
        current_time += milliseconds;
    }

    QTemporaryDir temporary;
    qint64 current_time = 1000000;
    TlsServer server;
    AuthenticationService service;
    TlsClient client;
    QSignalSpy ready { &service, &AuthenticationService::ready };
    QSignalSpy connected { &client, &TlsClient::connected };
    QSignalSpy server_connected { &server, &TlsServer::client_connected };
    QSignalSpy messages { &client, &TlsClient::message_received };
    QSignalSpy disconnected { &client, &TlsClient::disconnected };

private:
    /// Creates service settings whose clock reads this harness's mutable timestamp.
    AuthenticationServiceOptions make_options()
    {
        AuthenticationServiceOptions options;
        options.hash_parameters           = { 1, 1024 * 1024 };
        options.session_lifetime_ms       = 10000;
        options.authentication_timeout_ms = 5000;
        options.clock                     = [this] { return current_time; };
        return options;
    }
};

/// Creates a valid local signup payload.
QJsonObject signup_payload(const QString& username = QStringLiteral("Alice"))
{
    return QJsonObject {
        { QStringLiteral("username"), username },
        { QStringLiteral("password"), QStringLiteral("correct horse battery staple") },
        { QStringLiteral("displayName"), QStringLiteral("Alice Example") },
    };
}

/// Creates a valid local login payload.
QJsonObject login_payload(const QString& username, const QString& password)
{
    return QJsonObject {
        { QStringLiteral("username"), username },
        { QStringLiteral("password"), password },
    };
}

/// Creates a session-operation payload.
QJsonObject token_payload(const QString& token)
{
    return QJsonObject { { QStringLiteral("sessionToken"), token } };
}

} // namespace

/// Verifies local authentication over real TLS and SQLite connections.
class AuthenticationServiceTest : public QObject {
    Q_OBJECT

private slots:
    /// Covers signup, normalized login, session resumption, and logout.
    void signsUpLogsInAndResumes();
    /// Covers duplicate usernames and indistinguishable login failures.
    void rejectsDuplicateAndGenericLoginFailures();
    /// Covers the exact session expiry boundary.
    void expiresSessions();
    /// Disconnects an established connection when its session expires.
    void expiresAuthenticatedConnections();
    /// Covers fixed-window rate limiting and recovery with fake time.
    void enforcesRateLimits();
    /// Covers unauthenticated connection deadlines.
    void expiresUnauthenticatedConnections();
    /// Covers bounded concurrent authentication requests.
    void boundsPendingRequests();
    /// Covers session resumption from a second client connection.
    void resumesOnAnotherConnection();
    /// Rejects credential operations after authentication.
    void rejectsRepeatedAuthentication();
    /// Verifies that only password hashes and token digests are persisted.
    void persistsOnlyCredentialHashes();
};

void AuthenticationServiceTest::signsUpLogsInAndResumes()
{
    AuthenticationHarness harness;
    QVERIFY(harness.start());
    QVERIFY(harness.request(MessageType::AuthSignUp, signup_payload()));
    const auto signup = harness.result();
    QVERIFY(signup.has_value());
    QVERIFY(signup->user.has_value());
    QVERIFY(signup->user->id > 0);
    QVERIFY(signup->session_token.has_value());
    QCOMPARE(signup->session_token->size(), 43);
    QCOMPARE(signup->expires_at, std::optional<qint64> { harness.current_time + 10000 });

    const QString first_token = *signup->session_token;
    QVERIFY(harness.request(MessageType::AuthLogOut, token_payload(first_token)));
    QVERIFY(harness.result()->revoked);

    QVERIFY(harness.request(MessageType::AuthLogIn,
        login_payload(QStringLiteral("  ALICE  "), QStringLiteral("correct horse battery staple"))));
    const auto login = harness.result();
    QVERIFY(login.has_value());
    QVERIFY(login->session_token.has_value());
    QVERIFY(*login->session_token != first_token);
    QCOMPARE(login->user->username, QStringLiteral("Alice"));

    QVERIFY(harness.reconnect());
    QVERIFY(harness.request(MessageType::AuthSession, token_payload(*login->session_token)));
    const auto resumed = harness.result();
    QVERIFY(resumed.has_value());
    QVERIFY(!resumed->session_token.has_value());
    QCOMPARE(resumed->user->id, login->user->id);

    QVERIFY(harness.request(MessageType::AuthLogOut, token_payload(*login->session_token)));
    QVERIFY(harness.request(MessageType::AuthSession, token_payload(*login->session_token)));
    QCOMPARE(harness.error_code(), QStringLiteral("unauthenticated"));
}

void AuthenticationServiceTest::rejectsDuplicateAndGenericLoginFailures()
{
    AuthenticationHarness harness;
    QVERIFY(harness.start());
    QVERIFY(harness.request(MessageType::AuthSignUp, signup_payload()));
    const QString token = *harness.result()->session_token;
    QVERIFY(harness.request(MessageType::AuthLogOut, token_payload(token)));
    QVERIFY(harness.request(MessageType::AuthSignUp, signup_payload()));
    QCOMPARE(harness.error_code(), QStringLiteral("username_taken"));

    QVERIFY(harness.request(MessageType::AuthLogIn, login_payload(QStringLiteral("Alice"), QStringLiteral("wrong-password"))));
    const QJsonObject wrong_password = harness.response().payload;
    QCOMPARE(harness.error_code(), QStringLiteral("invalid_credentials"));
    QVERIFY(harness.request(MessageType::AuthLogIn, login_payload(QStringLiteral("Nobody"), QStringLiteral("wrong-password"))));
    QCOMPARE(harness.response().payload, wrong_password);

    QVERIFY(harness.request(MessageType::AuthLogIn,
        login_payload(QStringLiteral("Nobody"), QStringLiteral("tcp-chat-offline-verifier"))));
    QCOMPARE(harness.error_code(), QStringLiteral("invalid_credentials"));
}

void AuthenticationServiceTest::expiresSessions()
{
    AuthenticationHarness harness;
    QVERIFY(harness.start());
    QVERIFY(harness.request(MessageType::AuthSignUp, signup_payload()));
    const auto result   = harness.result();
    const QString token = *result->session_token;
    QVERIFY(harness.reconnect());
    harness.advance(*result->expires_at - harness.current_time);
    QVERIFY(harness.request(MessageType::AuthSession, token_payload(token)));
    QCOMPARE(harness.error_code(), QStringLiteral("unauthenticated"));
}

void AuthenticationServiceTest::expiresAuthenticatedConnections()
{
    AuthenticationHarness harness;
    QVERIFY(harness.start());
    QVERIFY(harness.request(MessageType::AuthSignUp, signup_payload()));
    const auto result = harness.result();
    harness.advance(*result->expires_at - harness.current_time);
    harness.service.check_authentication_deadlines();
    QTRY_COMPARE(harness.disconnected.size(), 1);
    QCOMPARE(harness.server.active_connections(), 0);
}

void AuthenticationServiceTest::enforcesRateLimits()
{
    AuthenticationHarness harness;
    QVERIFY(harness.start());
    for (int attempt = 0; attempt < 9; ++attempt) {
        QVERIFY(harness.request(MessageType::AuthLogIn, login_payload(QStringLiteral("Nobody"), QStringLiteral("wrong-password"))));
    }
    QCOMPARE(harness.error_code(), QStringLiteral("rate_limited"));
    harness.advance(60000);
    QVERIFY(harness.request(MessageType::AuthLogIn, login_payload(QStringLiteral("Nobody"), QStringLiteral("wrong-password"))));
    QCOMPARE(harness.error_code(), QStringLiteral("invalid_credentials"));
}

void AuthenticationServiceTest::expiresUnauthenticatedConnections()
{
    AuthenticationHarness harness;
    QVERIFY(harness.start());
    harness.advance(5000);
    harness.service.check_authentication_deadlines();
    QTRY_COMPARE(harness.disconnected.size(), 1);
    QCOMPARE(harness.server.active_connections(), 0);
}

void AuthenticationServiceTest::boundsPendingRequests()
{
    AuthenticationHarness harness;
    QVERIFY(harness.start());
    harness.messages.clear();
    Envelope first;
    first.type    = MessageType::AuthLogIn;
    first.payload = login_payload(QStringLiteral("Nobody"), QStringLiteral("wrong-password"));
    for (int index = 0; index < 5; ++index) {
        first.request_id = QStringLiteral("request-%1").arg(index);
        QVERIFY(!harness.client.send(first).has_value());
    }
    QTRY_COMPARE(harness.messages.size(), 5);
    bool saw_rate_limit = false;
    for (const auto& arguments : harness.messages) {
        const auto envelope = qvariant_cast<Envelope>(arguments.at(0));
        if (envelope.type == MessageType::Error
            && envelope.payload.value(QStringLiteral("code")).toString() == QStringLiteral("rate_limited")) {
            saw_rate_limit = true;
        }
    }
    QVERIFY(saw_rate_limit);
}

void AuthenticationServiceTest::resumesOnAnotherConnection()
{
    AuthenticationHarness harness;
    QVERIFY(harness.start());
    QVERIFY(harness.request(MessageType::AuthSignUp, signup_payload()));
    const auto signup   = harness.result();
    const QString token = *signup->session_token;

    TlsClient second;
    QSignalSpy connected(&second, &TlsClient::connected);
    QSignalSpy messages(&second, &TlsClient::message_received);
    QSignalSpy second_disconnected(&second, &TlsClient::disconnected);
    QVERIFY(!second.connect_to_host(client_options(harness.server.serverPort())).has_value());
    QVERIFY(connected.wait(5000));
    Envelope resume;
    resume.type       = MessageType::AuthSession;
    resume.request_id = QStringLiteral("second-client");
    resume.payload    = token_payload(token);
    QVERIFY(!second.send(resume).has_value());
    QVERIFY(messages.wait(5000));
    const auto result = tcp_chat::protocol::authentication_result_from_envelope(
        qvariant_cast<Envelope>(messages.at(0).at(0)));
    QVERIFY(result.has_value());
    QCOMPARE(result->user->id, signup->user->id);

    QVERIFY(harness.request(MessageType::AuthLogOut, token_payload(token)));
    QTRY_COMPARE(second_disconnected.size(), 1);
}

void AuthenticationServiceTest::rejectsRepeatedAuthentication()
{
    AuthenticationHarness harness;
    QVERIFY(harness.start());
    QVERIFY(harness.request(MessageType::AuthSignUp, signup_payload()));
    QVERIFY(harness.request(MessageType::AuthLogIn,
        login_payload(QStringLiteral("Alice"), QStringLiteral("correct horse battery staple"))));
    QCOMPARE(harness.error_code(), QStringLiteral("invalid_request"));
}

void AuthenticationServiceTest::persistsOnlyCredentialHashes()
{
    AuthenticationHarness harness;
    QVERIFY(harness.start());
    const QString database_path = harness.temporary.filePath(QStringLiteral("chat.sqlite"));
    QVERIFY(harness.request(MessageType::AuthSignUp, signup_payload()));
    const QString token = *harness.result()->session_token;

    const QString connection_name = QStringLiteral("credential_inspection");
    QSqlDatabase database         = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connection_name);
    database.setDatabaseName(database_path);
    QVERIFY(database.open());
    QSqlQuery query(database);
    QVERIFY(query.exec(QStringLiteral("SELECT password_hash FROM users")));
    QVERIFY(query.next());
    const QString password_hash = query.value(0).toString();
    QVERIFY(password_hash.startsWith(QStringLiteral("$argon2id$")));
    QVERIFY(!password_hash.contains(QStringLiteral("correct horse battery staple")));
    QVERIFY(query.exec(QStringLiteral("SELECT token_digest FROM sessions")));
    QVERIFY(query.next());
    const QByteArray stored_digest = query.value(0).toByteArray();
    QCOMPARE(stored_digest.size(), 32);
    QVERIFY(stored_digest != token.toUtf8());
    QCOMPARE(stored_digest, tcp_chat::auth::digest_session_token(token).value_or(QByteArray()));
    query.finish();
    query.clear();
    database.close();
    database = QSqlDatabase { };
    QSqlDatabase::removeDatabase(connection_name);
}

QTEST_GUILESS_MAIN(AuthenticationServiceTest)

#include "test_authentication_service.moc"

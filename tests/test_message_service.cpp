#include "auth/authentication_service.h"
#include "chat/message_service.h"
#include "client/tls_client.h"
#include "tcp_chat/frame.h"

#include <QJsonObject>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

Q_DECLARE_METATYPE(tcp_chat::protocol::Envelope)

namespace {

using tcp_chat::auth::AuthenticationService;
using tcp_chat::auth::AuthenticationServiceOptions;
using tcp_chat::chat::MessageService;
using tcp_chat::chat::MessageServiceOptions;
using tcp_chat::client::TlsClient;
using tcp_chat::client::TlsClientConfiguration;
using tcp_chat::protocol::AuthenticationResult;
using tcp_chat::protocol::ChatHistoryResult;
using tcp_chat::protocol::ChatMessage;
using tcp_chat::protocol::Envelope;
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

/// Creates a local signup payload with a distinct public display name.
QJsonObject signup_payload(const QString& username)
{
    return QJsonObject {
        { QStringLiteral("username"), username },
        { QStringLiteral("password"), QStringLiteral("correct horse battery staple") },
        { QStringLiteral("displayName"), username + QStringLiteral(" Example") },
    };
}

/// Creates a session-operation payload.
QJsonObject token_payload(const QString& token)
{
    return QJsonObject { { QStringLiteral("sessionToken"), token } };
}

/// Creates an idempotent send payload.
QJsonObject send_payload(const QString& client_id, const QString& body)
{
    return QJsonObject {
        { QStringLiteral("clientMessageId"), client_id },
        { QStringLiteral("body"), body },
    };
}

/// Returns the last envelope correlated with a request ID.
Envelope response(const QSignalSpy& messages, const QString& request_id)
{
    for (int index = messages.size() - 1; index >= 0; --index) {
        const auto envelope = qvariant_cast<Envelope>(messages.at(index).at(0));
        if (envelope.request_id == std::optional<QString> { request_id }) {
            return envelope;
        }
    }
    return Envelope { };
}

/// Returns a response's stable error code, or an empty string for non-errors.
QString error_code(const Envelope& envelope)
{
    return envelope.type == MessageType::Error ? envelope.payload.value(QStringLiteral("code")).toString() : QString();
}

/// Owns real TLS and SQLite services with deterministic message time.
class MessagingHarness {
public:
    /// Creates services with inexpensive password work and configurable message bounds.
    explicit MessagingHarness(int maximum_messages = 30, int maximum_pending = 8)
        : authentication(&server, authentication_options())
        , messaging(&server, &authentication, message_options(maximum_messages, maximum_pending))
    {
        qRegisterMetaType<Envelope>("tcp_chat::protocol::Envelope");
    }

    /// Starts the listener and both persistence services without opening clients.
    bool start()
    {
        if (server.start(server_options()).has_value()) {
            return false;
        }
        if (authentication.start(temporary.filePath(QStringLiteral("chat.sqlite")),
                              QStringLiteral(TCP_CHAT_SOURCE_DIR "/migrations"))
                .has_value()
            || !auth_ready.wait(5000) || !auth_ready.at(0).at(0).toBool()) {
            return false;
        }
        if (messaging.start(temporary.filePath(QStringLiteral("chat.sqlite")),
                         QStringLiteral(TCP_CHAT_SOURCE_DIR "/migrations"))
                .has_value()
            || !chat_ready.wait(5000) || !chat_ready.at(0).at(0).toBool()) {
            return false;
        }
        return true;
    }

    /// Connects and verifies the first client.
    bool connect_first()
    {
        return connect_client(first, first_connected);
    }

    /// Connects and verifies the second client.
    bool connect_second()
    {
        return connect_client(second, second_connected);
    }

    /// Signs up and authenticates the first client.
    std::optional<AuthenticationResult> sign_up_first(const QString& username = QStringLiteral("Alice"))
    {
        if (!connect_first()) {
            return std::nullopt;
        }
        return sign_up(first, first_messages, username);
    }

    /// Signs up and authenticates the second client.
    std::optional<AuthenticationResult> sign_up_second(const QString& username = QStringLiteral("Bob"))
    {
        if (!connect_second()) {
            return std::nullopt;
        }
        return sign_up(second, second_messages, username);
    }

    /// Sends one request and waits for its correlated response despite live events.
    bool request(TlsClient& client, QSignalSpy& messages, MessageType type, const QJsonObject& payload, const QString& id)
    {
        messages.clear();
        Envelope envelope;
        envelope.type       = type;
        envelope.request_id = id;
        envelope.payload    = payload;
        if (client.send(envelope).has_value()) {
            return false;
        }
        while (response(messages, id).request_id != std::optional<QString> { id }) {
            if (!messages.wait(5000)) {
                return false;
            }
        }
        return true;
    }

    /// Sends a message and decodes its correlated acknowledgement.
    std::optional<ChatMessage> send_first(const QString& client_id, const QString& body, const QString& request_id)
    {
        if (!request(first, first_messages, MessageType::ChatSend, send_payload(client_id, body), request_id)) {
            return std::nullopt;
        }
        return tcp_chat::protocol::chat_message_from_envelope(response(first_messages, request_id));
    }

    /// Requests and decodes one history page.
    std::optional<ChatHistoryResult> history_first(const QJsonObject& payload, const QString& request_id)
    {
        if (!request(first, first_messages, MessageType::ChatHistory, payload, request_id)) {
            return std::nullopt;
        }
        return tcp_chat::protocol::chat_history_result_from_envelope(response(first_messages, request_id));
    }

    QTemporaryDir temporary;
    qint64 current_time = 1000000;
    TlsServer server;
    AuthenticationService authentication;
    MessageService messaging;
    TlsClient first;
    TlsClient second;
    QSignalSpy auth_ready { &authentication, &AuthenticationService::ready };
    QSignalSpy chat_ready { &messaging, &MessageService::ready };
    QSignalSpy first_connected { &first, &TlsClient::connected };
    QSignalSpy second_connected { &second, &TlsClient::connected };
    QSignalSpy first_messages { &first, &TlsClient::message_received };
    QSignalSpy second_messages { &second, &TlsClient::message_received };
    QSignalSpy first_disconnected { &first, &TlsClient::disconnected };

private:
    /// Creates authentication settings whose clock reads this harness's timestamp.
    AuthenticationServiceOptions authentication_options()
    {
        AuthenticationServiceOptions options;
        options.hash_parameters           = { 1, 1024 * 1024 };
        options.session_lifetime_ms       = 600000;
        options.authentication_timeout_ms = 30000;
        options.clock                     = [this] { return current_time; };
        return options;
    }

    /// Creates messaging settings whose clock reads this harness's timestamp.
    MessageServiceOptions message_options(int maximum_messages, int maximum_pending)
    {
        MessageServiceOptions options;
        options.maximum_messages_per_connection = maximum_messages;
        options.maximum_messages_per_user       = maximum_messages;
        options.maximum_pending_per_connection  = maximum_pending;
        options.clock                           = [this] { return current_time; };
        return options;
    }

    /// Connects one client and waits for certificate verification.
    bool connect_client(TlsClient& client, QSignalSpy& connected)
    {
        if (client.connect_to_host(client_options(server.serverPort())).has_value()) {
            return false;
        }
        return connected.wait(5000);
    }

    /// Signs up an already connected client.
    std::optional<AuthenticationResult> sign_up(TlsClient& client, QSignalSpy& messages, const QString& username)
    {
        if (!request(client, messages, MessageType::AuthSignUp, signup_payload(username), QStringLiteral("signup"))) {
            return std::nullopt;
        }
        return tcp_chat::protocol::authentication_result_from_envelope(response(messages, QStringLiteral("signup")));
    }
};

/// Verifies authenticated messaging over real TLS and SQLite connections.
class MessageServiceTest : public QObject {
    Q_OBJECT

private slots:
    /// Rejects history and sends before authentication.
    void requiresAuthentication();
    /// Covers ordered multi-client delivery, exact retries, and key conflicts.
    void broadcastsAndPersistsIdempotentMessages();
    /// Covers both history directions and reconnect catch-up.
    void paginatesAndReconnects();
    /// Covers validation, fixed-window limits, and fake-time recovery.
    void validatesAndRateLimitsMessages();
    /// Covers bounded in-flight history requests.
    void boundsPendingRequests();
    /// Keeps large history responses inside the protocol frame bound.
    void boundsHistoryFrameSize();
};

void MessageServiceTest::requiresAuthentication()
{
    MessagingHarness harness;
    QVERIFY(harness.start());
    QVERIFY(harness.connect_first());
    QVERIFY(harness.request(harness.first, harness.first_messages, MessageType::ChatHistory, QJsonObject { }, QStringLiteral("history")));
    QCOMPARE(error_code(response(harness.first_messages, QStringLiteral("history"))), QStringLiteral("unauthenticated"));
    QVERIFY(harness.request(harness.first, harness.first_messages, MessageType::ChatSend,
        send_payload(QStringLiteral("client-1"), QStringLiteral("body")), QStringLiteral("send")));
    QCOMPARE(error_code(response(harness.first_messages, QStringLiteral("send"))), QStringLiteral("unauthenticated"));
}

void MessageServiceTest::broadcastsAndPersistsIdempotentMessages()
{
    MessagingHarness harness;
    QVERIFY(harness.start());
    const auto alice = harness.sign_up_first();
    const auto bob   = harness.sign_up_second();
    QVERIFY(alice.has_value() && alice->session_token.has_value());
    QVERIFY(bob.has_value());

    harness.first_messages.clear();
    harness.second_messages.clear();
    Envelope send;
    send.type       = MessageType::ChatSend;
    send.request_id = QStringLiteral("send-1");
    send.payload    = send_payload(QStringLiteral("alice-1"), QStringLiteral("  Hello room  "));
    QVERIFY(!harness.first.send(send).has_value());
    QTRY_COMPARE(harness.first_messages.size(), 2);
    QTRY_COMPARE(harness.second_messages.size(), 1);

    const auto acknowledgement = qvariant_cast<Envelope>(harness.first_messages.at(0).at(0));
    const auto first_event     = qvariant_cast<Envelope>(harness.first_messages.at(1).at(0));
    const auto second_event    = qvariant_cast<Envelope>(harness.second_messages.at(0).at(0));
    QCOMPARE(acknowledgement.request_id, std::optional<QString> { QStringLiteral("send-1") });
    QVERIFY(!first_event.request_id.has_value());
    QVERIFY(!second_event.request_id.has_value());
    const auto stored = tcp_chat::protocol::chat_message_from_envelope(acknowledgement);
    QVERIFY(stored.has_value());
    QCOMPARE(stored->body, QStringLiteral("  Hello room  "));
    QCOMPARE(stored->sender, *alice->user);
    QCOMPARE(tcp_chat::protocol::chat_message_from_envelope(first_event), stored);
    QCOMPARE(tcp_chat::protocol::chat_message_from_envelope(second_event), stored);

    const auto retry = harness.send_first(QStringLiteral("alice-1"), QStringLiteral("  Hello room  "), QStringLiteral("retry"));
    QCOMPARE(retry, stored);
    harness.second_messages.clear();
    Envelope ping;
    ping.type       = MessageType::Ping;
    ping.request_id = QStringLiteral("after-retry");
    QVERIFY(!harness.second.send(ping).has_value());
    QTRY_COMPARE(harness.second_messages.size(), 1);
    QCOMPARE(qvariant_cast<Envelope>(harness.second_messages.at(0).at(0)).type, MessageType::Pong);

    QVERIFY(harness.request(harness.first, harness.first_messages, MessageType::ChatSend,
        send_payload(QStringLiteral("alice-1"), QStringLiteral("different")), QStringLiteral("conflict")));
    QCOMPARE(error_code(response(harness.first_messages, QStringLiteral("conflict"))), QStringLiteral("invalid_request"));
    const auto history = harness.history_first(QJsonObject { }, QStringLiteral("history"));
    QVERIFY(history.has_value());
    QCOMPARE(history->messages.size(), 1);
    QCOMPARE(history->messages.at(0), *stored);

    QVERIFY(harness.request(harness.first, harness.first_messages, MessageType::AuthLogOut,
        token_payload(*alice->session_token), QStringLiteral("logout")));
    QVERIFY(harness.request(harness.first, harness.first_messages, MessageType::ChatSend,
        send_payload(QStringLiteral("alice-2"), QStringLiteral("not authorized")), QStringLiteral("after-logout")));
    QCOMPARE(error_code(response(harness.first_messages, QStringLiteral("after-logout"))), QStringLiteral("unauthenticated"));
}

void MessageServiceTest::paginatesAndReconnects()
{
    MessagingHarness harness;
    QVERIFY(harness.start());
    const auto alice = harness.sign_up_first();
    QVERIFY(alice.has_value() && alice->session_token.has_value());
    QList<qint64> ids;
    for (int sequence = 1; sequence <= 5; ++sequence) {
        const auto message = harness.send_first(QStringLiteral("client-%1").arg(sequence),
            QStringLiteral("message %1").arg(sequence), QStringLiteral("send-%1").arg(sequence));
        QVERIFY(message.has_value());
        ids.append(message->id);
    }

    const auto latest = harness.history_first(QJsonObject { { QStringLiteral("limit"), 2 } }, QStringLiteral("latest"));
    QVERIFY(latest.has_value());
    QCOMPARE(latest->messages.size(), 2);
    QCOMPARE(latest->messages.at(0).id, ids.at(3));
    QCOMPARE(latest->messages.at(1).id, ids.at(4));
    QVERIFY(latest->has_more);

    const auto older = harness.history_first(
        QJsonObject { { QStringLiteral("beforeId"), QString::number(ids.at(3)) }, { QStringLiteral("limit"), 2 } },
        QStringLiteral("older"));
    QVERIFY(older.has_value());
    QCOMPARE(older->messages.size(), 2);
    QCOMPARE(older->messages.at(0).id, ids.at(1));
    QCOMPARE(older->messages.at(1).id, ids.at(2));
    QVERIFY(older->has_more);

    const auto oldest = harness.history_first(
        QJsonObject { { QStringLiteral("beforeId"), QString::number(ids.at(1)) }, { QStringLiteral("limit"), 2 } },
        QStringLiteral("oldest"));
    QVERIFY(oldest.has_value());
    QCOMPARE(oldest->messages.size(), 1);
    QCOMPARE(oldest->messages.at(0).id, ids.at(0));
    QVERIFY(!oldest->has_more);

    const auto catch_up = harness.history_first(
        QJsonObject { { QStringLiteral("afterId"), QStringLiteral("0") }, { QStringLiteral("limit"), 2 } },
        QStringLiteral("catch-up"));
    QVERIFY(catch_up.has_value());
    QCOMPARE(catch_up->messages.size(), 2);
    QCOMPARE(catch_up->messages.at(0).id, ids.at(0));
    QVERIFY(catch_up->has_more);

    harness.first.disconnect_from_host();
    QTRY_COMPARE(harness.first_disconnected.size(), 1);
    QVERIFY(harness.connect_first());
    QVERIFY(harness.request(harness.first, harness.first_messages, MessageType::AuthSession,
        token_payload(*alice->session_token), QStringLiteral("resume")));
    const auto reconnected = harness.history_first(
        QJsonObject { { QStringLiteral("afterId"), QString::number(ids.at(2)) }, { QStringLiteral("limit"), 2 } },
        QStringLiteral("reconnected"));
    QVERIFY(reconnected.has_value());
    QCOMPARE(reconnected->messages.size(), 2);
    QCOMPARE(reconnected->messages.at(0).id, ids.at(3));
    QCOMPARE(reconnected->messages.at(1).id, ids.at(4));
    QVERIFY(!reconnected->has_more);
}

void MessageServiceTest::validatesAndRateLimitsMessages()
{
    MessagingHarness harness(2);
    QVERIFY(harness.start());
    QVERIFY(harness.sign_up_first().has_value());
    for (const QString& body : { QString(), QStringLiteral(" \n"), QString(4001, QLatin1Char('x')) }) {
        QVERIFY(harness.request(harness.first, harness.first_messages, MessageType::ChatSend,
            send_payload(QStringLiteral("invalid"), body), QStringLiteral("invalid")));
        QCOMPARE(error_code(response(harness.first_messages, QStringLiteral("invalid"))), QStringLiteral("invalid_request"));
    }

    QVERIFY(harness.send_first(QStringLiteral("client-1"), QStringLiteral("first"), QStringLiteral("send-1")).has_value());
    QVERIFY(harness.send_first(QStringLiteral("client-2"), QStringLiteral("second"), QStringLiteral("send-2")).has_value());
    QVERIFY(harness.request(harness.first, harness.first_messages, MessageType::ChatSend,
        send_payload(QStringLiteral("client-3"), QStringLiteral("third")), QStringLiteral("send-3")));
    QCOMPARE(error_code(response(harness.first_messages, QStringLiteral("send-3"))), QStringLiteral("rate_limited"));

    harness.current_time += 60000;
    const auto recovered = harness.send_first(QStringLiteral("client-3"), QStringLiteral("third"), QStringLiteral("send-4"));
    QVERIFY(recovered.has_value());
    QCOMPARE(recovered->created_at, harness.current_time);
}

void MessageServiceTest::boundsPendingRequests()
{
    MessagingHarness harness(30, 4);
    QVERIFY(harness.start());
    QVERIFY(harness.sign_up_first().has_value());
    harness.first_messages.clear();
    for (int request = 0; request < 6; ++request) {
        Envelope history;
        history.type       = MessageType::ChatHistory;
        history.request_id = QStringLiteral("history-%1").arg(request);
        QVERIFY(!harness.first.send(history).has_value());
    }
    QTRY_COMPARE(harness.first_messages.size(), 6);
    bool saw_rate_limit = false;
    for (const auto& arguments : harness.first_messages) {
        if (error_code(qvariant_cast<Envelope>(arguments.at(0))) == QStringLiteral("rate_limited")) {
            saw_rate_limit = true;
        }
    }
    QVERIFY(saw_rate_limit);
}

void MessageServiceTest::boundsHistoryFrameSize()
{
    MessagingHarness harness;
    QVERIFY(harness.start());
    QVERIFY(harness.sign_up_first().has_value());
    const QString body(4000, QLatin1Char('x'));
    for (int sequence = 0; sequence < 20; ++sequence) {
        QVERIFY(harness.send_first(QStringLiteral("client-%1").arg(sequence), body,
                           QStringLiteral("send-%1").arg(sequence))
                .has_value());
    }
    const auto history = harness.history_first(QJsonObject { { QStringLiteral("limit"), 20 } }, QStringLiteral("history"));
    QVERIFY(history.has_value());
    QVERIFY(!history->messages.isEmpty());
    QVERIFY(history->messages.size() < 20);
    QVERIFY(history->has_more);

    const auto payload = tcp_chat::protocol::chat_history_result_to_json(*history);
    QVERIFY(payload.has_value());
    Envelope envelope;
    envelope.type       = MessageType::ChatHistoryResult;
    envelope.request_id = QStringLiteral("history");
    envelope.payload    = *payload;
    QVERIFY(tcp_chat::protocol::encode_envelope(envelope).has_value());
}

} // namespace

QTEST_GUILESS_MAIN(MessageServiceTest)

#include "test_message_service.moc"

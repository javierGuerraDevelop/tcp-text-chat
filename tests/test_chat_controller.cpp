#include "auth/authentication_service.h"
#include "chat/message_service.h"
#include "client/authentication_controller.h"
#include "client/chat_controller.h"

#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

Q_DECLARE_METATYPE(tcp_chat::client::AuthenticationController::State)

namespace {

using tcp_chat::auth::AuthenticationService;
using tcp_chat::auth::AuthenticationServiceOptions;
using tcp_chat::chat::MessageService;
using tcp_chat::chat::MessageServiceOptions;
using tcp_chat::client::AuthenticationController;
using tcp_chat::client::ChatController;
using tcp_chat::client::ChatModel;
using tcp_chat::client::TlsClient;
using tcp_chat::client::TlsClientConfiguration;
using tcp_chat::server::TlsServer;
using tcp_chat::server::TlsServerConfiguration;
using State = AuthenticationController::State;

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

/// Owns real messaging services and their asynchronous client controller.
class ChatControllerHarness {
public:
    /// Creates services with deterministic time and configurable send limits.
    explicit ChatControllerHarness(int maximum_messages = 100)
        : authentication_service(&server, authentication_options())
        , message_service(&server, &authentication_service, message_options(maximum_messages))
        , authentication(&socket)
        , controller(&socket, &authentication, &model)
    {
        qRegisterMetaType<State>("tcp_chat::client::AuthenticationController::State");
    }

    /// Starts persistence and TLS, then reaches the unauthenticated ready state.
    bool start()
    {
        if (server.start(server_options()).has_value()) {
            return false;
        }
        if (authentication_service.start(temporary.filePath(QStringLiteral("chat.sqlite")),
                                      QStringLiteral(TCP_CHAT_SOURCE_DIR "/migrations"))
                .has_value()
            || !auth_ready.wait(5000)) {
            return false;
        }
        if (message_service.start(temporary.filePath(QStringLiteral("chat.sqlite")),
                               QStringLiteral(TCP_CHAT_SOURCE_DIR "/migrations"))
                .has_value()
            || !chat_ready.wait(5000)) {
            return false;
        }
        QSignalSpy states(&authentication, &AuthenticationController::state_changed);
        authentication.connect_to_server(client_options());
        return authentication.state() == State::Ready || (states.wait(5000) && authentication.state() == State::Ready);
    }

    /// Creates one account and completes initial history synchronization.
    bool sign_up()
    {
        QSignalSpy authenticated(&authentication, &AuthenticationController::authenticated);
        authentication.sign_up(QStringLiteral("Alice"), QStringLiteral("correct horse battery staple"), QStringLiteral("Alice Example"));
        return authentication.state() == State::Authenticated || (authenticated.wait(5000) && authentication.state() == State::Authenticated);
    }

    /// Returns a verified TLS configuration for the local listener.
    TlsClientConfiguration client_options() const
    {
        TlsClientConfiguration options;
        options.host                = QStringLiteral("localhost");
        options.port                = server.serverPort();
        options.ca_certificate_file = fixture(QStringLiteral("trusted_ca.crt"));
        options.handshake_timeout   = std::chrono::milliseconds(3000);
        return options;
    }

    QTemporaryDir temporary;
    qint64 current_time = 1000000;
    TlsServer server;
    AuthenticationService authentication_service;
    MessageService message_service;
    TlsClient socket;
    AuthenticationController authentication;
    ChatModel model;
    ChatController controller;
    QSignalSpy auth_ready { &authentication_service, &AuthenticationService::ready };
    QSignalSpy chat_ready { &message_service, &MessageService::ready };
    QSignalSpy history_loaded { &controller, &ChatController::history_loaded };
    QSignalSpy envelopes { &socket, &TlsClient::message_received };

private:
    /// Creates inexpensive authentication settings with an injected clock.
    AuthenticationServiceOptions authentication_options()
    {
        AuthenticationServiceOptions options;
        options.hash_parameters     = { 1, 1024 * 1024 };
        options.session_lifetime_ms = 600000;
        options.clock               = [this] { return current_time; };
        return options;
    }

    /// Creates message settings with an injected clock and test-specific limit.
    MessageServiceOptions message_options(int maximum_messages)
    {
        MessageServiceOptions options;
        options.maximum_messages_per_connection = maximum_messages;
        options.maximum_messages_per_user       = maximum_messages;
        options.clock                           = [this] { return current_time; };
        return options;
    }
};

/// Verifies client messaging against real TLS and SQLite services.
class ChatControllerTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks acknowledgement and live-event deduplication.
    void acknowledgesWithoutDuplicates();
    /// Checks failed-send retry with the same idempotency key.
    void retriesAfterRateLimit();
    /// Checks initial pages, older loading, and reconnect catch-up.
    void paginatesAndReconnects();
};

void ChatControllerTest::acknowledgesWithoutDuplicates()
{
    ChatControllerHarness harness;
    QVERIFY(harness.start());
    QVERIFY(harness.sign_up());
    QTRY_COMPARE(harness.history_loaded.size(), 1);
    harness.envelopes.clear();
    QVERIFY(!harness.controller.send_message(QStringLiteral(" \n")).has_value());
    QVERIFY(!harness.controller.send_message(QString(4001, QLatin1Char('x'))).has_value());
    QCOMPARE(harness.model.rowCount(), 0);

    const auto first = harness.controller.send_message(QStringLiteral("first"));
    QVERIFY(first.has_value());
    QTRY_COMPARE(harness.model.delivery_for_client_id(*first), std::optional<ChatModel::Delivery> { ChatModel::Delivery::Sent });
    const auto second = harness.controller.send_message(QStringLiteral("second"));
    QVERIFY(second.has_value());
    QTRY_COMPARE(harness.model.delivery_for_client_id(*second), std::optional<ChatModel::Delivery> { ChatModel::Delivery::Sent });
    QTRY_COMPARE(harness.envelopes.size(), 4);
    QCOMPARE(harness.model.rowCount(), 2);
    QCOMPARE(harness.model.data(harness.model.index(0)), QStringLiteral("first"));
    QCOMPARE(harness.model.data(harness.model.index(1)), QStringLiteral("second"));
}

void ChatControllerTest::retriesAfterRateLimit()
{
    ChatControllerHarness harness(1);
    QVERIFY(harness.start());
    QVERIFY(harness.sign_up());
    const auto first = harness.controller.send_message(QStringLiteral("first"));
    QVERIFY(first.has_value());
    QTRY_COMPARE(harness.model.delivery_for_client_id(*first), std::optional<ChatModel::Delivery> { ChatModel::Delivery::Sent });

    const auto failed = harness.controller.send_message(QStringLiteral("retry me"));
    QVERIFY(failed.has_value());
    QTRY_COMPARE(harness.model.delivery_for_client_id(*failed), std::optional<ChatModel::Delivery> { ChatModel::Delivery::Failed });
    harness.current_time += 60000;
    QVERIFY(harness.controller.retry_message(*failed));
    QTRY_COMPARE(harness.model.delivery_for_client_id(*failed), std::optional<ChatModel::Delivery> { ChatModel::Delivery::Sent });
    QCOMPARE(harness.model.rowCount(), 2);
    QCOMPARE(harness.model.message_for_client_id(*failed)->body, QStringLiteral("retry me"));
}

void ChatControllerTest::paginatesAndReconnects()
{
    ChatControllerHarness harness;
    QVERIFY(harness.start());
    QVERIFY(harness.sign_up());
    QList<QString> client_ids;
    for (int sequence = 1; sequence <= 55; ++sequence) {
        const auto sent = harness.controller.send_message(QStringLiteral("message %1").arg(sequence));
        QVERIFY(sent.has_value());
        client_ids.append(*sent);
        QTRY_COMPARE(harness.model.delivery_for_client_id(*sent), std::optional<ChatModel::Delivery> { ChatModel::Delivery::Sent });
    }
    QTRY_COMPARE(harness.model.rowCount(), 55);
    const qint64 last_id = harness.model.last_message_id();
    QVERIFY(last_id > 0);

    harness.model.clear();
    harness.authentication.reconnect_to_server();
    QTRY_COMPARE(harness.authentication.state(), State::Authenticated);
    QTRY_COMPARE(harness.history_loaded.size(), 2);
    QTRY_COMPARE(harness.model.rowCount(), 50);
    QVERIFY(harness.controller.has_older_history());
    QCOMPARE(harness.model.last_message_id(), last_id);

    harness.controller.load_older_history();
    QTRY_COMPARE(harness.model.rowCount(), 55);
    QVERIFY(!harness.controller.has_older_history());
    QVERIFY(harness.model.first_message_id() > 0);

    harness.authentication.reconnect_to_server();
    QTRY_COMPARE(harness.authentication.state(), State::Authenticated);
    QTRY_COMPARE(harness.history_loaded.size(), 3);
    QCOMPARE(harness.model.rowCount(), 55);
    QCOMPARE(harness.model.last_message_id(), last_id);
}

} // namespace

QTEST_GUILESS_MAIN(ChatControllerTest)

#include "test_chat_controller.moc"

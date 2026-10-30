#include "client/tls_client.h"
#include "server/tls_server.h"

#include <QDeadlineTimer>
#include <QJsonObject>
#include <QSignalSpy>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QTcpSocket>
#include <QTest>

#include <chrono>

Q_DECLARE_METATYPE(tcp_chat::protocol::Envelope)
Q_DECLARE_METATYPE(tcp_chat::protocol::ProtocolError)

namespace {

using namespace std::chrono_literals;
using tcp_chat::client::TlsClient;
using tcp_chat::client::TlsClientConfiguration;
using tcp_chat::protocol::Envelope;
using tcp_chat::protocol::ErrorCode;
using tcp_chat::protocol::FrameDecoder;
using tcp_chat::protocol::MessageType;
using tcp_chat::protocol::ProtocolError;
using tcp_chat::server::TlsServer;
using tcp_chat::server::TlsServerConfiguration;
using tcp_chat::transport::FramedSocket;
using tcp_chat::transport::Heartbeat;

/// Returns a clearly isolated non-production certificate fixture path.
QString fixture(const QString& filename)
{
    return QStringLiteral(TCP_CHAT_SOURCE_DIR "/tests/tls_fixtures/") + filename;
}

/// Creates a loopback listener configuration using the selected server identity.
TlsServerConfiguration server_configuration(const QString& identity)
{
    TlsServerConfiguration configuration;
    configuration.address                  = QHostAddress::LocalHost;
    configuration.certificate_chain_file   = fixture(identity + QStringLiteral(".crt"));
    configuration.private_key_file         = fixture(identity + QStringLiteral(".key"));
    configuration.handshake_timeout        = 3000ms;
    configuration.session.shutdown_timeout = 1000ms;
    return configuration;
}

/// Creates a client that trusts only the dedicated loopback test CA.
TlsClientConfiguration client_configuration(quint16 port)
{
    TlsClientConfiguration configuration;
    configuration.host                     = QStringLiteral("localhost");
    configuration.port                     = port;
    configuration.ca_certificate_file      = fixture(QStringLiteral("trusted_ca.crt"));
    configuration.handshake_timeout        = 3000ms;
    configuration.session.shutdown_timeout = 1000ms;
    return configuration;
}

/// Owns a client/server pair and spies created before any connection starts.
class PairHarness {
public:
    /// Starts the selected server identity and waits for both TLS endpoints.
    std::optional<QString> start(const QString& identity = QStringLiteral("trusted_server"))
    {
        if (const auto error = server.start(server_configuration(identity)); error.has_value()) {
            return error;
        }
        if (const auto error = client.connect_to_host(client_configuration(server.serverPort())); error.has_value()) {
            return error;
        }
        if (!client_connected.wait(3000)) {
            return QStringLiteral("The client did not complete TLS negotiation");
        }
        if (server_connected.isEmpty() && !server_connected.wait(3000)) {
            return QStringLiteral("The server did not complete TLS negotiation");
        }
        return std::nullopt;
    }

    /// Returns the identifier assigned to this pair's client.
    quint64 connection_id() const
    {
        return server_connected.at(0).at(0).toULongLong();
    }

    TlsServer server;
    TlsClient client;
    QSignalSpy server_connected { &server, &TlsServer::client_connected };
    QSignalSpy server_messages { &server, &TlsServer::message_received };
    QSignalSpy server_disconnected { &server, &TlsServer::client_disconnected };
    QSignalSpy client_connected { &client, &TlsClient::connected };
    QSignalSpy client_messages { &client, &TlsClient::message_received };
    QSignalSpy client_disconnected { &client, &TlsClient::disconnected };
};

/// Connects a raw TLS socket using normal certificate and hostname verification.
bool connect_raw_socket(QSslSocket& socket, quint16 port)
{
    QSslConfiguration configuration = QSslConfiguration::defaultConfiguration();
    configuration.setProtocol(QSsl::TlsV1_2OrLater);
    configuration.setCaCertificates(QSslCertificate::fromPath(fixture(QStringLiteral("trusted_ca.crt")), QSsl::Pem));
    socket.setSslConfiguration(configuration);
    socket.setPeerVerifyMode(QSslSocket::VerifyPeer);
    socket.setPeerVerifyName(QStringLiteral("localhost"));
    QSignalSpy encrypted(&socket, &QSslSocket::encrypted);
    socket.connectToHostEncrypted(QStringLiteral("localhost"), port);
    return encrypted.wait(3000);
}

/// Reads bounded chunks and decodes a requested number of responses without sleeping.
bool receive_envelopes(QSslSocket& socket, FrameDecoder& decoder, QList<Envelope>& envelopes, int expected)
{
    QDeadlineTimer deadline(3000ms);
    while (envelopes.size() < expected && !deadline.hasExpired()) {
        if (socket.bytesAvailable() == 0) {
            QSignalSpy ready(&socket, &QSslSocket::readyRead);
            if (!ready.wait(static_cast<int>(deadline.remainingTime()))) {
                return false;
            }
        }

        const QByteArray input = socket.read(tcp_chat::protocol::maximum_buffered_size);
        qsizetype offset       = 0;
        while (offset < input.size()) {
            const qsizetype consumed = decoder.append(QByteArrayView(input.constData() + offset, input.size() - offset));
            offset += consumed;
            bool drained = false;
            while (const auto payload = decoder.next_frame()) {
                drained = true;
                ProtocolError error;
                const auto envelope = tcp_chat::protocol::decode_envelope(*payload, &error);
                if (!envelope.has_value()) {
                    return false;
                }
                envelopes.append(*envelope);
            }
            if (decoder.error() != nullptr || (consumed == 0 && !drained)) {
                return false;
            }
        }
    }
    return envelopes.size() == expected;
}

} // namespace

/// Verifies verified TLS transport, framing integration, and bounded session behavior.
class TlsTransportTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks monotonic heartbeat boundaries without advancing real time.
    void tracksHeartbeatDeadlines();
    /// Rejects invalid session timing and queue bounds.
    void validatesSessionOptions();
    /// Validates credentials and addresses before opening sockets.
    void validatesEndpointConfiguration();
    /// Exchanges envelopes in both directions over a trusted TLS connection.
    void exchangesMessagesOverTrustedTls();
    /// Carries an envelope whose payload requires multiple bounded socket reads.
    void exchangesLargeEnvelope();
    /// Returns to a disconnected state after a refused connection.
    void disconnectsAfterConnectionFailure();
    /// Provides independently verifiable certificate rejection cases.
    void rejectsInvalidServerCertificates_data();
    /// Rejects expired, untrusted, and wrong-host server identities.
    void rejectsInvalidServerCertificates();
    /// Rejects a plaintext client without starting a framed session.
    void rejectsPlaintextConnections();
    /// Answers fragmented and coalesced heartbeat requests in order.
    void answersFragmentedAndCoalescedPings();
    /// Returns a framing error before closing a malformed TLS stream.
    void reportsInvalidFramesBeforeClosing();
    /// Applies backpressure and prevents sends during graceful shutdown.
    void boundsPendingOutputAndClosesGracefully();
    /// Flushes a final application message during client shutdown.
    void flushesClientOutputDuringShutdown();
};

void TlsTransportTest::tracksHeartbeatDeadlines()
{
    Heartbeat heartbeat(100ms, 300ms, 0);
    QVERIFY(!heartbeat.should_ping(99));
    QVERIFY(heartbeat.should_ping(100));
    heartbeat.record_ping(100);
    QVERIFY(!heartbeat.should_ping(199));
    QVERIFY(heartbeat.should_ping(200));
    QVERIFY(!heartbeat.expired(299));
    QVERIFY(heartbeat.expired(300));
    heartbeat.receive(250);
    QVERIFY(!heartbeat.expired(549));
    QVERIFY(heartbeat.expired(550));
}

void TlsTransportTest::validatesSessionOptions()
{
    tcp_chat::transport::SessionOptions options;
    QVERIFY(!tcp_chat::transport::validate_session_options(options).has_value());

    options.maximum_pending_output = tcp_chat::protocol::maximum_buffered_size - 1;
    QCOMPARE(tcp_chat::transport::validate_session_options(options)->code, ErrorCode::InvalidRequest);
    options                    = tcp_chat::transport::SessionOptions { };
    options.heartbeat_interval = options.heartbeat_timeout;
    QCOMPARE(tcp_chat::transport::validate_session_options(options)->code, ErrorCode::InvalidRequest);
    options.shutdown_timeout = 0ms;
    QCOMPARE(tcp_chat::transport::validate_session_options(options)->code, ErrorCode::InvalidRequest);
}

void TlsTransportTest::validatesEndpointConfiguration()
{
    TlsServer server;
    TlsServerConfiguration server_options = server_configuration(QStringLiteral("missing_server"));
    QVERIFY(server.start(server_options).has_value());
    QVERIFY(!server.isListening());
    server_options                  = server_configuration(QStringLiteral("trusted_server"));
    server_options.private_key_file = fixture(QStringLiteral("missing.key"));
    QVERIFY(server.start(server_options).has_value());
    server_options.maximum_connections = 0;
    QVERIFY(server.start(server_options).has_value());

    TlsClient client;
    TlsClientConfiguration client_options;
    QVERIFY(client.connect_to_host(client_options).has_value());
    client_options                     = client_configuration(1);
    client_options.ca_certificate_file = fixture(QStringLiteral("missing_ca.crt"));
    QVERIFY(client.connect_to_host(client_options).has_value());
    QCOMPARE(client.state(), TlsClient::State::Disconnected);
}

void TlsTransportTest::exchangesMessagesOverTrustedTls()
{
    PairHarness pair;
    const auto started = pair.start();
    QVERIFY2(!started.has_value(), qPrintable(started.value_or(QString())));
    QCOMPARE(pair.client.state(), TlsClient::State::Connected);
    QCOMPARE(pair.server.active_connections(), 1);
    QVERIFY(pair.connection_id() > 0);

    Envelope to_client;
    to_client.type       = MessageType::Pong;
    to_client.request_id = QStringLiteral("server-response");
    to_client.payload    = QJsonObject { { QStringLiteral("text"), QStringLiteral("hello") } };
    QVERIFY(!pair.server.send(pair.connection_id(), to_client).has_value());
    QVERIFY(pair.client_messages.wait(3000));
    QCOMPARE(qvariant_cast<Envelope>(pair.client_messages.at(0).at(0)), to_client);

    Envelope to_server;
    to_server.type       = MessageType::Pong;
    to_server.request_id = QStringLiteral("client-response");
    to_server.payload    = QJsonObject { { QStringLiteral("text"), QStringLiteral("reply") } };
    QVERIFY(!pair.client.send(to_server).has_value());
    QVERIFY(pair.server_messages.wait(3000));
    QCOMPARE(pair.server_messages.at(0).at(0).toULongLong(), pair.connection_id());
    QCOMPARE(qvariant_cast<Envelope>(pair.server_messages.at(0).at(1)), to_server);
    QVERIFY(pair.server.send(0, to_server).has_value());
}

void TlsTransportTest::exchangesLargeEnvelope()
{
    PairHarness pair;
    QVERIFY(!pair.start().has_value());
    Envelope message;
    message.type    = MessageType::Pong;
    message.payload = QJsonObject { { QStringLiteral("text"), QString(65000, QLatin1Char('x')) } };
    QVERIFY(tcp_chat::protocol::encode_envelope(message)->size() <= tcp_chat::protocol::maximum_buffered_size);

    QVERIFY(!pair.client.send(message).has_value());
    QTRY_COMPARE(pair.server_messages.size(), 1);
    QCOMPARE(qvariant_cast<Envelope>(pair.server_messages.at(0).at(1)), message);
}

void TlsTransportTest::disconnectsAfterConnectionFailure()
{
    QTcpServer unused_server;
    QVERIFY(unused_server.listen(QHostAddress::LocalHost, 0));
    const quint16 unused_port = unused_server.serverPort();
    unused_server.close();

    TlsClient client;
    QSignalSpy errors(&client, &TlsClient::error);
    QSignalSpy disconnected(&client, &TlsClient::disconnected);
    QVERIFY(!client.connect_to_host(client_configuration(unused_port)).has_value());
    QTRY_VERIFY(!errors.isEmpty());
    QTRY_COMPARE(disconnected.size(), 1);
    QCOMPARE(client.state(), TlsClient::State::Disconnected);
}

void TlsTransportTest::rejectsInvalidServerCertificates_data()
{
    QTest::addColumn<QString>("identity");
    QTest::newRow("expired") << QStringLiteral("expired_server");
    QTest::newRow("untrusted") << QStringLiteral("untrusted_server");
    QTest::newRow("wrong host") << QStringLiteral("wrong_host_server");
}

void TlsTransportTest::rejectsInvalidServerCertificates()
{
    QFETCH(QString, identity);

    TlsServer server;
    const auto server_error = server.start(server_configuration(identity));
    QVERIFY2(!server_error.has_value(), qPrintable(server_error.value_or(QString())));
    TlsClient client;
    QSignalSpy connected(&client, &TlsClient::connected);
    QSignalSpy errors(&client, &TlsClient::error);
    const auto client_error = client.connect_to_host(client_configuration(server.serverPort()));
    QVERIFY(!client_error.has_value());
    QVERIFY(errors.wait(3000));
    QTRY_COMPARE(client.state(), TlsClient::State::Disconnected);
    QVERIFY(connected.isEmpty());
    QCOMPARE(server.active_connections(), 0);
}

void TlsTransportTest::rejectsPlaintextConnections()
{
    TlsServer server;
    QVERIFY(!server.start(server_configuration(QStringLiteral("trusted_server"))).has_value());
    QSignalSpy negotiation_errors(&server, &TlsServer::connection_error);
    QTcpSocket socket;
    socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
    QVERIFY(socket.waitForConnected(1000));
    QSignalSpy disconnected(&socket, &QTcpSocket::disconnected);
    QCOMPARE(socket.write(QByteArrayLiteral("plaintext connection\n")), qint64(21));
    QVERIFY(socket.waitForBytesWritten(1000));
    QVERIFY(disconnected.wait(3000));
    QTRY_VERIFY(!negotiation_errors.isEmpty());
    QCOMPARE(server.active_connections(), 0);
}

void TlsTransportTest::answersFragmentedAndCoalescedPings()
{
    TlsServer server;
    QVERIFY(!server.start(server_configuration(QStringLiteral("trusted_server"))).has_value());
    QSslSocket socket;
    QVERIFY(connect_raw_socket(socket, server.serverPort()));

    Envelope first;
    first.type             = MessageType::Ping;
    first.request_id       = QStringLiteral("first-ping");
    const auto first_frame = tcp_chat::protocol::encode_envelope(first);
    QVERIFY(first_frame.has_value());
    QCOMPARE(socket.write(first_frame->constData(), 1), qint64(1));
    QVERIFY(socket.waitForBytesWritten(1000));
    QCOMPARE(socket.write(first_frame->constData() + 1, 2), qint64(2));
    QVERIFY(socket.waitForBytesWritten(1000));
    QCOMPARE(socket.write(first_frame->constData() + 3, first_frame->size() - 3),
        qint64(first_frame->size() - 3));

    Envelope second;
    second.type             = MessageType::Ping;
    second.request_id       = QStringLiteral("second-ping");
    const auto second_frame = tcp_chat::protocol::encode_envelope(second);
    QVERIFY(second_frame.has_value());
    QCOMPARE(socket.write(*second_frame), qint64(second_frame->size()));

    FrameDecoder decoder;
    QList<Envelope> responses;
    QVERIFY(receive_envelopes(socket, decoder, responses, 2));
    QCOMPARE(responses.size(), 2);
    QCOMPARE(responses.at(0).type, MessageType::Pong);
    QCOMPARE(responses.at(0).request_id, first.request_id);
    QCOMPARE(responses.at(1).type, MessageType::Pong);
    QCOMPARE(responses.at(1).request_id, second.request_id);
}

void TlsTransportTest::reportsInvalidFramesBeforeClosing()
{
    TlsServer server;
    QVERIFY(!server.start(server_configuration(QStringLiteral("trusted_server"))).has_value());
    QSslSocket socket;
    QVERIFY(connect_raw_socket(socket, server.serverPort()));
    QByteArray empty_frame;
    empty_frame.resize(4);

    QCOMPARE(socket.write(empty_frame), qint64(empty_frame.size()));
    FrameDecoder decoder;
    QList<Envelope> responses;
    QVERIFY(receive_envelopes(socket, decoder, responses, 1));
    QCOMPARE(responses.at(0).type, MessageType::Error);
    QCOMPARE(responses.at(0).payload.value(QStringLiteral("code")).toString(), QStringLiteral("invalid_frame"));
    QTRY_COMPARE(socket.state(), QAbstractSocket::UnconnectedState);
}

void TlsTransportTest::boundsPendingOutputAndClosesGracefully()
{
    TlsServer server;
    TlsServerConfiguration server_options         = server_configuration(QStringLiteral("trusted_server"));
    server_options.session.maximum_pending_output = tcp_chat::protocol::maximum_buffered_size;
    QVERIFY(!server.start(server_options).has_value());

    QSslSocket socket;
    QVERIFY(connect_raw_socket(socket, server.serverPort()));
    tcp_chat::transport::SessionOptions session_options;
    session_options.maximum_pending_output = tcp_chat::protocol::maximum_buffered_size;
    session_options.shutdown_timeout       = 1000ms;
    FramedSocket session(&socket, session_options);
    QVERIFY(!session.start().has_value());
    QSignalSpy pending(&session, &FramedSocket::pending_output_changed);
    QSignalSpy disconnected(&session, &FramedSocket::disconnected);

    std::optional<ProtocolError> backpressure;
    for (int index = 0; index < 128 && !backpressure.has_value(); ++index) {
        Envelope message;
        message.type    = MessageType::Pong;
        message.payload = QJsonObject { { QStringLiteral("text"), QString(60000, QLatin1Char('x')) } };
        backpressure    = session.send(message);
        QVERIFY(session.pending_output_bytes() <= session_options.maximum_pending_output);
    }
    QVERIFY(backpressure.has_value());
    QCOMPARE(backpressure->code, ErrorCode::Unavailable);
    for (const auto& arguments : pending) {
        QVERIFY(arguments.at(0).toLongLong() <= session_options.maximum_pending_output);
    }

    session.close();
    const Envelope closing_message;
    QCOMPARE(session.send(closing_message)->code, ErrorCode::InvalidRequest);
    QVERIFY(disconnected.wait(3000));
    QCOMPARE(session.pending_output_bytes(), 0);
}

void TlsTransportTest::flushesClientOutputDuringShutdown()
{
    PairHarness pair;
    QVERIFY(!pair.start().has_value());
    Envelope message;
    message.type       = MessageType::Pong;
    message.request_id = QStringLiteral("final-message");
    message.payload    = QJsonObject { { QStringLiteral("text"), QStringLiteral("delivered before close") } };

    QVERIFY(!pair.client.send(message).has_value());
    pair.client.disconnect_from_host();
    QCOMPARE(pair.client.state(), TlsClient::State::Closing);
    QCOMPARE(pair.client.send(message)->code, ErrorCode::InvalidRequest);
    QVERIFY(pair.server_messages.wait(3000));
    QCOMPARE(qvariant_cast<Envelope>(pair.server_messages.at(0).at(1)), message);
    QTRY_COMPARE(pair.client_disconnected.size(), 1);
    QCOMPARE(pair.client.state(), TlsClient::State::Disconnected);
    QTRY_COMPARE(pair.server.active_connections(), 0);
}

QTEST_GUILESS_MAIN(TlsTransportTest)

#include "test_tls_transport.moc"

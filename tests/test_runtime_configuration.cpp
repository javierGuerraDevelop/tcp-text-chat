#include "client/client_configuration.h"
#include "server_configuration.h"

#include <QCommandLineParser>
#include <QTemporaryDir>
#include <QTest>

namespace {

/// Returns a non-production test certificate path.
QString fixture(const QString& filename)
{
    return QStringLiteral(TCP_CHAT_SOURCE_DIR "/tests/tls_fixtures/") + filename;
}

/// Saves and clears all supported runtime variables without exposing their values.
class RuntimeEnvironment {
public:
    /// Removes runtime configuration for an isolated test.
    RuntimeEnvironment()
    {
        for (const auto& name : names_) {
            present_.append(qEnvironmentVariableIsSet(name.constData()));
            values_.append(qgetenv(name.constData()));
            qunsetenv(name.constData());
        }
    }

    /// Restores the caller's original environment.
    ~RuntimeEnvironment()
    {
        for (qsizetype index = 0; index < names_.size(); ++index) {
            if (present_.at(index)) {
                qputenv(names_.at(index).constData(), values_.at(index));
            } else {
                qunsetenv(names_.at(index).constData());
            }
        }
    }

private:
    const QList<QByteArray> names_ = {
        QByteArrayLiteral("TCP_CHAT_SERVER_HOST"),
        QByteArrayLiteral("TCP_CHAT_SERVER_PORT"),
        QByteArrayLiteral("TCP_CHAT_TLS_CA_FILE"),
        QByteArrayLiteral("TCP_CHAT_TLS_PEER_NAME"),
        QByteArrayLiteral("TCP_CHAT_LISTEN_ADDRESS"),
        QByteArrayLiteral("TCP_CHAT_PORT"),
        QByteArrayLiteral("TCP_CHAT_TLS_CERTIFICATE_FILE"),
        QByteArrayLiteral("TCP_CHAT_TLS_PRIVATE_KEY_FILE"),
        QByteArrayLiteral("TCP_CHAT_DATABASE_PATH"),
        QByteArrayLiteral("TCP_CHAT_MIGRATIONS_PATH"),
        QByteArrayLiteral("TCP_CHAT_OAUTH_CALLBACK_URL"),
        QByteArrayLiteral("TCP_CHAT_OAUTH_LISTEN_ADDRESS"),
        QByteArrayLiteral("TCP_CHAT_OAUTH_LISTEN_PORT"),
        QByteArrayLiteral("TCP_CHAT_OAUTH_TLS_CERTIFICATE_FILE"),
        QByteArrayLiteral("TCP_CHAT_OAUTH_TLS_PRIVATE_KEY_FILE"),
        QByteArrayLiteral("TCP_CHAT_GOOGLE_CLIENT_ID"),
        QByteArrayLiteral("TCP_CHAT_GOOGLE_CLIENT_SECRET"),
        QByteArrayLiteral("TCP_CHAT_GITHUB_CLIENT_ID"),
        QByteArrayLiteral("TCP_CHAT_GITHUB_CLIENT_SECRET"),
    };
    QList<QByteArray> values_;
    QList<bool> present_;
};

/// Creates valid local-only server arguments with optional overrides.
bool parse_server(QCommandLineParser& parser, const QTemporaryDir& directory, const QStringList& overrides = { })
{
    tcp_chat::server::add_server_command_line_options(parser);
    QStringList arguments {
        QStringLiteral("server"),
        QStringLiteral("--certificate"),
        fixture(QStringLiteral("trusted_server.crt")),
        QStringLiteral("--private-key"),
        fixture(QStringLiteral("trusted_server.key")),
        QStringLiteral("--database"),
        directory.filePath(QStringLiteral("data/chat.sqlite")),
        QStringLiteral("--migrations"),
        QStringLiteral(TCP_CHAT_SOURCE_DIR "/migrations"),
    };
    arguments.append(overrides);
    return parser.parse(arguments);
}

/// Supplies two complete test-only provider credential pairs.
void configure_providers()
{
    qputenv("TCP_CHAT_GOOGLE_CLIENT_ID", QByteArrayLiteral("google-test-client"));
    qputenv("TCP_CHAT_GOOGLE_CLIENT_SECRET", QByteArrayLiteral("google-test-secret"));
    qputenv("TCP_CHAT_GITHUB_CLIENT_ID", QByteArrayLiteral("github-test-client"));
    qputenv("TCP_CHAT_GITHUB_CLIENT_SECRET", QByteArrayLiteral("github-test-secret"));
}

} // namespace

/// Verifies executable configuration precedence and startup validation.
class RuntimeConfigurationTest final : public QObject {
    Q_OBJECT

private slots:
    /// Loads local server persistence and TLS with no OAuth listener.
    void local_server_configuration()
    {
        RuntimeEnvironment environment;
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        QCommandLineParser parser;
        QVERIFY(parse_server(parser, directory));
        QString error;
        const auto configuration = tcp_chat::server::load_server_configuration(parser, &error);
        QVERIFY2(configuration.has_value(), qPrintable(error));
        QCOMPARE(configuration->tls.address, QHostAddress::LocalHost);
        QCOMPARE(configuration->tls.port, 10443);
        QCOMPARE(configuration->database_path, directory.filePath(QStringLiteral("data/chat.sqlite")));
        QVERIFY(QDir(directory.filePath(QStringLiteral("data"))).exists());
        QVERIFY(!configuration->authentication.oauth_callback.has_value());
        QVERIFY(configuration->authentication.oauth_providers.isEmpty());
    }

    /// Gives CLI values precedence over environment settings.
    void environment_and_cli_precedence()
    {
        RuntimeEnvironment environment;
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        qputenv("TCP_CHAT_PORT", QByteArrayLiteral("11443"));
        qputenv("TCP_CHAT_TLS_CERTIFICATE_FILE", QByteArrayLiteral("missing-certificate"));
        QCommandLineParser parser;
        QVERIFY(parse_server(parser, directory, { QStringLiteral("--port"), QStringLiteral("12443") }));
        QString error;
        const auto configuration = tcp_chat::server::load_server_configuration(parser, &error);
        QVERIFY2(configuration.has_value(), qPrintable(error));
        QCOMPARE(configuration->tls.port, 12443);
        QCOMPARE(configuration->tls.certificate_chain_file, fixture(QStringLiteral("trusted_server.crt")));

        qputenv("TCP_CHAT_SERVER_HOST", QByteArrayLiteral("chat.example.invalid"));
        qputenv("TCP_CHAT_SERVER_PORT", QByteArrayLiteral("11443"));
        qputenv("TCP_CHAT_TLS_CA_FILE", qPrintable(fixture(QStringLiteral("trusted_ca.crt"))));
        qputenv("TCP_CHAT_TLS_PEER_NAME", QByteArrayLiteral("localhost"));
        QCommandLineParser client_parser;
        tcp_chat::client::add_client_command_line_options(client_parser);
        QVERIFY(client_parser.parse({ QStringLiteral("client") }));
        const auto client = tcp_chat::client::load_client_configuration(client_parser, &error);
        QVERIFY2(client.has_value(), qPrintable(error));
        QCOMPARE(client->host, QStringLiteral("chat.example.invalid"));
        QCOMPARE(client->port, 11443);
        QCOMPARE(client->peer_name, QStringLiteral("localhost"));
        QCOMPARE(client->ca_certificate_file, fixture(QStringLiteral("trusted_ca.crt")));
    }

    /// Rejects missing TLS files, invalid ports, and invalid persistence paths.
    void rejects_invalid_server_settings()
    {
        RuntimeEnvironment environment;
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        QCommandLineParser parser;
        tcp_chat::server::add_server_command_line_options(parser);
        QVERIFY(parser.parse({ QStringLiteral("server") }));
        QString error;
        QVERIFY(!tcp_chat::server::load_server_configuration(parser, &error).has_value());
        QVERIFY(error.contains(QStringLiteral("certificate")));

        QCommandLineParser bad_port;
        QVERIFY(parse_server(bad_port, directory, { QStringLiteral("--port"), QStringLiteral("0") }));
        QVERIFY(!tcp_chat::server::load_server_configuration(bad_port, &error).has_value());
        QVERIFY(error.contains(QStringLiteral("port")));

        QCommandLineParser bad_migrations;
        QVERIFY(parse_server(bad_migrations, directory, { QStringLiteral("--migrations"), directory.filePath(QStringLiteral("missing")) }));
        QVERIFY(!tcp_chat::server::load_server_configuration(bad_migrations, &error).has_value());
        QVERIFY(error.contains(QStringLiteral("migrations")));
    }

    /// Loads both real providers and an exact HTTPS callback without exposing secrets.
    void oauth_server_configuration()
    {
        RuntimeEnvironment environment;
        configure_providers();
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        QCommandLineParser parser;
        QVERIFY(parse_server(parser, directory, {
                                                    QStringLiteral("--oauth-callback"),
                                                    QStringLiteral("https://localhost:10444/oauth/callback"),
                                                    QStringLiteral("--oauth-certificate"),
                                                    fixture(QStringLiteral("trusted_server.crt")),
                                                    QStringLiteral("--oauth-private-key"),
                                                    fixture(QStringLiteral("trusted_server.key")),
                                                }));
        QString error;
        const auto configuration = tcp_chat::server::load_server_configuration(parser, &error);
        QVERIFY2(configuration.has_value(), qPrintable(error));
        QVERIFY(configuration->authentication.oauth_callback.has_value());
        QCOMPARE(configuration->authentication.oauth_callback->port, 10444);
        QCOMPARE(configuration->authentication.oauth_callback->expected_authority, QStringLiteral("localhost:10444"));
        QCOMPARE(configuration->authentication.oauth_callback->callback_path, QStringLiteral("/oauth/callback"));
        QCOMPARE(configuration->authentication.oauth_providers.size(), 2);
        QVERIFY(error.isEmpty());
    }

    /// Rejects missing, insecure, mismatched, or incomplete OAuth settings.
    void rejects_invalid_oauth_settings()
    {
        RuntimeEnvironment environment;
        configure_providers();
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        QString error;
        QCommandLineParser missing_callback;
        QVERIFY(parse_server(missing_callback, directory));
        QVERIFY(!tcp_chat::server::load_server_configuration(missing_callback, &error).has_value());
        QVERIFY(error.contains(QStringLiteral("callback URL")));

        QCommandLineParser insecure;
        QVERIFY(parse_server(insecure, directory, { QStringLiteral("--oauth-callback"), QStringLiteral("http://localhost:10444/oauth/callback") }));
        QVERIFY(!tcp_chat::server::load_server_configuration(insecure, &error).has_value());
        QVERIFY(error.contains(QStringLiteral("HTTPS")));

        QCommandLineParser mismatched;
        QVERIFY(parse_server(mismatched, directory, {
                                                        QStringLiteral("--oauth-callback"),
                                                        QStringLiteral("https://localhost:10444/oauth/callback"),
                                                        QStringLiteral("--oauth-listen-port"),
                                                        QStringLiteral("10445"),
                                                        QStringLiteral("--oauth-certificate"),
                                                        fixture(QStringLiteral("trusted_server.crt")),
                                                        QStringLiteral("--oauth-private-key"),
                                                        fixture(QStringLiteral("trusted_server.key")),
                                                    }));
        QVERIFY(!tcp_chat::server::load_server_configuration(mismatched, &error).has_value());
        QVERIFY(error.contains(QStringLiteral("match")));

        qunsetenv("TCP_CHAT_GITHUB_CLIENT_ID");
        QCommandLineParser incomplete;
        QVERIFY(parse_server(incomplete, directory));
        QVERIFY(!tcp_chat::server::load_server_configuration(incomplete, &error).has_value());
        QVERIFY(error.contains(QStringLiteral("TCP_CHAT_GITHUB_CLIENT_ID")));
        QVERIFY(!error.contains(QStringLiteral("github-test-secret")));
    }

    /// Uses secure client defaults and rejects invalid trust or port settings.
    void client_configuration_validation()
    {
        RuntimeEnvironment environment;
        QString error;
        QCommandLineParser defaults;
        tcp_chat::client::add_client_command_line_options(defaults);
        QVERIFY(defaults.parse({ QStringLiteral("client") }));
        const auto client = tcp_chat::client::load_client_configuration(defaults, &error);
        QVERIFY2(client.has_value(), qPrintable(error));
        QCOMPARE(client->host, QStringLiteral("localhost"));
        QCOMPARE(client->peer_name, QStringLiteral("localhost"));
        QCOMPARE(client->port, 10443);
        QVERIFY(client->ca_certificate_file.isEmpty());

        QCommandLineParser bad_port;
        tcp_chat::client::add_client_command_line_options(bad_port);
        QVERIFY(bad_port.parse({ QStringLiteral("client"), QStringLiteral("--port"), QStringLiteral("0") }));
        QVERIFY(!tcp_chat::client::load_client_configuration(bad_port, &error).has_value());
        QCommandLineParser bad_ca;
        tcp_chat::client::add_client_command_line_options(bad_ca);
        QVERIFY(bad_ca.parse({ QStringLiteral("client"), QStringLiteral("--ca"), QStringLiteral("missing-ca.pem") }));
        QVERIFY(!tcp_chat::client::load_client_configuration(bad_ca, &error).has_value());
        QVERIFY(error.contains(QStringLiteral("CA")));
    }
};

QTEST_GUILESS_MAIN(RuntimeConfigurationTest)
#include "test_runtime_configuration.moc"

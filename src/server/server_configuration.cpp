#include "server_configuration.h"

#include "auth/oauth_provider_factory.h"

#include <QCommandLineParser>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>

namespace tcp_chat::server {
namespace {

    /// Reads a CLI value, then its environment fallback, then a documented default.
    QString setting(const QCommandLineParser& parser, const QString& option, const char* environment, const QString& fallback = QString())
    {
        if (parser.isSet(option)) {
            return parser.value(option);
        }
        const QString value = qEnvironmentVariable(environment);
        return value.isEmpty() ? fallback : value;
    }

    /// Returns a safe configuration error.
    std::optional<ServerConfiguration> invalid(QString* error, const QString& message)
    {
        if (error != nullptr) {
            *error = message;
        }
        return std::nullopt;
    }

    /// Parses a nonzero TCP port.
    std::optional<quint16> parse_port(const QString& value)
    {
        bool valid         = false;
        const quint16 port = value.toUShort(&valid);
        return valid && port != 0 ? std::optional<quint16> { port } : std::nullopt;
    }

    /// Checks that a configured path names a readable regular file.
    bool readable_file(const QString& path)
    {
        const QFileInfo info(path);
        return info.isFile() && info.isReadable();
    }

} // namespace

void add_server_command_line_options(QCommandLineParser& parser)
{
    parser.addOptions({
        { QStringLiteral("listen"), QStringLiteral("Numeric listen address (default: 127.0.0.1)."), QStringLiteral("address") },
        { QStringLiteral("port"), QStringLiteral("Chat TLS listen port (default: 10443)."), QStringLiteral("port") },
        { QStringLiteral("certificate"), QStringLiteral("Server certificate chain PEM file."), QStringLiteral("path") },
        { QStringLiteral("private-key"), QStringLiteral("Server RSA private key PEM file."), QStringLiteral("path") },
        { QStringLiteral("database"), QStringLiteral("SQLite database path."), QStringLiteral("path") },
        { QStringLiteral("migrations"), QStringLiteral("SQL migrations directory (default: ./migrations)."), QStringLiteral("path") },
        { QStringLiteral("oauth-callback"), QStringLiteral("Exact externally registered HTTPS OAuth callback URL."), QStringLiteral("url") },
        { QStringLiteral("oauth-listen"), QStringLiteral("OAuth callback numeric listen address (default: 127.0.0.1)."), QStringLiteral("address") },
        { QStringLiteral("oauth-listen-port"), QStringLiteral("OAuth callback listen port; defaults to the callback URL port."), QStringLiteral("port") },
        { QStringLiteral("oauth-certificate"), QStringLiteral("OAuth callback certificate chain PEM file."), QStringLiteral("path") },
        { QStringLiteral("oauth-private-key"), QStringLiteral("OAuth callback RSA private key PEM file."), QStringLiteral("path") },
    });
}

std::optional<ServerConfiguration> load_server_configuration(const QCommandLineParser& parser, QString* error)
{
    ServerConfiguration configuration;
    if (!configuration.tls.address.setAddress(setting(parser, QStringLiteral("listen"), "TCP_CHAT_LISTEN_ADDRESS", QStringLiteral("127.0.0.1")).trimmed())
        || configuration.tls.address.isNull()) {
        return invalid(error, QStringLiteral("The chat listen address must be a numeric IP address"));
    }
    const auto port = parse_port(setting(parser, QStringLiteral("port"), "TCP_CHAT_PORT", QStringLiteral("10443")));
    if (!port.has_value()) {
        return invalid(error, QStringLiteral("The chat listen port must be between 1 and 65535"));
    }
    configuration.tls.port                   = *port;
    configuration.tls.certificate_chain_file = setting(parser, QStringLiteral("certificate"), "TCP_CHAT_TLS_CERTIFICATE_FILE");
    configuration.tls.private_key_file       = setting(parser, QStringLiteral("private-key"), "TCP_CHAT_TLS_PRIVATE_KEY_FILE");
    if (!readable_file(configuration.tls.certificate_chain_file) || !readable_file(configuration.tls.private_key_file)) {
        return invalid(error, QStringLiteral("Chat TLS certificate and private key files must be readable regular files"));
    }

    configuration.database_path = setting(parser, QStringLiteral("database"), "TCP_CHAT_DATABASE_PATH");
    if (configuration.database_path.isEmpty()) {
        const QString data_directory = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        if (data_directory.isEmpty()) {
            return invalid(error, QStringLiteral("The application data directory is unavailable; set a database path explicitly"));
        }
        configuration.database_path = data_directory + QStringLiteral("/chat.sqlite");
    }
    configuration.migrations_path = setting(parser, QStringLiteral("migrations"), "TCP_CHAT_MIGRATIONS_PATH",
        QDir::current().absoluteFilePath(QStringLiteral("migrations")));
    if (QFileInfo(configuration.database_path).isDir()) {
        return invalid(error, QStringLiteral("The database path must name a SQLite file"));
    }
    QDir database_directory = QFileInfo(configuration.database_path).absoluteDir();
    if (!database_directory.exists() && !database_directory.mkpath(QStringLiteral("."))) {
        return invalid(error, QStringLiteral("The database parent directory could not be created"));
    }
    const QFileInfo migrations_info(configuration.migrations_path);
    if (!migrations_info.isDir() || !migrations_info.isReadable()) {
        return invalid(error, QStringLiteral("The migrations path must be a readable directory"));
    }

    QList<std::shared_ptr<auth::OAuthProvider>> providers;
    if (const auto provider_error = auth::load_oauth_providers_from_environment(&providers); provider_error.has_value()) {
        return invalid(error, *provider_error);
    }
    const QString callback = setting(parser, QStringLiteral("oauth-callback"), "TCP_CHAT_OAUTH_CALLBACK_URL");
    if (!providers.isEmpty() && callback.isEmpty()) {
        return invalid(error, QStringLiteral("An OAuth callback URL is required when provider credentials are configured"));
    }
    if (providers.isEmpty() && !callback.isEmpty()) {
        return invalid(error, QStringLiteral("OAuth callback configuration requires at least one provider credential pair"));
    }
    if (providers.isEmpty()) {
        if (error != nullptr) {
            error->clear();
        }
        return configuration;
    }

    const QUrl callback_url(callback, QUrl::StrictMode);
    if (!callback_url.isValid() || callback_url.scheme() != QStringLiteral("https") || callback_url.host().isEmpty()
        || !callback_url.userInfo().isEmpty() || callback_url.hasQuery() || callback_url.hasFragment()
        || !callback_url.path().startsWith(QLatin1Char('/')) || callback_url.path().isEmpty()) {
        return invalid(error, QStringLiteral("The OAuth callback must be an exact HTTPS URL with a path and no credentials, query, or fragment"));
    }
    const auto oauth_port_setting = setting(parser, QStringLiteral("oauth-listen-port"), "TCP_CHAT_OAUTH_LISTEN_PORT");
    const auto oauth_port         = oauth_port_setting.isEmpty()
        ? std::optional<quint16> { static_cast<quint16>(callback_url.port(443)) }
        : parse_port(oauth_port_setting);
    if (!oauth_port.has_value()) {
        return invalid(error, QStringLiteral("The OAuth callback listen port must be between 1 and 65535"));
    }
    if (*oauth_port != callback_url.port(443)) {
        return invalid(error, QStringLiteral("The OAuth callback listen port must match the callback URL port"));
    }

    auth::OAuthCallbackServerOptions callback_options;
    if (!callback_options.address.setAddress(setting(parser, QStringLiteral("oauth-listen"), "TCP_CHAT_OAUTH_LISTEN_ADDRESS", QStringLiteral("127.0.0.1")).trimmed())
        || callback_options.address.isNull()) {
        return invalid(error, QStringLiteral("The OAuth callback listen address must be a numeric IP address"));
    }
    callback_options.port                   = *oauth_port;
    callback_options.expected_authority     = callback_url.authority(QUrl::FullyEncoded);
    callback_options.callback_path          = callback_url.path();
    callback_options.certificate_chain_file = setting(parser, QStringLiteral("oauth-certificate"), "TCP_CHAT_OAUTH_TLS_CERTIFICATE_FILE");
    callback_options.private_key_file       = setting(parser, QStringLiteral("oauth-private-key"), "TCP_CHAT_OAUTH_TLS_PRIVATE_KEY_FILE");
    if (!readable_file(callback_options.certificate_chain_file) || !readable_file(callback_options.private_key_file)) {
        return invalid(error, QStringLiteral("OAuth callback TLS certificate and private key files must be readable regular files"));
    }

    configuration.authentication.oauth_callback  = std::move(callback_options);
    configuration.authentication.oauth_providers = std::move(providers);
    if (error != nullptr) {
        error->clear();
    }
    return configuration;
}

} // namespace tcp_chat::server

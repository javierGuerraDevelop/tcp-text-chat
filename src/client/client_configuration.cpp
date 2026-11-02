#include "client_configuration.h"

#include <QCommandLineParser>
#include <QFileInfo>

namespace tcp_chat::client {
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

    /// Returns a configuration error without reproducing supplied connection values.
    std::optional<TlsClientConfiguration> invalid(QString* error, const QString& message)
    {
        if (error != nullptr) {
            *error = message;
        }
        return std::nullopt;
    }

} // namespace

void add_client_command_line_options(QCommandLineParser& parser)
{
    parser.addOptions({
        { QStringLiteral("host"), QStringLiteral("Chat server hostname (default: localhost)."), QStringLiteral("host") },
        { QStringLiteral("port"), QStringLiteral("Chat server TLS port (default: 10443)."), QStringLiteral("port") },
        { QStringLiteral("ca"), QStringLiteral("Optional private CA PEM file; system trust is used otherwise."), QStringLiteral("path") },
        { QStringLiteral("peer-name"), QStringLiteral("Optional certificate verification name; defaults to the host."), QStringLiteral("name") },
    });
}

std::optional<TlsClientConfiguration> load_client_configuration(const QCommandLineParser& parser, QString* error)
{
    TlsClientConfiguration configuration;
    configuration.host                = setting(parser, QStringLiteral("host"), "TCP_CHAT_SERVER_HOST", QStringLiteral("localhost")).trimmed();
    configuration.peer_name           = setting(parser, QStringLiteral("peer-name"), "TCP_CHAT_TLS_PEER_NAME").trimmed();
    configuration.ca_certificate_file = setting(parser, QStringLiteral("ca"), "TCP_CHAT_TLS_CA_FILE");
    if (configuration.host.isEmpty()) {
        return invalid(error, QStringLiteral("The server hostname must not be empty"));
    }
    if (configuration.peer_name.isEmpty()) {
        configuration.peer_name = configuration.host;
    }

    const QString port = setting(parser, QStringLiteral("port"), "TCP_CHAT_SERVER_PORT", QStringLiteral("10443"));
    bool valid_port    = false;
    configuration.port = port.toUShort(&valid_port);
    if (!valid_port || configuration.port == 0) {
        return invalid(error, QStringLiteral("The server port must be between 1 and 65535"));
    }
    if (!configuration.ca_certificate_file.isEmpty() && !QFileInfo(configuration.ca_certificate_file).isReadable()) {
        return invalid(error, QStringLiteral("The trusted CA file must be readable"));
    }
    if (error != nullptr) {
        error->clear();
    }
    return configuration;
}

} // namespace tcp_chat::client

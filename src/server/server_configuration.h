#pragma once

#include "auth/authentication_service.h"
#include "tls_server.h"

class QCommandLineParser;

namespace tcp_chat::server {

/// Contains validated startup settings for the headless chat server.
struct ServerConfiguration {
    TlsServerConfiguration tls;
    QString database_path;
    QString migrations_path;
    auth::AuthenticationServiceOptions authentication;
};

/// Adds listener, persistence, TLS, and OAuth options to the server command line.
void add_server_command_line_options(QCommandLineParser& parser);

/// Loads and validates startup configuration without logging credentials or secret values.
std::optional<ServerConfiguration> load_server_configuration(const QCommandLineParser& parser, QString* error);

} // namespace tcp_chat::server

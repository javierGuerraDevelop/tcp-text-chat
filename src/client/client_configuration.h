#pragma once

#include "tls_client.h"

class QCommandLineParser;

namespace tcp_chat::client {

/// Adds server connection and private-CA options to the client command line.
void add_client_command_line_options(QCommandLineParser& parser);

/// Loads a verified TLS client configuration from CLI overrides and environment settings.
std::optional<TlsClientConfiguration> load_client_configuration(const QCommandLineParser& parser, QString* error);

} // namespace tcp_chat::client

#include "auth/authentication_service.h"
#include "chat/message_service.h"
#include "server_configuration.h"
#include "tcp_chat/version.h"
#include "tls_server.h"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QLoggingCategory>
#include <QTextStream>

Q_LOGGING_CATEGORY(server_log, "tcp_chat.server")

/// Starts the configured TLS chat server and runs until termination.
int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("tcp-text-chat"));
    QCoreApplication::setApplicationName(QStringLiteral("tcp-text-chat-server"));
    QCoreApplication::setApplicationVersion(tcp_chat::application_version());

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("TCP text chat server"));
    parser.addHelpOption();
    parser.addVersionOption();
    tcp_chat::server::add_server_command_line_options(parser);
    parser.process(app);

    QString error;
    const auto configuration = tcp_chat::server::load_server_configuration(parser, &error);
    if (!configuration.has_value()) {
        QTextStream(stderr) << "Server configuration error: " << error << Qt::endl;
        return 2;
    }

    tcp_chat::server::TlsServer server;
    if (const auto start_error = server.start(configuration->tls); start_error.has_value()) {
        QTextStream(stderr) << "Server startup error: " << *start_error << Qt::endl;
        return 2;
    }
    tcp_chat::auth::AuthenticationService authentication(&server, configuration->authentication);
    tcp_chat::chat::MessageService messaging(&server, &authentication);
    QObject::connect(&messaging, &tcp_chat::chat::MessageService::ready, &app, [](bool success, const QString& message) {
        if (!success) {
            qCCritical(server_log) << "Messaging startup failed:" << message;
            QCoreApplication::exit(1);
            return;
        }
        qCInfo(server_log) << "Messaging service is ready";
    });
    QObject::connect(&authentication, &tcp_chat::auth::AuthenticationService::ready, &app,
        [&messaging, &configuration](bool success, const QString& message) {
            if (!success) {
                qCCritical(server_log) << "Authentication startup failed:" << message;
                QCoreApplication::exit(1);
                return;
            }
            qCInfo(server_log) << "Authentication service is ready";
            if (const auto error = messaging.start(configuration->database_path, configuration->migrations_path); error.has_value()) {
                qCCritical(server_log) << "Messaging startup failed:" << *error;
                QCoreApplication::exit(1);
            }
        });
    QObject::connect(&server, &tcp_chat::server::TlsServer::connection_error, &app, [](const QString& message) {
        qCWarning(server_log) << "Client connection failed:" << message;
    });
    QObject::connect(&app, &QCoreApplication::aboutToQuit, &server, &tcp_chat::server::TlsServer::close);
    if (const auto start_error = authentication.start(configuration->database_path, configuration->migrations_path); start_error.has_value()) {
        QTextStream(stderr) << "Authentication startup error: " << *start_error << Qt::endl;
        return 2;
    }

    qCInfo(server_log) << "Chat server listening on" << configuration->tls.address.toString() << "port" << configuration->tls.port;
    return QCoreApplication::exec();
}

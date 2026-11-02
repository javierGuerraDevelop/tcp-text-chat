#include "authentication_controller.h"
#include "client_application.h"
#include "client_configuration.h"
#include "main_window.h"
#include "tcp_chat/version.h"
#include "theme_manager.h"
#include "tls_client.h"

#include <QApplication>
#include <QCommandLineParser>
#include <QTextStream>

/// Starts the desktop client and connects its authentication flow to the configured server.
int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("tcp-text-chat"));
    QCoreApplication::setApplicationName(QStringLiteral("tcp-text-chat-client"));
    QCoreApplication::setApplicationVersion(tcp_chat::application_version());

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("TCP text chat client"));
    parser.addHelpOption();
    parser.addVersionOption();
    tcp_chat::client::add_client_command_line_options(parser);
    parser.process(app);
    QString error;
    const auto configuration = tcp_chat::client::load_client_configuration(parser, &error);
    if (!configuration.has_value()) {
        QTextStream(stderr) << "Client configuration error: " << error << Qt::endl;
        return 2;
    }

    tcp_chat::client::TlsClient socket;
    tcp_chat::client::AuthenticationController controller(&socket);
    tcp_chat::client::ThemeManager theme_manager(app);
    tcp_chat::client::MainWindow window(theme_manager);
    tcp_chat::client::ClientApplication application(window, controller, *configuration);
    window.show();
    application.start();
    return QApplication::exec();
}

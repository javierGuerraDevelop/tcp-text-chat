#include "tcp_chat/version.h"

#include <QCommandLineParser>
#include <QCoreApplication>

/// Starts the server and processes its command-line metadata options.
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
    parser.process(app);

    return 0;
}

#include "main_window.h"
#include "tcp_chat/version.h"
#include "theme_manager.h"

#include <QApplication>
#include <QCommandLineParser>

/// Starts the desktop client and applies its persisted appearance.
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
    parser.process(app);

    tcp_chat::client::ThemeManager theme_manager(app);
    tcp_chat::client::MainWindow window(theme_manager);
    window.show();
    return QApplication::exec();
}

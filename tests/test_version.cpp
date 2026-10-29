#include "tcp_chat/version.h"

#include <QTest>

/// Verifies shared application metadata.
class VersionTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks that the library reports the version supplied by CMake.
    void reportsProjectVersion() const;
};

void VersionTest::reportsProjectVersion() const
{
    QCOMPARE(tcp_chat::application_version(), QStringLiteral(TCP_CHAT_APPLICATION_VERSION));
}

QTEST_GUILESS_MAIN(VersionTest)

#include "test_version.moc"

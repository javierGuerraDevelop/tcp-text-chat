#include "storage/database_worker.h"

#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QThread>

Q_DECLARE_METATYPE(tcp_chat::storage::StorageErrorCode)

/// Verifies correlated OAuth account operations on the database thread.
class OAuthDatabaseWorkerTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks independent request IDs and repeat identity resolution.
    void correlatesAccountRequests();
};

void OAuthDatabaseWorkerTest::correlatesAccountRequests()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    QThread thread;
    auto* worker = new tcp_chat::storage::DatabaseWorker;
    worker->moveToThread(&thread);
    QObject::connect(&thread, &QThread::finished, worker, &QObject::deleteLater);
    thread.start();
    QSignalSpy opened(worker, &tcp_chat::storage::DatabaseWorker::opened);
    QVERIFY(QMetaObject::invokeMethod(worker, "open", Qt::QueuedConnection,
        Q_ARG(QString, temporary.filePath(QStringLiteral("chat.sqlite"))),
        Q_ARG(QString, QStringLiteral(TCP_CHAT_SOURCE_DIR "/migrations")), Q_ARG(qint64, 1000)));
    QVERIFY(opened.wait(5000) || !opened.isEmpty());
    QCOMPARE(opened.at(0).at(0).toLongLong(), 1);

    tcp_chat::storage::NewOAuthUser first { QStringLiteral("fake"), QStringLiteral("subject-1"),
        QStringLiteral("user_first"), QStringLiteral("user_first"), QStringLiteral("user_first"), 1000 };
    tcp_chat::storage::NewOAuthUser second = first;
    second.username                        = QStringLiteral("user_second");
    second.normalized_username             = second.username;
    second.display_name                    = second.username;
    QSignalSpy resolved(worker, &tcp_chat::storage::DatabaseWorker::oauth_user_resolved);
    QVERIFY(QMetaObject::invokeMethod(worker, "find_or_create_oauth_user", Qt::QueuedConnection,
        Q_ARG(quint64, 91), Q_ARG(tcp_chat::storage::NewOAuthUser, first)));
    QVERIFY(QMetaObject::invokeMethod(worker, "find_or_create_oauth_user", Qt::QueuedConnection,
        Q_ARG(quint64, 17), Q_ARG(tcp_chat::storage::NewOAuthUser, second)));
    QTRY_COMPARE(resolved.size(), 2);
    QCOMPARE(resolved.at(0).at(0).toULongLong(), 91);
    QCOMPARE(resolved.at(1).at(0).toULongLong(), 17);
    const auto created  = qvariant_cast<tcp_chat::storage::UserRecord>(resolved.at(0).at(1));
    const auto existing = qvariant_cast<tcp_chat::storage::UserRecord>(resolved.at(1).at(1));
    QCOMPARE(created, existing);
    QCOMPARE(created.password_hash, std::nullopt);
    QVERIFY(QMetaObject::invokeMethod(worker, "close", Qt::BlockingQueuedConnection));
    thread.quit();
    QVERIFY(thread.wait(5000));
}

QTEST_GUILESS_MAIN(OAuthDatabaseWorkerTest)

#include "test_oauth_database_worker.moc"

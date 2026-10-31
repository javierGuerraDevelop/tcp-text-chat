#include "storage/database_worker.h"

#include "storage_test_utils.h"

#include <QMetaObject>
#include <QSignalSpy>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <QTest>
#include <QThread>

Q_DECLARE_METATYPE(tcp_chat::storage::StorageErrorCode)

namespace {

/// Owns a running worker thread and closes it before destruction.
class WorkerHarness {
public:
    /// Starts a thread with a worker moved into it.
    WorkerHarness()
    {
        worker_ = new tcp_chat::storage::DatabaseWorker;
        worker_->moveToThread(&thread_);
        QObject::connect(&thread_, &QThread::finished, worker_, &QObject::deleteLater);
        thread_.start();
    }

    /// Closes the worker and stops its thread.
    ~WorkerHarness()
    {
        if (thread_.isRunning()) {
            QMetaObject::invokeMethod(worker_, "close", Qt::BlockingQueuedConnection);
            thread_.quit();
            thread_.wait(5000);
        }
    }

    WorkerHarness(const WorkerHarness&)            = delete;
    WorkerHarness& operator=(const WorkerHarness&) = delete;

    /// Returns the worker for queued test invocations and signal spies.
    tcp_chat::storage::DatabaseWorker* worker() const
    {
        return worker_;
    }

private:
    QThread thread_;
    tcp_chat::storage::DatabaseWorker* worker_ = nullptr;
};

/// Queues a database open request on the worker thread.
bool queue_open(tcp_chat::storage::DatabaseWorker* worker, const QString& database, const QString& migrations)
{
    return QMetaObject::invokeMethod(worker, "open", Qt::QueuedConnection, Q_ARG(QString, database),
        Q_ARG(QString, migrations), Q_ARG(qint64, 1000));
}

/// Queues a database close request on the worker thread.
bool queue_close(tcp_chat::storage::DatabaseWorker* worker)
{
    return QMetaObject::invokeMethod(worker, "close", Qt::QueuedConnection);
}

} // namespace

/// Verifies database ownership and cleanup across the worker lifecycle.
class DatabaseWorkerTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks successful migration, schema visibility, and clean close.
    void opensAndClosesOnWorkerThread();
    /// Checks cleanup and reopen after a failed migration.
    void reopensAfterFailedOpen();
    /// Checks duplicate open rejection without replacing the connection.
    void rejectsDuplicateOpen();
};

void DatabaseWorkerTest::opensAndClosesOnWorkerThread()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    const QString database_path = temporary.filePath(QStringLiteral("chat.sqlite"));
    WorkerHarness harness;
    QSignalSpy opened(harness.worker(), &tcp_chat::storage::DatabaseWorker::opened);
    QSignalSpy closed(harness.worker(), &tcp_chat::storage::DatabaseWorker::closed);

    QVERIFY(queue_open(harness.worker(), database_path, tcp_chat::testing::migration_directory()));
    QVERIFY(opened.wait(5000) || !opened.isEmpty());
    QCOMPARE(opened.size(), 1);
    QCOMPARE(opened.at(0).at(0).toLongLong(), 1);
    const auto error = qvariant_cast<tcp_chat::storage::StorageError>(opened.at(0).at(1));
    QCOMPARE(error.code, tcp_chat::storage::StorageErrorCode::None);

    tcp_chat::testing::TestDatabase checker(database_path);
    QVERIFY(checker.database().open());
    QSqlQuery query(checker.database());
    QVERIFY(query.exec(QStringLiteral("SELECT COUNT(*) FROM users")));
    QVERIFY(query.next());

    QVERIFY(queue_close(harness.worker()));
    QVERIFY(closed.wait(5000) || !closed.isEmpty());
    QCOMPARE(closed.size(), 1);
    harness.worker()->thread()->quit();
    QVERIFY(harness.worker()->thread()->wait(5000));
}

void DatabaseWorkerTest::reopensAfterFailedOpen()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    const QString database_path = temporary.filePath(QStringLiteral("chat.sqlite"));
    WorkerHarness harness;
    QSignalSpy opened(harness.worker(), &tcp_chat::storage::DatabaseWorker::opened);

    QVERIFY(queue_open(harness.worker(), database_path, temporary.filePath(QStringLiteral("missing"))));
    QVERIFY(opened.wait(5000) || !opened.isEmpty());
    QCOMPARE(opened.size(), 1);
    QCOMPARE(opened.at(0).at(0).toLongLong(), -1);
    auto error = qvariant_cast<tcp_chat::storage::StorageError>(opened.at(0).at(1));
    QCOMPARE(error.code, tcp_chat::storage::StorageErrorCode::InvalidMigration);

    QVERIFY(queue_open(harness.worker(), database_path, tcp_chat::testing::migration_directory()));
    QVERIFY(opened.wait(5000) || !opened.isEmpty());
    QCOMPARE(opened.size(), 2);
    QCOMPARE(opened.at(1).at(0).toLongLong(), 1);
    error = qvariant_cast<tcp_chat::storage::StorageError>(opened.at(1).at(1));
    QCOMPARE(error.code, tcp_chat::storage::StorageErrorCode::None);
}

void DatabaseWorkerTest::rejectsDuplicateOpen()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    const QString database_path = temporary.filePath(QStringLiteral("chat.sqlite"));
    WorkerHarness harness;
    QSignalSpy opened(harness.worker(), &tcp_chat::storage::DatabaseWorker::opened);

    QVERIFY(queue_open(harness.worker(), database_path, tcp_chat::testing::migration_directory()));
    QVERIFY(opened.wait(5000) || !opened.isEmpty());
    QVERIFY(queue_open(harness.worker(), database_path, tcp_chat::testing::migration_directory()));
    QVERIFY(opened.wait(5000) || !opened.isEmpty());
    QCOMPARE(opened.size(), 2);
    QCOMPARE(opened.at(1).at(0).toLongLong(), -1);
    const auto error = qvariant_cast<tcp_chat::storage::StorageError>(opened.at(1).at(1));
    QCOMPARE(error.code, tcp_chat::storage::StorageErrorCode::InvalidInput);
}

QTEST_GUILESS_MAIN(DatabaseWorkerTest)

#include "test_database_worker.moc"

#include "storage/migration_runner.h"

#include "storage_test_utils.h"

#include <QDir>
#include <QFile>
#include <QSet>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <QTest>

Q_DECLARE_METATYPE(tcp_chat::storage::StorageErrorCode)

namespace {

/// Writes a UTF-8 test migration and returns whether the operation succeeded.
bool write_script(const QString& path, const QByteArray& contents)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }
    return file.write(contents) == contents.size();
}

} // namespace

/// Verifies transactional schema migration behavior.
class MigrationRunnerTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks the initial tables, pragmas, and migration timestamp.
    void appliesInitialSchema();
    /// Checks that an up-to-date database performs no writes.
    void repeatsWithoutReapplying();
    /// Checks that foreign key enforcement is active per connection.
    void enforcesForeignKeys();
    /// Checks rollback of a later partially executed migration.
    void rollsBackFailedMigration();
    /// Checks semicolons inside strings and comments.
    void handlesSemicolonsInSqlScripts();
    /// Checks rejection of a missing intermediate version.
    void rejectsMigrationGaps();
    /// Checks rejection of two files with the same numeric version.
    void rejectsDuplicateVersions();
    /// Checks the supported in-memory journal-mode exception.
    void allowsMemoryDatabaseWithoutWal();
};

void MigrationRunnerTest::appliesInitialSchema()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(connection.database().open());

    tcp_chat::storage::StorageError error;
    const auto result = tcp_chat::storage::MigrationRunner::migrate(
        connection.database(), tcp_chat::testing::migration_directory(), 123456, &error);
    QVERIFY(result.has_value());
    QCOMPARE(result->current_version, 1);
    QCOMPARE(result->applied_versions, QList<int> { 1 });
    QCOMPARE(error.code, tcp_chat::storage::StorageErrorCode::None);

    QSet<QString> tables;
    QSqlQuery query(connection.database());
    QVERIFY(query.exec(QStringLiteral("SELECT name FROM sqlite_master WHERE type = 'table'")));
    while (query.next()) {
        tables.insert(query.value(0).toString());
    }
    for (const QString& table : { QStringLiteral("schema_migrations"), QStringLiteral("users"),
             QStringLiteral("oauth_accounts"), QStringLiteral("sessions"), QStringLiteral("messages") }) {
        QVERIFY(tables.contains(table));
    }

    QVERIFY(query.exec(QStringLiteral("SELECT applied_at FROM schema_migrations WHERE version = 1")));
    QVERIFY(query.next());
    QCOMPARE(query.value(0).toLongLong(), 123456);
    QVERIFY(query.exec(QStringLiteral("PRAGMA foreign_keys")));
    QVERIFY(query.next());
    QCOMPARE(query.value(0).toInt(), 1);
    QVERIFY(query.exec(QStringLiteral("PRAGMA journal_mode")));
    QVERIFY(query.next());
    QCOMPARE(query.value(0).toString().toLower(), QStringLiteral("wal"));
    QVERIFY(query.exec(QStringLiteral("PRAGMA busy_timeout")));
    QVERIFY(query.next());
    QCOMPARE(query.value(0).toInt(), 5000);
}

void MigrationRunnerTest::repeatsWithoutReapplying()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(connection.database().open());

    const auto first = tcp_chat::storage::MigrationRunner::migrate(
        connection.database(), tcp_chat::testing::migration_directory(), 1000);
    QVERIFY(first.has_value());
    const auto second = tcp_chat::storage::MigrationRunner::migrate(
        connection.database(), tcp_chat::testing::migration_directory(), 2000);
    QVERIFY(second.has_value());
    QCOMPARE(second->current_version, 1);
    QVERIFY(second->applied_versions.isEmpty());

    QSqlQuery query(connection.database());
    QVERIFY(query.exec(QStringLiteral("SELECT COUNT(*), applied_at FROM schema_migrations WHERE version = 1")));
    QVERIFY(query.next());
    QCOMPARE(query.value(0).toInt(), 1);
    QCOMPARE(query.value(1).toLongLong(), 1000);
}

void MigrationRunnerTest::enforcesForeignKeys()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(connection.database().open());
    QVERIFY(tcp_chat::storage::MigrationRunner::migrate(
        connection.database(), tcp_chat::testing::migration_directory(), 1000)
            .has_value());

    QSqlQuery query(connection.database());
    QVERIFY(!query.exec(QStringLiteral("INSERT INTO sessions(user_id, token_digest, created_at, expires_at, last_seen_at) "
                                       "VALUES(999, X'00', 1, 2, 1)")));
}

void MigrationRunnerTest::rollsBackFailedMigration()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    QDir migrations(temporary.filePath(QStringLiteral("migrations")));
    QVERIFY(migrations.mkpath(QStringLiteral(".")));
    QVERIFY(QFile::copy(tcp_chat::testing::migration_directory() + QStringLiteral("/0001_initial.sql"),
        migrations.filePath(QStringLiteral("0001_initial.sql"))));
    QVERIFY(write_script(migrations.filePath(QStringLiteral("0002_broken.sql")),
        QByteArrayLiteral("CREATE TABLE broken(value TEXT); INSERT INTO missing_table VALUES(1);")));

    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(connection.database().open());
    tcp_chat::storage::StorageError error;
    const auto result = tcp_chat::storage::MigrationRunner::migrate(connection.database(), migrations.path(), 1000, &error);
    QVERIFY(!result.has_value());
    QCOMPARE(error.code, tcp_chat::storage::StorageErrorCode::QueryFailed);

    QSqlQuery query(connection.database());
    QVERIFY(query.exec(QStringLiteral("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'broken'")));
    QVERIFY(query.next());
    QCOMPARE(query.value(0).toInt(), 0);
    QVERIFY(query.exec(QStringLiteral("SELECT MAX(version) FROM schema_migrations")));
    QVERIFY(query.next());
    QCOMPARE(query.value(0).toInt(), 1);
}

void MigrationRunnerTest::handlesSemicolonsInSqlScripts()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    QDir migrations(temporary.filePath(QStringLiteral("migrations")));
    QVERIFY(migrations.mkpath(QStringLiteral(".")));
    QVERIFY(write_script(migrations.filePath(QStringLiteral("0001_examples.sql")),
        QByteArrayLiteral("-- comment ; ignored\n"
                          "CREATE TABLE examples(value TEXT);\n"
                          "INSERT INTO examples VALUES('semi;colon');\n"
                          "/* block ; comment */\n")));

    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(connection.database().open());
    const auto result = tcp_chat::storage::MigrationRunner::migrate(connection.database(), migrations.path(), 1000);
    QVERIFY(result.has_value());

    QSqlQuery query(connection.database());
    QVERIFY(query.exec(QStringLiteral("SELECT value FROM examples")));
    QVERIFY(query.next());
    QCOMPARE(query.value(0).toString(), QStringLiteral("semi;colon"));
}

void MigrationRunnerTest::rejectsMigrationGaps()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    QDir migrations(temporary.filePath(QStringLiteral("migrations")));
    QVERIFY(migrations.mkpath(QStringLiteral(".")));
    QVERIFY(write_script(migrations.filePath(QStringLiteral("0002_gap.sql")),
        QByteArrayLiteral("CREATE TABLE skipped(value TEXT);")));

    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(connection.database().open());
    tcp_chat::storage::StorageError error;
    const auto result = tcp_chat::storage::MigrationRunner::migrate(connection.database(), migrations.path(), 1000, &error);
    QVERIFY(!result.has_value());
    QCOMPARE(error.code, tcp_chat::storage::StorageErrorCode::InvalidMigration);
}

void MigrationRunnerTest::rejectsDuplicateVersions()
{
    QTemporaryDir temporary;
    QVERIFY(temporary.isValid());
    QDir migrations(temporary.filePath(QStringLiteral("migrations")));
    QVERIFY(migrations.mkpath(QStringLiteral(".")));
    QVERIFY(write_script(migrations.filePath(QStringLiteral("0001_first.sql")),
        QByteArrayLiteral("CREATE TABLE first_table(value TEXT);")));
    QVERIFY(write_script(migrations.filePath(QStringLiteral("0001_second.sql")),
        QByteArrayLiteral("CREATE TABLE second_table(value TEXT);")));

    tcp_chat::testing::TestDatabase connection(temporary.filePath(QStringLiteral("chat.sqlite")));
    QVERIFY(connection.database().open());
    tcp_chat::storage::StorageError error;
    const auto result = tcp_chat::storage::MigrationRunner::migrate(connection.database(), migrations.path(), 1000, &error);
    QVERIFY(!result.has_value());
    QCOMPARE(error.code, tcp_chat::storage::StorageErrorCode::InvalidMigration);
}

void MigrationRunnerTest::allowsMemoryDatabaseWithoutWal()
{
    tcp_chat::testing::TestDatabase connection(QStringLiteral(":memory:"));
    QVERIFY(connection.database().open());
    const auto result = tcp_chat::storage::MigrationRunner::migrate(
        connection.database(), tcp_chat::testing::migration_directory(), 1000);
    QVERIFY(result.has_value());

    QSqlQuery query(connection.database());
    QVERIFY(query.exec(QStringLiteral("PRAGMA journal_mode")));
    QVERIFY(query.next());
    QCOMPARE(query.value(0).toString().toLower(), QStringLiteral("memory"));
}

QTEST_GUILESS_MAIN(MigrationRunnerTest)

#include "test_migration_runner.moc"

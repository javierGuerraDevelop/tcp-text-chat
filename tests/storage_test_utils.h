#pragma once

#include <QAtomicInteger>
#include <QSqlDatabase>
#include <QString>

namespace tcp_chat::testing {

/// Owns a uniquely named test connection and removes it after dependent objects are destroyed.
class TestDatabase {
public:
    /// Creates a closed SQLite connection for a test-selected path.
    explicit TestDatabase(const QString& path)
    {
        static QAtomicInteger<quint64> sequence;
        connection_name_ = QStringLiteral("storage_test_%1").arg(sequence.fetchAndAddRelaxed(1));
        database_        = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connection_name_);
        database_.setDatabaseName(path);
    }

    /// Closes and removes the named connection.
    ~TestDatabase()
    {
        database_.close();
        database_ = QSqlDatabase { };
        QSqlDatabase::removeDatabase(connection_name_);
    }

    TestDatabase(const TestDatabase&)            = delete;
    TestDatabase& operator=(const TestDatabase&) = delete;

    /// Returns the underlying connection for use on the current thread.
    QSqlDatabase& database()
    {
        return database_;
    }

private:
    QSqlDatabase database_;
    QString connection_name_;
};

/// Returns the repository's SQL migration directory.
inline QString migration_directory()
{
    return QStringLiteral(TCP_CHAT_SOURCE_DIR "/migrations");
}

} // namespace tcp_chat::testing

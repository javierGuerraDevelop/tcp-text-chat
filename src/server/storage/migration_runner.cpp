#include "migration_runner.h"

#include "sql_utils.h"

#include <QDir>
#include <QFile>
#include <QRegularExpression>
#include <QSqlQuery>
#include <QStringDecoder>

namespace tcp_chat::storage {
namespace {

    /// Identifies one versioned SQL file on disk.
    struct MigrationFile {
        int version = 0;
        QString path;
    };

    /// Describes the SQL lexical context used when splitting a migration script.
    enum class ParseState {
        Normal,
        SingleQuoted,
        DoubleQuoted,
        BacktickQuoted,
        LineComment,
        BlockComment,
    };

    /// Reads ordered, contiguously numbered migration files from a directory.
    std::optional<QList<MigrationFile>> migration_files(const QString& directory, StorageError* error)
    {
        const QDir migration_directory(directory);
        if (!migration_directory.exists()) {
            detail::set_error(error, StorageErrorCode::InvalidMigration, QStringLiteral("Migration directory does not exist"));
            return std::nullopt;
        }

        const auto names = migration_directory.entryList({ QStringLiteral("*.sql") }, QDir::Files, QDir::Name);
        if (names.isEmpty()) {
            detail::set_error(error, StorageErrorCode::InvalidMigration, QStringLiteral("Migration directory contains no SQL files"));
            return std::nullopt;
        }

        QList<MigrationFile> files;
        const QRegularExpression pattern(QStringLiteral("^(\\d{4})_.+\\.sql$"));
        for (const QString& name : names) {
            const auto match = pattern.match(name);
            if (!match.hasMatch()) {
                detail::set_error(error, StorageErrorCode::InvalidMigration, QStringLiteral("Migration filename is invalid"));
                return std::nullopt;
            }

            bool valid_version = false;
            const int version  = match.captured(1).toInt(&valid_version);
            if (!valid_version || version <= 0) {
                detail::set_error(error, StorageErrorCode::InvalidMigration, QStringLiteral("Migration version is invalid"));
                return std::nullopt;
            }
            files.append(MigrationFile { version, migration_directory.filePath(name) });
        }
        return files;
    }

    /// Splits SQL statements at semicolons outside quoted values and comments.
    std::optional<QList<QString>> split_statements(const QString& script, StorageError* error)
    {
        QList<QString> statements;
        QString current;
        ParseState state = ParseState::Normal;

        for (qsizetype index = 0; index < script.size(); ++index) {
            const QChar character = script[index];
            const QChar next      = index + 1 < script.size() ? script[index + 1] : QChar();

            if (state == ParseState::LineComment) {
                if (character == QLatin1Char('\n')) {
                    current.append(character);
                    state = ParseState::Normal;
                }
                continue;
            }
            if (state == ParseState::BlockComment) {
                if (character == QLatin1Char('*') && next == QLatin1Char('/')) {
                    ++index;
                    current.append(QLatin1Char(' '));
                    state = ParseState::Normal;
                }
                continue;
            }
            if (state != ParseState::Normal) {
                current.append(character);
                const QChar delimiter = state == ParseState::SingleQuoted
                    ? QLatin1Char('\'')
                    : (state == ParseState::DoubleQuoted ? QLatin1Char('"') : QLatin1Char('`'));
                if (character == delimiter) {
                    if (next == delimiter) {
                        current.append(next);
                        ++index;
                    } else {
                        state = ParseState::Normal;
                    }
                }
                continue;
            }

            if (character == QLatin1Char('-') && next == QLatin1Char('-')) {
                ++index;
                state = ParseState::LineComment;
                continue;
            }
            if (character == QLatin1Char('/') && next == QLatin1Char('*')) {
                ++index;
                current.append(QLatin1Char(' '));
                state = ParseState::BlockComment;
                continue;
            }
            if (character == QLatin1Char('\'')) {
                current.append(character);
                state = ParseState::SingleQuoted;
                continue;
            }
            if (character == QLatin1Char('"')) {
                current.append(character);
                state = ParseState::DoubleQuoted;
                continue;
            }
            if (character == QLatin1Char('`')) {
                current.append(character);
                state = ParseState::BacktickQuoted;
                continue;
            }
            if (character == QLatin1Char(';')) {
                const QString statement = current.trimmed();
                if (!statement.isEmpty()) {
                    statements.append(statement);
                }
                current.clear();
                continue;
            }
            current.append(character);
        }

        if (state == ParseState::SingleQuoted || state == ParseState::DoubleQuoted
            || state == ParseState::BacktickQuoted || state == ParseState::BlockComment) {
            detail::set_error(error, StorageErrorCode::InvalidMigration, QStringLiteral("Migration contains unterminated SQL text"));
            return std::nullopt;
        }

        const QString trailing = current.trimmed();
        if (!trailing.isEmpty()) {
            statements.append(trailing);
        }
        if (statements.isEmpty()) {
            detail::set_error(error, StorageErrorCode::InvalidMigration, QStringLiteral("Migration contains no SQL statements"));
            return std::nullopt;
        }
        return statements;
    }

    /// Reads one UTF-8 migration script from disk.
    std::optional<QString> read_script(const QString& path, StorageError* error)
    {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            detail::set_error(error, StorageErrorCode::OpenFailed, QStringLiteral("Could not open migration script"));
            return std::nullopt;
        }

        QStringDecoder decoder(QStringDecoder::Utf8);
        const QString script = decoder.decode(file.readAll());
        if (decoder.hasError()) {
            detail::set_error(error, StorageErrorCode::InvalidMigration, QStringLiteral("Migration script is not valid UTF-8"));
            return std::nullopt;
        }
        return script;
    }

    /// Returns the greatest applied schema version, or zero for a new database.
    std::optional<int> current_version(QSqlDatabase& database, StorageError* error)
    {
        QSqlQuery query(database);
        if (!query.exec(QStringLiteral("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")) || !query.next()) {
            detail::set_query_error(error, query.lastError(), QStringLiteral("Could not read schema version"));
            return std::nullopt;
        }
        return query.value(0).toInt();
    }

} // namespace

std::optional<MigrationResult> MigrationRunner::migrate(
    QSqlDatabase& database, const QString& directory, qint64 now, StorageError* error)
{
    detail::clear_error(error);
    if (!database.isOpen()) {
        detail::set_error(error, StorageErrorCode::OpenFailed, QStringLiteral("Database connection is not open"));
        return std::nullopt;
    }
    if (now < 0) {
        detail::set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("Migration timestamp must not be negative"));
        return std::nullopt;
    }

    if (!detail::execute(database, QStringLiteral("PRAGMA foreign_keys = ON"), error)
        || !detail::execute(database, QStringLiteral("PRAGMA busy_timeout = 5000"), error)
        || !detail::execute(database, QStringLiteral("PRAGMA journal_mode = WAL"), error)
        || !detail::execute(database,
            QStringLiteral("CREATE TABLE IF NOT EXISTS schema_migrations ("
                           "version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)"),
            error)) {
        return std::nullopt;
    }

    const auto current = current_version(database, error);
    if (!current.has_value()) {
        return std::nullopt;
    }
    const auto files = migration_files(directory, error);
    if (!files.has_value()) {
        return std::nullopt;
    }
    if (*current > files->last().version) {
        detail::set_error(error, StorageErrorCode::InvalidMigration, QStringLiteral("Database schema is newer than available migrations"));
        return std::nullopt;
    }

    MigrationResult result;
    result.current_version = *current;
    for (const MigrationFile& file : *files) {
        if (file.version <= result.current_version) {
            continue;
        }
        if (file.version != result.current_version + 1) {
            detail::set_error(error, StorageErrorCode::InvalidMigration, QStringLiteral("Migration versions are not contiguous"));
            return std::nullopt;
        }

        const auto script = read_script(file.path, error);
        if (!script.has_value()) {
            return std::nullopt;
        }
        const auto statements = split_statements(*script, error);
        if (!statements.has_value()) {
            return std::nullopt;
        }

        detail::Transaction transaction(database);
        if (!transaction.begin(error)) {
            return std::nullopt;
        }
        for (const QString& statement : *statements) {
            if (!detail::execute(database, statement, error)) {
                return std::nullopt;
            }
        }

        QSqlQuery insert(database);
        insert.prepare(QStringLiteral("INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)"));
        insert.addBindValue(file.version);
        insert.addBindValue(now);
        if (!insert.exec()) {
            detail::set_query_error(error, insert.lastError(), QStringLiteral("Could not record migration"));
            return std::nullopt;
        }
        if (!transaction.commit(error)) {
            return std::nullopt;
        }

        result.current_version = file.version;
        result.applied_versions.append(file.version);
    }

    return result;
}

} // namespace tcp_chat::storage

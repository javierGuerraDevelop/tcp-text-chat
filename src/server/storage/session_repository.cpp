#include "session_repository.h"

#include "sql_utils.h"

#include <QSqlQuery>

namespace tcp_chat::storage {
namespace {

    constexpr qsizetype token_digest_size = 32;

    /// Converts the current query row to a session record.
    SessionRecord read_session(QSqlQuery& query)
    {
        SessionRecord session;
        session.id           = query.value(0).toLongLong();
        session.user_id      = query.value(1).toLongLong();
        session.token_digest = query.value(2).toByteArray();
        session.created_at   = query.value(3).toLongLong();
        session.expires_at   = query.value(4).toLongLong();
        session.last_seen_at = query.value(5).toLongLong();
        if (!query.value(6).isNull()) {
            session.revoked_at = query.value(6).toLongLong();
        }
        return session;
    }

} // namespace

SessionRepository::SessionRepository(const QSqlDatabase& database)
    : database_(database)
{
}

std::optional<SessionRecord> SessionRepository::create_session(const NewSession& input, StorageError* error)
{
    detail::clear_error(error);
    if (input.user_id <= 0 || input.token_digest.size() != token_digest_size || input.created_at < 0
        || input.expires_at <= input.created_at || input.last_seen_at < input.created_at) {
        detail::set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("Session fields are invalid"));
        return std::nullopt;
    }

    QSqlQuery query(database_);
    query.prepare(QStringLiteral("INSERT INTO sessions(user_id, token_digest, created_at, expires_at, last_seen_at) "
                                 "VALUES(?, ?, ?, ?, ?)"));
    query.addBindValue(input.user_id);
    query.addBindValue(input.token_digest);
    query.addBindValue(input.created_at);
    query.addBindValue(input.expires_at);
    query.addBindValue(input.last_seen_at);
    if (!query.exec()) {
        if (query.lastError().nativeErrorCode() == QStringLiteral("19")
            || query.lastError().nativeErrorCode() == QStringLiteral("2067")) {
            const bool duplicate_digest = query.lastError().text().contains(QStringLiteral("token_digest"));
            detail::set_error(error, duplicate_digest ? StorageErrorCode::Conflict : StorageErrorCode::ConstraintViolation,
                duplicate_digest ? QStringLiteral("Session token digest already exists")
                                 : QStringLiteral("Session references a missing user"));
        } else {
            detail::set_query_error(error, query.lastError(), QStringLiteral("Could not create session"));
        }
        return std::nullopt;
    }

    return find_by_id(query.lastInsertId().toLongLong(), error);
}

std::optional<SessionRecord> SessionRepository::find_active_session(
    const QByteArray& token_digest, qint64 now, StorageError* error)
{
    detail::clear_error(error);
    if (token_digest.size() != token_digest_size || now < 0) {
        detail::set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("Session lookup fields are invalid"));
        return std::nullopt;
    }

    QSqlQuery query(database_);
    query.prepare(QStringLiteral("SELECT id, user_id, token_digest, created_at, expires_at, last_seen_at, revoked_at "
                                 "FROM sessions WHERE token_digest = ? AND revoked_at IS NULL AND expires_at > ?"));
    query.addBindValue(token_digest);
    query.addBindValue(now);
    if (!query.exec()) {
        detail::set_query_error(error, query.lastError(), QStringLiteral("Could not find active session"));
        return std::nullopt;
    }
    if (!query.next()) {
        detail::set_error(error, StorageErrorCode::NotFound, QStringLiteral("Active session was not found"));
        return std::nullopt;
    }
    return read_session(query);
}

std::optional<SessionRecord> SessionRepository::revoke_session(qint64 id, qint64 now, StorageError* error)
{
    detail::clear_error(error);
    if (id <= 0 || now < 0) {
        detail::set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("Session revocation fields are invalid"));
        return std::nullopt;
    }

    QSqlQuery query(database_);
    query.prepare(QStringLiteral("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"));
    query.addBindValue(now);
    query.addBindValue(id);
    if (!query.exec()) {
        detail::set_query_error(error, query.lastError(), QStringLiteral("Could not revoke session"));
        return std::nullopt;
    }
    return find_by_id(id, error);
}

std::optional<SessionRecord> SessionRepository::find_by_id(qint64 id, StorageError* error)
{
    detail::clear_error(error);
    QSqlQuery query(database_);
    query.prepare(QStringLiteral("SELECT id, user_id, token_digest, created_at, expires_at, last_seen_at, revoked_at "
                                 "FROM sessions WHERE id = ?"));
    query.addBindValue(id);
    if (!query.exec()) {
        detail::set_query_error(error, query.lastError(), QStringLiteral("Could not find session"));
        return std::nullopt;
    }
    if (!query.next()) {
        detail::set_error(error, StorageErrorCode::NotFound, QStringLiteral("Session was not found"));
        return std::nullopt;
    }
    return read_session(query);
}

} // namespace tcp_chat::storage

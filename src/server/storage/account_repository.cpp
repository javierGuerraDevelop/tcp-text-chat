#include "account_repository.h"

#include "sql_utils.h"

#include <QSqlQuery>

namespace tcp_chat::storage {
namespace {

    /// Converts the current query row to a user record.
    UserRecord read_user(QSqlQuery& query)
    {
        UserRecord user;
        user.id                  = query.value(0).toLongLong();
        user.username            = query.value(1).toString();
        user.normalized_username = query.value(2).toString();
        user.display_name        = query.value(3).toString();
        if (!query.value(4).isNull()) {
            user.password_hash = query.value(4).toString();
        }
        user.created_at = query.value(5).toLongLong();
        user.updated_at = query.value(6).toLongLong();
        return user;
    }

    /// Finds one user using a repository-selected WHERE clause and bound value.
    std::optional<UserRecord> find_user(
        QSqlDatabase& database, const QString& where, const QVariant& value, StorageError* error)
    {
        QSqlQuery query(database);
        query.prepare(QStringLiteral("SELECT id, username, normalized_username, display_name, password_hash, "
                                     "created_at, updated_at FROM users WHERE ")
            + where);
        query.addBindValue(value);
        if (!query.exec()) {
            detail::set_query_error(error, query.lastError(), QStringLiteral("Could not find user"));
            return std::nullopt;
        }
        if (!query.next()) {
            detail::set_error(error, StorageErrorCode::NotFound, QStringLiteral("User was not found"));
            return std::nullopt;
        }
        return read_user(query);
    }

} // namespace

AccountRepository::AccountRepository(const QSqlDatabase& database)
    : database_(database)
{
}

std::optional<UserRecord> AccountRepository::create_local_user(const NewLocalUser& input, StorageError* error)
{
    detail::clear_error(error);
    if (input.username.isEmpty() || input.normalized_username.isEmpty() || input.display_name.isEmpty()
        || input.password_hash.isEmpty() || input.now < 0) {
        detail::set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("Local user fields are incomplete"));
        return std::nullopt;
    }

    QSqlQuery query(database_);
    query.prepare(QStringLiteral("INSERT INTO users(username, normalized_username, display_name, password_hash, "
                                 "created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)"));
    query.addBindValue(input.username);
    query.addBindValue(input.normalized_username);
    query.addBindValue(input.display_name);
    query.addBindValue(input.password_hash);
    query.addBindValue(input.now);
    query.addBindValue(input.now);
    if (!query.exec()) {
        if (query.lastError().nativeErrorCode() == QStringLiteral("19")
            || query.lastError().nativeErrorCode() == QStringLiteral("2067")) {
            detail::set_error(error, StorageErrorCode::Conflict, QStringLiteral("Normalized username already exists"));
        } else {
            detail::set_query_error(error, query.lastError(), QStringLiteral("Could not create user"));
        }
        return std::nullopt;
    }

    return find_user_by_id(query.lastInsertId().toLongLong(), error);
}

std::optional<UserRecord> AccountRepository::find_user_by_id(qint64 id, StorageError* error)
{
    detail::clear_error(error);
    if (id <= 0) {
        detail::set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("User ID must be positive"));
        return std::nullopt;
    }
    return find_user(database_, QStringLiteral("id = ?"), id, error);
}

std::optional<UserRecord> AccountRepository::find_user_by_normalized_username(
    const QString& normalized_username, StorageError* error)
{
    detail::clear_error(error);
    if (normalized_username.isEmpty()) {
        detail::set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("Normalized username must not be empty"));
        return std::nullopt;
    }
    return find_user(database_, QStringLiteral("normalized_username = ?"), normalized_username, error);
}

} // namespace tcp_chat::storage

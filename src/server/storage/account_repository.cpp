#include "account_repository.h"

#include "sql_utils.h"

#include <QSqlQuery>

#include <algorithm>

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

std::optional<UserRecord> AccountRepository::find_or_create_oauth_user(const NewOAuthUser& input, StorageError* error)
{
    detail::clear_error(error);
    const bool valid_provider = !input.provider.isEmpty() && input.provider.size() <= 32
        && input.provider.front() >= QLatin1Char('a') && input.provider.front() <= QLatin1Char('z')
        && std::all_of(input.provider.cbegin(), input.provider.cend(), [](QChar character) {
               return (character >= QLatin1Char('a') && character <= QLatin1Char('z'))
                   || (character >= QLatin1Char('0') && character <= QLatin1Char('9')) || character == QLatin1Char('_')
                   || character == QLatin1Char('-');
           });
    if (!valid_provider || input.provider_subject.isEmpty() || input.provider_subject.size() > 256
        || input.provider_subject.trimmed() != input.provider_subject || input.username.isEmpty() || input.username.size() > 32
        || input.normalized_username.isEmpty() || input.normalized_username.size() > 32 || input.display_name.isEmpty()
        || input.display_name.size() > 64 || input.now < 0) {
        detail::set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("OAuth user fields are invalid"));
        return std::nullopt;
    }

    detail::Transaction transaction(database_);
    if (!transaction.begin(error)) {
        return std::nullopt;
    }
    QSqlQuery query(database_);
    query.prepare(QStringLiteral("SELECT u.id, u.username, u.normalized_username, u.display_name, u.password_hash, "
                                 "u.created_at, u.updated_at FROM oauth_accounts AS o JOIN users AS u ON u.id = o.user_id "
                                 "WHERE o.provider = ? AND o.provider_subject = ?"));
    query.addBindValue(input.provider);
    query.addBindValue(input.provider_subject);
    if (!query.exec()) {
        detail::set_query_error(error, query.lastError(), QStringLiteral("Could not find OAuth user"));
        return std::nullopt;
    }
    if (query.next()) {
        const UserRecord user = read_user(query);
        if (!transaction.commit(error)) {
            return std::nullopt;
        }
        return user;
    }

    query.prepare(QStringLiteral("INSERT INTO users(username, normalized_username, display_name, password_hash, "
                                 "created_at, updated_at) VALUES(?, ?, ?, NULL, ?, ?)"));
    query.addBindValue(input.username);
    query.addBindValue(input.normalized_username);
    query.addBindValue(input.display_name);
    query.addBindValue(input.now);
    query.addBindValue(input.now);
    if (!query.exec()) {
        const QString native = query.lastError().nativeErrorCode();
        detail::set_error(error, native == QStringLiteral("19") || native == QStringLiteral("2067") ? StorageErrorCode::Conflict : StorageErrorCode::QueryFailed,
            QStringLiteral("Could not provision OAuth user"));
        return std::nullopt;
    }
    const qint64 user_id = query.lastInsertId().toLongLong();
    query.prepare(QStringLiteral("INSERT INTO oauth_accounts(user_id, provider, provider_subject, created_at, updated_at) "
                                 "VALUES(?, ?, ?, ?, ?)"));
    query.addBindValue(user_id);
    query.addBindValue(input.provider);
    query.addBindValue(input.provider_subject);
    query.addBindValue(input.now);
    query.addBindValue(input.now);
    if (!query.exec()) {
        const QString native = query.lastError().nativeErrorCode();
        detail::set_error(error, native == QStringLiteral("19") || native == QStringLiteral("2067") ? StorageErrorCode::Conflict : StorageErrorCode::QueryFailed,
            QStringLiteral("Could not link OAuth identity"));
        return std::nullopt;
    }
    const auto user = find_user_by_id(user_id, error);
    if (!user.has_value() || !transaction.commit(error)) {
        return std::nullopt;
    }
    return user;
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

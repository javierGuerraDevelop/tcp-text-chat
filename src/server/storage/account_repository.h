#pragma once

#include "records.h"
#include "storage_error.h"

#include <QSqlDatabase>

#include <optional>

namespace tcp_chat::storage {

/// Persists local users through bound queries on one thread-affine connection.
class AccountRepository {
public:
    /// Creates a repository for an open connection on the current thread.
    explicit AccountRepository(const QSqlDatabase& database);

    /// Inserts a local user and returns its persisted record.
    std::optional<UserRecord> create_local_user(const NewLocalUser& input, StorageError* error = nullptr);

    /// Finds an exact provider identity or atomically creates its OAuth-only user and link.
    std::optional<UserRecord> find_or_create_oauth_user(const NewOAuthUser& input, StorageError* error = nullptr);

    /// Finds a user by integer ID, or reports NotFound.
    std::optional<UserRecord> find_user_by_id(qint64 id, StorageError* error = nullptr);

    /// Finds a user by normalized login name, or reports NotFound.
    std::optional<UserRecord> find_user_by_normalized_username(
        const QString& normalized_username, StorageError* error = nullptr);

private:
    QSqlDatabase database_;
};

} // namespace tcp_chat::storage

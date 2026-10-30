#pragma once

#include "records.h"
#include "storage_error.h"

#include <QSqlDatabase>

#include <optional>

namespace tcp_chat::storage {

/// Persists expiring, revocable sessions on one thread-affine connection.
class SessionRepository {
public:
    /// Creates a repository for an open connection on the current thread.
    explicit SessionRepository(const QSqlDatabase& database);

    /// Inserts a session and returns its persisted record.
    std::optional<SessionRecord> create_session(const NewSession& input, StorageError* error = nullptr);

    /// Finds an unexpired, unrevoked session by its 32-byte token digest.
    std::optional<SessionRecord> find_active_session(
        const QByteArray& token_digest, qint64 now, StorageError* error = nullptr);

    /// Marks a session revoked and returns its current record; repeated revocation is idempotent.
    std::optional<SessionRecord> revoke_session(qint64 id, qint64 now, StorageError* error = nullptr);

private:
    /// Finds a session by integer ID, or reports NotFound.
    std::optional<SessionRecord> find_by_id(qint64 id, StorageError* error);

    QSqlDatabase database_;
};

} // namespace tcp_chat::storage

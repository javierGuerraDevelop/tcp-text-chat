#pragma once

#include "records.h"
#include "storage_error.h"

#include <QList>
#include <QSqlDatabase>

#include <optional>

namespace tcp_chat::storage {

inline constexpr qsizetype maximum_message_body_size      = 4000;
inline constexpr qsizetype maximum_client_message_id_size = 128;

/// Persists shared-room messages and idempotent send retries on one connection.
class MessageRepository {
public:
    /// Creates a repository for an open connection on the current thread.
    explicit MessageRepository(const QSqlDatabase& database);

    /// Appends a message or returns the original row for an exact idempotent retry.
    std::optional<MessageAppendResult> append_message(const NewMessage& input, StorageError* error = nullptr);

    /// Returns a page before an optional message ID in ascending ID order.
    std::optional<QList<MessageRecord>> history_before(
        std::optional<qint64> before_id, int limit = 50, StorageError* error = nullptr);

    /// Returns messages after an ID in ascending ID order for reconnect synchronization.
    std::optional<QList<MessageRecord>> history_after(qint64 last_id, int limit = 50, StorageError* error = nullptr);

private:
    /// Finds a message by integer ID, or reports NotFound.
    std::optional<MessageRecord> find_by_id(qint64 id, StorageError* error);
    /// Finds a message by its sender-scoped idempotency key, or reports NotFound.
    std::optional<MessageRecord> find_by_client_id(
        qint64 sender_id, const QString& client_message_id, StorageError* error);

    QSqlDatabase database_;
};

} // namespace tcp_chat::storage

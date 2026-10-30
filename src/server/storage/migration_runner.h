#pragma once

#include "storage_error.h"

#include <QList>
#include <QSqlDatabase>

#include <optional>

namespace tcp_chat::storage {

/// Reports the current schema version and versions applied by one run.
struct MigrationResult {
    int current_version = 0;
    QList<int> applied_versions;
};

/// Applies ordered SQL migrations to an open connection on the current thread.
class MigrationRunner {
public:
    /// Applies pending migrations transactionally using the caller's timestamp.
    static std::optional<MigrationResult> migrate(
        QSqlDatabase& database, const QString& directory, qint64 now, StorageError* error = nullptr);
};

} // namespace tcp_chat::storage

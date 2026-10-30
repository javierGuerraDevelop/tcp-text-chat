#pragma once

#include <QString>

namespace tcp_chat::storage {

/// Classifies persistence failures without exposing query text or credentials.
enum class StorageErrorCode {
    None,
    InvalidInput,
    OpenFailed,
    InvalidMigration,
    QueryFailed,
    ConstraintViolation,
    Conflict,
    NotFound,
};

/// Describes a storage failure for logs and typed error handling.
struct StorageError {
    StorageErrorCode code = StorageErrorCode::None;
    QString message;
};

} // namespace tcp_chat::storage

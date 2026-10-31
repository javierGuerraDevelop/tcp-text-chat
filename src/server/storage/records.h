#pragma once

#include <QByteArray>
#include <QMetaType>
#include <QString>

#include <optional>

namespace tcp_chat::storage {

/// Contains a persisted local or OAuth-linked user.
struct UserRecord {
    qint64 id = 0;
    QString username;
    QString normalized_username;
    QString display_name;
    std::optional<QString> password_hash;
    qint64 created_at = 0;
    qint64 updated_at = 0;

    bool operator==(const UserRecord&) const = default;
};

/// Contains the fields needed to insert a local user.
struct NewLocalUser {
    QString username;
    QString normalized_username;
    QString display_name;
    QString password_hash;
    qint64 now = 0;
};

/// Contains a persisted server session with a hashed opaque token.
struct SessionRecord {
    qint64 id      = 0;
    qint64 user_id = 0;
    QByteArray token_digest;
    qint64 created_at   = 0;
    qint64 expires_at   = 0;
    qint64 last_seen_at = 0;
    std::optional<qint64> revoked_at;

    bool operator==(const SessionRecord&) const = default;
};

/// Contains the fields needed to insert a server session.
struct NewSession {
    qint64 user_id = 0;
    QByteArray token_digest;
    qint64 created_at   = 0;
    qint64 expires_at   = 0;
    qint64 last_seen_at = 0;
};

/// Contains one persisted shared-room message.
struct MessageRecord {
    qint64 id        = 0;
    qint64 sender_id = 0;
    QString client_message_id;
    QString body;
    qint64 created_at = 0;

    bool operator==(const MessageRecord&) const = default;
};

/// Contains the fields needed to append a shared-room message.
struct NewMessage {
    qint64 sender_id = 0;
    QString client_message_id;
    QString body;
    qint64 created_at = 0;
};

/// Distinguishes a new message insert from an idempotent retry result.
struct MessageAppendResult {
    MessageRecord message;
    bool inserted = false;
};

} // namespace tcp_chat::storage

Q_DECLARE_METATYPE(tcp_chat::storage::UserRecord)
Q_DECLARE_METATYPE(tcp_chat::storage::NewLocalUser)
Q_DECLARE_METATYPE(tcp_chat::storage::SessionRecord)
Q_DECLARE_METATYPE(tcp_chat::storage::NewSession)
Q_DECLARE_METATYPE(tcp_chat::storage::MessageRecord)
Q_DECLARE_METATYPE(tcp_chat::storage::NewMessage)
Q_DECLARE_METATYPE(tcp_chat::storage::MessageAppendResult)

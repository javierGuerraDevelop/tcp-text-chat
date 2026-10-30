#include "message_repository.h"

#include "sql_utils.h"

#include <QSqlQuery>

#include <algorithm>

namespace tcp_chat::storage {
namespace {

    /// Converts the current query row to a message record.
    MessageRecord read_message(QSqlQuery& query)
    {
        MessageRecord message;
        message.id                = query.value(0).toLongLong();
        message.sender_id         = query.value(1).toLongLong();
        message.client_message_id = query.value(2).toString();
        message.body              = query.value(3).toString();
        message.created_at        = query.value(4).toLongLong();
        return message;
    }

    /// Reads all message rows from an executed query.
    QList<MessageRecord> read_messages(QSqlQuery& query)
    {
        QList<MessageRecord> messages;
        while (query.next()) {
            messages.append(read_message(query));
        }
        return messages;
    }

} // namespace

MessageRepository::MessageRepository(const QSqlDatabase& database)
    : database_(database)
{
}

std::optional<MessageAppendResult> MessageRepository::append_message(const NewMessage& input, StorageError* error)
{
    detail::clear_error(error);
    if (input.sender_id <= 0 || input.client_message_id.isEmpty()
        || input.client_message_id.size() > maximum_client_message_id_size || input.body.trimmed().isEmpty()
        || input.body.size() > maximum_message_body_size || input.created_at < 0) {
        detail::set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("Message fields are invalid"));
        return std::nullopt;
    }

    detail::Transaction transaction(database_);
    if (!transaction.begin(error)) {
        return std::nullopt;
    }

    QSqlQuery insert(database_);
    insert.prepare(QStringLiteral("INSERT INTO messages(sender_id, client_message_id, body, created_at) "
                                  "VALUES(?, ?, ?, ?)"));
    insert.addBindValue(input.sender_id);
    insert.addBindValue(input.client_message_id);
    insert.addBindValue(input.body);
    insert.addBindValue(input.created_at);
    if (!insert.exec()) {
        const QSqlError insert_error = insert.lastError();
        if (insert_error.text().contains(QStringLiteral("UNIQUE constraint failed"), Qt::CaseInsensitive)) {
            const auto existing = find_by_client_id(input.sender_id, input.client_message_id, error);
            if (!existing.has_value()) {
                return std::nullopt;
            }
            if (existing->body != input.body || existing->created_at != input.created_at) {
                detail::set_error(error, StorageErrorCode::Conflict,
                    QStringLiteral("Client message ID was already used for different content"));
                return std::nullopt;
            }
            if (!transaction.commit(error)) {
                return std::nullopt;
            }
            return MessageAppendResult { *existing, false };
        }

        detail::set_query_error(error, insert_error, QStringLiteral("Could not append message"));
        return std::nullopt;
    }

    auto message = find_by_id(insert.lastInsertId().toLongLong(), error);
    if (!message.has_value() || !transaction.commit(error)) {
        return std::nullopt;
    }
    return MessageAppendResult { std::move(*message), true };
}

std::optional<QList<MessageRecord>> MessageRepository::history_before(
    std::optional<qint64> before_id, int limit, StorageError* error)
{
    detail::clear_error(error);
    if (limit <= 0 || limit > 100 || (before_id.has_value() && *before_id <= 0)) {
        detail::set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("History pagination fields are invalid"));
        return std::nullopt;
    }

    QSqlQuery query(database_);
    QString statement = QStringLiteral("SELECT id, sender_id, client_message_id, body, created_at FROM messages");
    if (before_id.has_value()) {
        statement += QStringLiteral(" WHERE id < ?");
    }
    statement += QStringLiteral(" ORDER BY id DESC LIMIT ?");
    query.prepare(statement);
    if (before_id.has_value()) {
        query.addBindValue(*before_id);
    }
    query.addBindValue(limit);
    if (!query.exec()) {
        detail::set_query_error(error, query.lastError(), QStringLiteral("Could not read message history"));
        return std::nullopt;
    }

    auto messages = read_messages(query);
    std::reverse(messages.begin(), messages.end());
    return messages;
}

std::optional<QList<MessageRecord>> MessageRepository::history_after(qint64 last_id, int limit, StorageError* error)
{
    detail::clear_error(error);
    if (last_id < 0 || limit <= 0 || limit > 100) {
        detail::set_error(error, StorageErrorCode::InvalidInput, QStringLiteral("History pagination fields are invalid"));
        return std::nullopt;
    }

    QSqlQuery query(database_);
    query.prepare(QStringLiteral("SELECT id, sender_id, client_message_id, body, created_at FROM messages "
                                 "WHERE id > ? ORDER BY id ASC LIMIT ?"));
    query.addBindValue(last_id);
    query.addBindValue(limit);
    if (!query.exec()) {
        detail::set_query_error(error, query.lastError(), QStringLiteral("Could not read messages after reconnect"));
        return std::nullopt;
    }
    return read_messages(query);
}

std::optional<MessageRecord> MessageRepository::find_by_id(qint64 id, StorageError* error)
{
    detail::clear_error(error);
    QSqlQuery query(database_);
    query.prepare(QStringLiteral("SELECT id, sender_id, client_message_id, body, created_at FROM messages WHERE id = ?"));
    query.addBindValue(id);
    if (!query.exec()) {
        detail::set_query_error(error, query.lastError(), QStringLiteral("Could not find message"));
        return std::nullopt;
    }
    if (!query.next()) {
        detail::set_error(error, StorageErrorCode::NotFound, QStringLiteral("Message was not found"));
        return std::nullopt;
    }
    return read_message(query);
}

std::optional<MessageRecord> MessageRepository::find_by_client_id(
    qint64 sender_id, const QString& client_message_id, StorageError* error)
{
    detail::clear_error(error);
    QSqlQuery query(database_);
    query.prepare(QStringLiteral("SELECT id, sender_id, client_message_id, body, created_at FROM messages "
                                 "WHERE sender_id = ? AND client_message_id = ?"));
    query.addBindValue(sender_id);
    query.addBindValue(client_message_id);
    if (!query.exec()) {
        detail::set_query_error(error, query.lastError(), QStringLiteral("Could not find idempotent message"));
        return std::nullopt;
    }
    if (!query.next()) {
        detail::set_error(error, StorageErrorCode::NotFound, QStringLiteral("Idempotent message was not found"));
        return std::nullopt;
    }
    return read_message(query);
}

} // namespace tcp_chat::storage

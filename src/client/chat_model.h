#pragma once

#include "tcp_chat/chat_protocol.h"

#include <QAbstractListModel>
#include <QList>

namespace tcp_chat::client {

/// Stores a bounded, ID-ordered message window with local delivery state.
class ChatModel final : public QAbstractListModel {
    Q_OBJECT

public:
    /// Exposes message fields to views and delegates without widget dependencies.
    enum Role {
        IdRole = Qt::UserRole,
        ClientMessageIdRole,
        SenderRole,
        UsernameRole,
        BodyRole,
        TimestampRole,
        DeliveryRole,
        OutgoingRole,
    };

    /// Identifies local acknowledgement state for a message.
    enum class Delivery {
        Sending,
        Sent,
        Failed,
    };
    Q_ENUM(Delivery)

    static constexpr qsizetype maximum_loaded_messages = 500;

    /// Creates an empty model with no authenticated sender.
    explicit ChatModel(QObject* parent = nullptr);

    /// Returns the number of loaded persisted and pending messages.
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    /// Returns plain-text message content and presentation metadata.
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;

    /// Updates the identity used to align outgoing messages.
    void set_user(const protocol::UserIdentity& user);
    /// Removes all persisted and pending entries.
    void clear();
    /// Inserts or deduplicates one live or acknowledged message.
    void append_message(const protocol::ChatMessage& message);
    /// Prepends an ascending older-history batch while removing duplicates.
    void prepend_history(const QList<protocol::ChatMessage>& messages);
    /// Appends an ascending initial or reconnect-history batch before pending entries.
    void append_history(const QList<protocol::ChatMessage>& messages);
    /// Adds an unsent message at the bottom of the view.
    void add_pending(const QString& client_message_id, const QString& body);
    /// Marks a failed entry as pending another idempotent send attempt.
    void mark_sending(const QString& client_message_id);
    /// Replaces a pending entry with its persisted server message.
    void mark_sent(const QString& client_message_id, const protocol::ChatMessage& message);
    /// Marks a pending entry as safe to retry with the same client message ID.
    void mark_failed(const QString& client_message_id);
    /// Returns the smallest persisted ID, or zero when none is loaded.
    qint64 first_message_id() const;
    /// Returns the greatest persisted ID, or zero when none is loaded.
    qint64 last_message_id() const;
    /// Returns a message with its sender-scoped idempotency key.
    std::optional<protocol::ChatMessage> message_for_client_id(const QString& client_message_id) const;
    /// Returns a message's delivery state when it is loaded.
    std::optional<Delivery> delivery_for_client_id(const QString& client_message_id) const;

private:
    struct Entry {
        protocol::ChatMessage message;
        Delivery delivery = Delivery::Sent;
    };

    /// Finds a persisted message by server ID, or returns -1.
    int row_for_id(qint64 id) const;
    /// Finds an unacknowledged message by client ID, or returns -1.
    int row_for_pending(const QString& client_message_id) const;
    /// Bounds the model by dropping the oldest or newest persisted rows.
    void trim(bool older_history);

    QList<Entry> entries_;
    protocol::UserIdentity user_;
};

} // namespace tcp_chat::client

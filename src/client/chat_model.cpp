#include "chat_model.h"

#include <QDateTime>
#include <QSet>

namespace tcp_chat::client {

ChatModel::ChatModel(QObject* parent)
    : QAbstractListModel(parent)
{
}

int ChatModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(entries_.size());
}

QVariant ChatModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= entries_.size()) {
        return QVariant { };
    }
    const Entry& entry = entries_.at(index.row());
    switch (role) {
    case Qt::DisplayRole:
    case BodyRole:
    case Qt::ToolTipRole:
        return entry.message.body;
    case Qt::AccessibleTextRole:
        return QStringLiteral("%1: %2").arg(entry.message.sender.display_name, entry.message.body);
    case IdRole:
        return entry.message.id;
    case ClientMessageIdRole:
        return entry.message.client_message_id;
    case SenderRole:
        return entry.message.sender.display_name;
    case UsernameRole:
        return entry.message.sender.username;
    case TimestampRole:
        if (entry.message.created_at <= 0) {
            return QString { };
        }
        return QDateTime::fromMSecsSinceEpoch(entry.message.created_at).toLocalTime().toString(QStringLiteral("HH:mm"));
    case DeliveryRole:
        return static_cast<int>(entry.delivery);
    case OutgoingRole:
        return entry.message.sender.id == user_.id;
    default:
        return QVariant { };
    }
}

void ChatModel::set_user(const protocol::UserIdentity& user)
{
    if (user_ == user) {
        return;
    }
    user_ = user;
    if (!entries_.isEmpty()) {
        emit dataChanged(index(0), index(rowCount() - 1), { OutgoingRole });
    }
}

void ChatModel::clear()
{
    if (entries_.isEmpty()) {
        return;
    }
    beginResetModel();
    entries_.clear();
    endResetModel();
}

void ChatModel::append_message(const protocol::ChatMessage& message)
{
    if (message.id <= 0) {
        return;
    }
    int row = row_for_id(message.id);
    if (row < 0) {
        row = row_for_pending(message.client_message_id);
    }
    if (row >= 0) {
        entries_[row].message  = message;
        entries_[row].delivery = Delivery::Sent;
        emit dataChanged(index(row), index(row));
        return;
    }

    qsizetype position = entries_.size();
    for (qsizetype index = 0; index < entries_.size(); ++index) {
        if (entries_.at(index).message.id == 0 || entries_.at(index).message.id > message.id) {
            position = index;
            break;
        }
    }
    beginInsertRows(QModelIndex(), static_cast<int>(position), static_cast<int>(position));
    entries_.insert(position, Entry { message, Delivery::Sent });
    endInsertRows();
    trim(false);
}

void ChatModel::prepend_history(const QList<protocol::ChatMessage>& messages)
{
    QSet<qint64> ids;
    for (const Entry& entry : entries_) {
        if (entry.message.id > 0) {
            ids.insert(entry.message.id);
        }
    }
    QList<Entry> additions;
    for (const protocol::ChatMessage& message : messages) {
        if (message.id > 0 && !ids.contains(message.id)) {
            ids.insert(message.id);
            additions.append(Entry { message, Delivery::Sent });
        }
    }
    if (additions.isEmpty()) {
        return;
    }
    beginInsertRows(QModelIndex(), 0, static_cast<int>(additions.size() - 1));
    for (qsizetype index = 0; index < additions.size(); ++index) {
        entries_.insert(index, additions.at(index));
    }
    endInsertRows();
    trim(true);
}

void ChatModel::append_history(const QList<protocol::ChatMessage>& messages)
{
    QSet<qint64> ids;
    for (const Entry& entry : entries_) {
        if (entry.message.id > 0) {
            ids.insert(entry.message.id);
        }
    }
    QList<Entry> additions;
    for (const protocol::ChatMessage& message : messages) {
        if (message.id > 0 && !ids.contains(message.id)) {
            ids.insert(message.id);
            additions.append(Entry { message, Delivery::Sent });
        }
    }
    if (additions.isEmpty()) {
        return;
    }

    qsizetype position = entries_.size();
    for (qsizetype index = 0; index < entries_.size(); ++index) {
        if (entries_.at(index).message.id == 0) {
            position = index;
            break;
        }
    }
    beginInsertRows(QModelIndex(), static_cast<int>(position), static_cast<int>(position + additions.size() - 1));
    for (qsizetype index = 0; index < additions.size(); ++index) {
        entries_.insert(position + index, additions.at(index));
    }
    endInsertRows();
    trim(false);
}

void ChatModel::add_pending(const QString& client_message_id, const QString& body)
{
    if (row_for_pending(client_message_id) >= 0) {
        return;
    }
    protocol::ChatMessage message;
    message.sender            = user_;
    message.client_message_id = client_message_id;
    message.body              = body;
    const int row             = rowCount();
    beginInsertRows(QModelIndex(), row, row);
    entries_.append(Entry { message, Delivery::Sending });
    endInsertRows();
    trim(false);
}

void ChatModel::mark_sending(const QString& client_message_id)
{
    const int row = row_for_pending(client_message_id);
    if (row < 0) {
        return;
    }
    entries_[row].delivery = Delivery::Sending;
    emit dataChanged(index(row), index(row), { DeliveryRole, Qt::AccessibleTextRole });
}

void ChatModel::mark_sent(const QString& client_message_id, const protocol::ChatMessage& message)
{
    const int row = row_for_pending(client_message_id);
    if (row < 0) {
        append_message(message);
        return;
    }
    entries_[row].message  = message;
    entries_[row].delivery = Delivery::Sent;
    emit dataChanged(index(row), index(row));
}

void ChatModel::mark_failed(const QString& client_message_id)
{
    const int row = row_for_pending(client_message_id);
    if (row < 0) {
        return;
    }
    entries_[row].delivery = Delivery::Failed;
    emit dataChanged(index(row), index(row), { DeliveryRole, Qt::AccessibleTextRole });
}

qint64 ChatModel::first_message_id() const
{
    qint64 first = 0;
    for (const Entry& entry : entries_) {
        if (entry.message.id > 0 && (first == 0 || entry.message.id < first)) {
            first = entry.message.id;
        }
    }
    return first;
}

qint64 ChatModel::last_message_id() const
{
    qint64 last = 0;
    for (const Entry& entry : entries_) {
        last = qMax(last, entry.message.id);
    }
    return last;
}

std::optional<protocol::ChatMessage> ChatModel::message_for_client_id(const QString& client_message_id) const
{
    for (const Entry& entry : entries_) {
        if (entry.message.sender.id == user_.id && entry.message.client_message_id == client_message_id) {
            return entry.message;
        }
    }
    return std::nullopt;
}

std::optional<ChatModel::Delivery> ChatModel::delivery_for_client_id(const QString& client_message_id) const
{
    for (const Entry& entry : entries_) {
        if (entry.message.sender.id == user_.id && entry.message.client_message_id == client_message_id) {
            return entry.delivery;
        }
    }
    return std::nullopt;
}

int ChatModel::row_for_id(qint64 id) const
{
    for (qsizetype row = 0; row < entries_.size(); ++row) {
        if (entries_.at(row).message.id == id) {
            return static_cast<int>(row);
        }
    }
    return -1;
}

int ChatModel::row_for_pending(const QString& client_message_id) const
{
    for (qsizetype row = 0; row < entries_.size(); ++row) {
        const Entry& entry = entries_.at(row);
        if (entry.message.id == 0 && entry.message.sender.id == user_.id
            && entry.message.client_message_id == client_message_id) {
            return static_cast<int>(row);
        }
    }
    return -1;
}

void ChatModel::trim(bool older_history)
{
    while (entries_.size() > maximum_loaded_messages) {
        int row = -1;
        if (older_history) {
            for (qsizetype index = entries_.size() - 1; index >= 0; --index) {
                if (entries_.at(index).message.id > 0) {
                    row = static_cast<int>(index);
                    break;
                }
            }
        } else {
            for (qsizetype index = 0; index < entries_.size(); ++index) {
                if (entries_.at(index).message.id > 0) {
                    row = static_cast<int>(index);
                    break;
                }
            }
        }
        if (row < 0) {
            return;
        }
        beginRemoveRows(QModelIndex(), row, row);
        entries_.removeAt(row);
        endRemoveRows();
    }
}

} // namespace tcp_chat::client

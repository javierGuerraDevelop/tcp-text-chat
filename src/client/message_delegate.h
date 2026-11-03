#pragma once

#include <QStyledItemDelegate>

class QListView;

namespace tcp_chat::client {

/// Paints plain-text message bubbles with wrapping and delivery feedback.
class MessageDelegate final : public QStyledItemDelegate {
    Q_OBJECT

public:
    /// Creates a delegate whose wrapping width follows the list viewport.
    explicit MessageDelegate(QListView* parent);

    /// Paints one message using semantic palette roles rather than per-row stylesheets.
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
    /// Calculates the wrapped row height from the current viewport width.
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override;

private:
    QListView* const view_;
};

} // namespace tcp_chat::client

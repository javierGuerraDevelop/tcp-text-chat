#include "message_delegate.h"

#include "chat_model.h"

#include <QListView>
#include <QPainter>
#include <QPainterPath>

namespace tcp_chat::client {
namespace {

    /// Contains the computed geometry and text for one wrapped message row.
    struct MessageLayout {
        QRect bubble;
        QRect header;
        QRect body;
        QRect delivery;
        QString header_text;
        QString body_text;
        QString delivery_text;
        bool outgoing             = false;
        ChatModel::Delivery state = ChatModel::Delivery::Sent;
    };

    /// Computes shared paint and size geometry from the viewport and font metrics.
    MessageLayout message_layout(const QStyleOptionViewItem& option, const QModelIndex& index, const QListView* view)
    {
        MessageLayout layout;
        layout.outgoing         = index.data(ChatModel::OutgoingRole).toBool();
        layout.state            = static_cast<ChatModel::Delivery>(index.data(ChatModel::DeliveryRole).toInt());
        layout.body_text        = index.data(ChatModel::BodyRole).toString();
        layout.header_text      = layout.outgoing ? QStringLiteral("You") : index.data(ChatModel::SenderRole).toString();
        const QString timestamp = index.data(ChatModel::TimestampRole).toString();
        if (!timestamp.isEmpty()) {
            layout.header_text += QStringLiteral("  ·  ") + timestamp;
        }
        if (layout.state == ChatModel::Delivery::Sending) {
            layout.delivery_text = QStringLiteral("Sending…");
        } else if (layout.state == ChatModel::Delivery::Failed) {
            layout.delivery_text = QStringLiteral("Failed  ·  Activate to retry");
        }

        const int viewport_width = view != nullptr ? view->viewport()->width() : option.rect.width();
        const int available      = qMax(120, viewport_width - 48);
        const int bubble_width   = qMin(540, available);
        const int text_width     = bubble_width - 24;
        const QFontMetrics metrics(option.font);
        const QRect body_bounds   = metrics.boundingRect(QRect(0, 0, text_width, 100000),
            Qt::TextWordWrap | Qt::TextExpandTabs, layout.body_text);
        const int delivery_height = layout.delivery_text.isEmpty() ? 0 : metrics.height() + 4;
        const int bubble_height   = 12 + metrics.height() + 6 + body_bounds.height() + delivery_height + 12;
        const int x               = layout.outgoing ? viewport_width - bubble_width - 16 : 16;
        layout.bubble             = QRect(qMax(0, x), option.rect.top() + 6, bubble_width, bubble_height);
        layout.header             = layout.bubble.adjusted(12, 12, -12, 0);
        layout.header.setHeight(metrics.height());
        layout.body     = QRect(layout.bubble.left() + 12, layout.header.bottom() + 7, text_width, body_bounds.height());
        layout.delivery = QRect(layout.bubble.left() + 12, layout.body.bottom() + 5, text_width, metrics.height());
        return layout;
    }

} // namespace

MessageDelegate::MessageDelegate(QListView* parent)
    : QStyledItemDelegate(parent)
    , view_(parent)
{
}

void MessageDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    const MessageLayout layout = message_layout(option, index, view_);
    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);

    const QPalette& palette = option.palette;
    const QColor background = layout.outgoing ? palette.color(QPalette::Highlight) : palette.color(QPalette::Base);
    const QColor text       = layout.outgoing ? palette.color(QPalette::HighlightedText) : palette.color(QPalette::Text);
    painter->setBrush(background);
    painter->setPen(option.state & (QStyle::State_Selected | QStyle::State_HasFocus) ? QPen(palette.color(QPalette::Accent), 2)
                                                                                     : QPen(palette.color(QPalette::Midlight), 1));
    painter->drawRoundedRect(layout.bubble, 9, 9);

    QFont header_font = option.font;
    header_font.setWeight(QFont::DemiBold);
    painter->setFont(header_font);
    painter->setPen(text);
    painter->drawText(layout.header, Qt::AlignLeft | Qt::AlignVCenter, layout.header_text);
    painter->setFont(option.font);
    painter->drawText(layout.body, Qt::TextWordWrap | Qt::TextExpandTabs, layout.body_text);
    if (!layout.delivery_text.isEmpty()) {
        painter->setPen(!layout.outgoing && layout.state == ChatModel::Delivery::Failed ? palette.color(QPalette::BrightText) : text);
        painter->drawText(layout.delivery, Qt::AlignLeft | Qt::AlignVCenter, layout.delivery_text);
    }
    painter->restore();
}

QSize MessageDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    const MessageLayout layout = message_layout(option, index, view_);
    return QSize(view_ != nullptr ? view_->viewport()->width() : option.rect.width(), layout.bubble.height() + 12);
}

} // namespace tcp_chat::client

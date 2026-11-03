#include "chat_controller.h"

#include <QJsonObject>
#include <QUuid>

namespace tcp_chat::client {

ChatController::ChatController(TlsClient* client, AuthenticationController* authentication, ChatModel* model, QObject* parent)
    : QObject(parent)
    , client_(client)
    , authentication_(authentication)
    , model_(model)
{
    if (client_ != nullptr) {
        connect(client_, &TlsClient::message_received, this, &ChatController::message_received);
    }
    if (authentication_ != nullptr) {
        connect(authentication_, &AuthenticationController::authenticated, this, &ChatController::authenticated);
        connect(authentication_, &AuthenticationController::state_changed, this, &ChatController::authentication_state_changed);
    }
}

std::optional<QString> ChatController::send_message(const QString& body)
{
    if (!active_ || client_ == nullptr || model_ == nullptr || client_->state() != TlsClient::State::Connected
        || !protocol::valid_chat_body(body) || send_requests_.size() >= maximum_pending_sends) {
        return std::nullopt;
    }
    const QString client_message_id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    model_->add_pending(client_message_id, body);
    const auto result = send_with_id(client_message_id, body);
    if (!result.has_value()) {
        model_->mark_failed(client_message_id);
        emit operation_failed(QStringLiteral("The message could not be sent. Activate it to retry."));
        return std::nullopt;
    }
    return result;
}

bool ChatController::retry_message(const QString& client_message_id)
{
    if (!active_ || model_ == nullptr || send_requests_.size() >= maximum_pending_sends) {
        return false;
    }
    const auto message  = model_->message_for_client_id(client_message_id);
    const auto delivery = model_->delivery_for_client_id(client_message_id);
    if (!message.has_value() || delivery != std::optional<ChatModel::Delivery> { ChatModel::Delivery::Failed }
        || !protocol::valid_chat_body(message->body)) {
        return false;
    }
    model_->mark_sending(client_message_id);
    if (!send_with_id(client_message_id, message->body).has_value()) {
        model_->mark_failed(client_message_id);
        emit operation_failed(QStringLiteral("The message could not be sent. Activate it to retry."));
        return false;
    }
    return true;
}

void ChatController::load_older_history()
{
    if (!active_ || history_loading_ || !has_older_history_ || model_ == nullptr || model_->first_message_id() <= 0) {
        return;
    }
    request_history(HistoryMode::Before);
}

bool ChatController::is_loading_history() const
{
    return history_loading_;
}

bool ChatController::has_older_history() const
{
    return has_older_history_;
}

void ChatController::authenticated(const protocol::UserIdentity& user)
{
    if (model_ == nullptr) {
        return;
    }
    model_->set_user(user);
    active_ = true;
    request_history(model_->last_message_id() > 0 ? HistoryMode::After : HistoryMode::Latest);
}

void ChatController::authentication_state_changed(AuthenticationController::State state)
{
    if (state == AuthenticationController::State::Authenticated) {
        return;
    }
    active_ = false;
    fail_pending_sends();
    history_request_id_.clear();
    history_mode_ = HistoryMode::None;
    set_history_loading(false);
}

void ChatController::message_received(const protocol::Envelope& envelope)
{
    if (envelope.type == protocol::MessageType::Error) {
        if (envelope.request_id.has_value() && send_requests_.contains(*envelope.request_id)) {
            const QString client_message_id = send_requests_.take(*envelope.request_id);
            model_->mark_failed(client_message_id);
            emit operation_failed(envelope.payload.value(QStringLiteral("message")).toString(QStringLiteral("The message could not be sent")));
        } else if (envelope.request_id == history_request_id_ && !history_request_id_.isEmpty()) {
            history_request_id_.clear();
            history_mode_ = HistoryMode::None;
            set_history_loading(false);
            emit operation_failed(envelope.payload.value(QStringLiteral("message")).toString(QStringLiteral("Message history is unavailable")));
        }
        return;
    }
    if (envelope.type == protocol::MessageType::ChatHistoryResult && envelope.request_id == history_request_id_
        && !history_request_id_.isEmpty()) {
        history_received(envelope);
        return;
    }
    if (envelope.type != protocol::MessageType::ChatMessage || model_ == nullptr) {
        return;
    }

    const auto message = protocol::chat_message_from_envelope(envelope);
    if (!message.has_value()) {
        client_->disconnect_from_host();
        emit operation_failed(QStringLiteral("The server returned an invalid chat message"));
        return;
    }
    if (envelope.request_id.has_value() && send_requests_.contains(*envelope.request_id)) {
        const QString client_message_id = send_requests_.take(*envelope.request_id);
        model_->mark_sent(client_message_id, *message);
    } else {
        model_->append_message(*message);
    }
}

std::optional<QString> ChatController::send_with_id(const QString& client_message_id, const QString& body)
{
    const QString request_id = QStringLiteral("chat-send-%1").arg(next_request_id_++);
    protocol::Envelope request;
    request.type       = protocol::MessageType::ChatSend;
    request.request_id = request_id;
    request.payload    = QJsonObject {
        { QStringLiteral("clientMessageId"), client_message_id },
        { QStringLiteral("body"), body },
    };
    send_requests_.insert(request_id, client_message_id);
    if (const auto error = client_->send(request); error.has_value()) {
        send_requests_.remove(request_id);
        return error->message;
    }
    return client_message_id;
}

void ChatController::request_history(HistoryMode mode)
{
    if (!active_ || client_ == nullptr || model_ == nullptr || client_->state() != TlsClient::State::Connected) {
        return;
    }
    protocol::Envelope request;
    request.type       = protocol::MessageType::ChatHistory;
    request.request_id = QStringLiteral("chat-history-%1").arg(next_request_id_++);
    if (mode == HistoryMode::Before) {
        request.payload.insert(QStringLiteral("beforeId"), QString::number(model_->first_message_id()));
    } else if (mode == HistoryMode::After) {
        request.payload.insert(QStringLiteral("afterId"), QString::number(model_->last_message_id()));
    }
    history_mode_       = mode;
    history_request_id_ = *request.request_id;
    set_history_loading(true);
    if (const auto error = client_->send(request); error.has_value()) {
        history_request_id_.clear();
        history_mode_ = HistoryMode::None;
        set_history_loading(false);
        emit operation_failed(error->message);
    }
}

void ChatController::history_received(const protocol::Envelope& envelope)
{
    const auto result = protocol::chat_history_result_from_envelope(envelope);
    if (!result.has_value()) {
        history_request_id_.clear();
        history_mode_ = HistoryMode::None;
        set_history_loading(false);
        client_->disconnect_from_host();
        emit operation_failed(QStringLiteral("The server returned invalid message history"));
        return;
    }

    const HistoryMode completed = history_mode_;
    history_request_id_.clear();
    history_mode_ = HistoryMode::None;
    if (completed == HistoryMode::Before) {
        model_->prepend_history(result->messages);
        set_has_older_history(result->has_more);
    } else {
        model_->append_history(result->messages);
        if (completed == HistoryMode::Latest) {
            set_has_older_history(result->has_more);
        }
    }

    if (completed == HistoryMode::After && result->has_more && model_->last_message_id() > 0) {
        request_history(HistoryMode::After);
        return;
    }
    set_history_loading(false);
    if (completed == HistoryMode::Latest || completed == HistoryMode::After) {
        emit history_loaded();
    }
}

void ChatController::set_history_loading(bool loading)
{
    if (history_loading_ == loading) {
        return;
    }
    history_loading_ = loading;
    emit history_loading_changed(loading);
}

void ChatController::set_has_older_history(bool available)
{
    if (has_older_history_ == available) {
        return;
    }
    has_older_history_ = available;
    emit older_history_available_changed(available);
}

void ChatController::fail_pending_sends()
{
    const QList<QString> client_message_ids = send_requests_.values();
    for (const QString& client_message_id : client_message_ids) {
        model_->mark_failed(client_message_id);
    }
    send_requests_.clear();
}

} // namespace tcp_chat::client

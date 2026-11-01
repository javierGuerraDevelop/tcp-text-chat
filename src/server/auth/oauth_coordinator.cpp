#include "oauth_coordinator.h"

#include "oauth_crypto.h"

#include <QDateTime>
#include <QMetaObject>

#include <sodium.h>

#include <algorithm>
#include <limits>

namespace tcp_chat::auth {

OAuthCoordinator::Flow::~Flow()
{
    if (!verifier.isEmpty()) {
        sodium_memzero(verifier.data(), static_cast<size_t>(verifier.size()));
    }
    if (!nonce.isEmpty()) {
        sodium_memzero(nonce.data(), static_cast<size_t>(nonce.size()));
    }
    if (!handoff.isEmpty()) {
        QByteArray encoded = handoff.toLatin1();
        sodium_memzero(encoded.data(), static_cast<size_t>(encoded.size()));
        handoff.fill(QChar('\0'));
    }
}

OAuthCoordinator::OAuthCoordinator(QUrl redirect_uri, OAuthCoordinatorOptions options, QObject* parent)
    : QObject(parent)
    , redirect_uri_(std::move(redirect_uri))
    , options_(std::move(options))
{
    qRegisterMetaType<tcp_chat::auth::OAuthExchangeResult>("tcp_chat::auth::OAuthExchangeResult");
}

std::optional<QString> OAuthCoordinator::configuration_error() const
{
    if (!redirect_uri_.isValid() || redirect_uri_.scheme() != QStringLiteral("https") || redirect_uri_.host().isEmpty()
        || !redirect_uri_.userInfo().isEmpty() || redirect_uri_.hasQuery() || redirect_uri_.hasFragment()) {
        return QStringLiteral("OAuth callback must be an exact HTTPS URL without credentials, query, or fragment");
    }
    if (options_.maximum_flows <= 0 || options_.maximum_flows_per_connection <= 0 || options_.maximum_pending_exchanges <= 0
        || options_.flow_lifetime_ms <= 0 || options_.handoff_lifetime_ms <= 0 || options_.terminal_result_lifetime_ms <= 0) {
        return QStringLiteral("OAuth flow limits and lifetimes must be positive");
    }
    return std::nullopt;
}

bool OAuthCoordinator::add_provider(std::shared_ptr<OAuthProvider> provider, QString* error)
{
    if (configuration_error().has_value() || provider == nullptr) {
        *error = QStringLiteral("An OAuth provider and valid callback configuration are required");
        return false;
    }
    if (const auto provider_error = provider->configuration_error(); provider_error.has_value()) {
        *error = *provider_error;
        return false;
    }
    const QString& id = provider->configuration().id;
    if (providers_.contains(id)) {
        *error = QStringLiteral("OAuth provider identifiers must be unique");
        return false;
    }
    OAuthProvider* const registered = provider.get();
    providers_.insert(id, std::move(provider));
    connect(registered, &OAuthProvider::exchange_finished, this, &OAuthCoordinator::exchange_finished);
    return true;
}

std::optional<OAuthStartResult> OAuthCoordinator::start(quint64 connection_id, const QString& provider_id, QString* error)
{
    check_expirations();
    const auto provider = providers_.find(provider_id);
    if (connection_id == 0 || provider == providers_.end()) {
        *error = QStringLiteral("The requested sign-in provider is unavailable");
        return std::nullopt;
    }
    const int owned = static_cast<int>(std::count_if(flows_.cbegin(), flows_.cend(), [connection_id](const auto& flow) {
        return flow->connection_id == connection_id;
    }));
    if (owned >= options_.maximum_flows_per_connection || flows_.size() >= options_.maximum_flows) {
        *error = QStringLiteral("Too many pending sign-in requests");
        return std::nullopt;
    }

    const auto handle    = generate_oauth_token();
    const auto state     = generate_oauth_token();
    const auto verifier  = generate_oauth_token();
    const auto nonce     = (*provider)->configuration().use_nonce ? generate_oauth_token() : std::optional<OAuthToken> { };
    const qint64 current = now();
    if (!handle.has_value() || !state.has_value() || !verifier.has_value()
        || ((*provider)->configuration().use_nonce && !nonce.has_value()) || flows_.contains(handle->digest)
        || states_.contains(state->digest) || current > std::numeric_limits<qint64>::max() - options_.flow_lifetime_ms) {
        *error = QStringLiteral("Sign-in could not be initialized");
        return std::nullopt;
    }
    const auto challenge = pkce_s256_challenge(verifier->value);
    if (!challenge.has_value()) {
        *error = QStringLiteral("Sign-in could not be initialized");
        return std::nullopt;
    }
    OAuthAuthorizationRequest request;
    request.state          = state->value.toLatin1();
    request.code_challenge = *challenge;
    request.redirect_uri   = redirect_uri_;
    if (nonce.has_value()) {
        request.nonce = nonce->value.toLatin1();
    }
    const auto url = (*provider)->authorization_url(request);
    if (!url.has_value()) {
        *error = QStringLiteral("Sign-in could not be initialized");
        return std::nullopt;
    }

    auto flow           = std::make_shared<Flow>();
    flow->id            = next_flow_id_++;
    flow->connection_id = connection_id;
    flow->provider      = provider.key();
    flow->verifier      = verifier->value.toLatin1();
    if (nonce.has_value()) {
        flow->nonce = nonce->value.toLatin1();
    }
    flow->expires_at     = current + options_.flow_lifetime_ms;
    const auto candidate = generate_oauth_token();
    if (!candidate.has_value()) {
        *error = QStringLiteral("Sign-in could not be initialized");
        return std::nullopt;
    }
    flow->username = QStringLiteral("user_") + candidate->value.left(24).toLower();
    flows_.insert(handle->digest, flow);
    states_.insert(state->digest, handle->digest);
    return OAuthStartResult { handle->value, *url, flow->expires_at };
}

std::optional<OAuthStatusResult> OAuthCoordinator::status(quint64 connection_id, const QString& flow_handle)
{
    check_expirations();
    const auto digest = digest_oauth_token(flow_handle);
    if (!digest.has_value()) {
        return std::nullopt;
    }
    const auto flow = flows_.constFind(*digest);
    if (flow == flows_.cend() || (*flow)->connection_id != connection_id) {
        return std::nullopt;
    }
    if ((*flow)->phase == Phase::Failed) {
        return OAuthStatusResult { OAuthFlowStatus::Failed, QString(), (*flow)->expires_at };
    }
    if ((*flow)->phase == Phase::Ready) {
        return OAuthStatusResult { OAuthFlowStatus::Ready, (*flow)->handoff, (*flow)->expires_at };
    }
    return OAuthStatusResult { OAuthFlowStatus::Pending, QString(), (*flow)->expires_at };
}

void OAuthCoordinator::authorization_received(const QString& state, const QString& code, const QString& error)
{
    const auto state_digest = digest_oauth_token(state);
    if (!state_digest.has_value()) {
        return;
    }
    const auto state_entry = states_.find(*state_digest);
    if (state_entry == states_.end()) {
        return;
    }
    const QByteArray flow_digest = state_entry.value();
    states_.erase(state_entry);
    const auto flow_entry = flows_.find(flow_digest);
    if (flow_entry == flows_.end()) {
        return;
    }
    const auto flow = flow_entry.value();
    if (now() >= flow->expires_at || flow->phase != Phase::Callback) {
        flows_.erase(flow_entry);
        return;
    }
    if (!error.isEmpty() || code.isEmpty() || code.size() > 2048) {
        fail_flow(*flow, now());
        return;
    }
    const int pending = static_cast<int>(std::count_if(flows_.cbegin(), flows_.cend(), [](const auto& candidate) {
        return candidate->phase == Phase::Exchange || candidate->phase == Phase::Provisioning;
    }));
    if (pending >= options_.maximum_pending_exchanges) {
        fail_flow(*flow, now());
        return;
    }
    flow->phase = Phase::Exchange;
    OAuthExchange exchange;
    exchange.code           = code.toUtf8();
    exchange.verifier       = flow->verifier;
    exchange.redirect_uri   = redirect_uri_;
    exchange.expected_nonce = flow->nonce;
    providers_.value(flow->provider)->exchange(flow->id, std::move(exchange));
}

void OAuthCoordinator::exchange_finished(const OAuthExchangeResult& result)
{
    const auto* provider = qobject_cast<OAuthProvider*>(sender());
    if (provider == nullptr) {
        return;
    }
    const auto entry = std::find_if(flows_.begin(), flows_.end(), [&result](const auto& flow) {
        return flow->id == result.flow_id && flow->phase == Phase::Exchange;
    });
    if (entry == flows_.end() || (*entry)->provider != provider->configuration().id) {
        return;
    }
    const auto flow                 = entry.value();
    const auto& configuration       = provider->configuration();
    const bool signed_token         = configuration.identity_source == OAuthIdentitySource::SignedToken;
    const QString expected_audience = signed_token
        ? (configuration.audience.isEmpty() ? configuration.client_id : configuration.audience)
        : QString();
    if (!result.identity.has_value() || result.identity->provider != configuration.id || result.identity->subject.isEmpty()
        || result.identity->subject.size() > 256 || result.identity->subject.trimmed() != result.identity->subject
        || std::any_of(result.identity->subject.cbegin(), result.identity->subject.cend(), [](QChar character) { return !character.isPrint(); })
        || result.identity->audience != expected_audience
        || (!signed_token && !result.identity->issuer.isEmpty())
        || (!configuration.issuer.isEmpty() && result.identity->issuer != configuration.issuer)
        || (configuration.use_nonce
            && !constant_time_equal(result.identity->nonce, flow->nonce))
        || (!configuration.use_nonce && !result.identity->nonce.isEmpty())) {
        fail_flow(*flow, now());
        return;
    }
    flow->subject = result.identity->subject;
    flow->phase   = Phase::Provisioning;
    if (!request_account(*flow)) {
        fail_flow(*flow, now());
    }
}

void OAuthCoordinator::account_resolved(quint64 flow_id, qint64 user_id, bool username_conflict)
{
    const auto entry = std::find_if(flows_.begin(), flows_.end(), [flow_id](const auto& flow) {
        return flow->id == flow_id && flow->phase == Phase::Provisioning;
    });
    if (entry == flows_.end()) {
        return;
    }
    const auto flow = entry.value();
    if (user_id <= 0 && username_conflict && flow->provisioning_attempts < 4) {
        ++flow->provisioning_attempts;
        if (request_account(*flow)) {
            return;
        }
    }
    if (user_id <= 0 || now() >= flow->expires_at) {
        fail_flow(*flow, now());
        return;
    }
    const auto handoff   = generate_oauth_token();
    const qint64 current = now();
    if (!handoff.has_value() || current > std::numeric_limits<qint64>::max() - options_.handoff_lifetime_ms) {
        fail_flow(*flow, current);
        return;
    }
    flow->user_id        = user_id;
    flow->handoff        = handoff->value;
    flow->handoff_digest = handoff->digest;
    flow->expires_at     = qMin(flow->expires_at, current + options_.handoff_lifetime_ms);
    flow->phase          = Phase::Ready;
}

bool OAuthCoordinator::request_account(Flow& flow)
{
    const auto candidate = generate_oauth_token();
    if (!candidate.has_value()) {
        return false;
    }
    flow.username = QStringLiteral("user_") + candidate->value.left(24).toLower();
    emit account_resolution_requested(flow.id, flow.provider, flow.subject, flow.username, flow.username, flow.username);
    return true;
}

std::optional<qint64> OAuthCoordinator::redeem(quint64 connection_id, const QString& flow_handle, const QString& handoff)
{
    check_expirations();
    const auto flow_digest    = digest_oauth_token(flow_handle);
    const auto handoff_digest = digest_oauth_token(handoff);
    if (!flow_digest.has_value() || !handoff_digest.has_value()) {
        return std::nullopt;
    }
    const auto entry = flows_.find(*flow_digest);
    if (entry == flows_.end() || (*entry)->connection_id != connection_id || (*entry)->phase != Phase::Ready
        || now() >= (*entry)->expires_at || !constant_time_equal((*entry)->handoff_digest, *handoff_digest)) {
        return std::nullopt;
    }
    const qint64 user_id = (*entry)->user_id;
    flows_.erase(entry);
    return user_id;
}

void OAuthCoordinator::cancel_connection(quint64 connection_id)
{
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (it.value()->connection_id == connection_id) {
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}

void OAuthCoordinator::check_expirations()
{
    const qint64 current = now();
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (current >= it.value()->expires_at) {
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = states_.begin(); it != states_.end();) {
        if (!flows_.contains(it.value())) {
            it = states_.erase(it);
        } else {
            ++it;
        }
    }
}

qint64 OAuthCoordinator::connection_deadline(quint64 connection_id) const
{
    qint64 deadline = 0;
    for (auto it = flows_.cbegin(); it != flows_.cend(); ++it) {
        if ((*it)->connection_id == connection_id && (*it)->phase != Phase::Failed) {
            deadline = qMax(deadline, (*it)->expires_at);
        }
    }
    return deadline;
}

void OAuthCoordinator::fail_flow(Flow& flow, qint64 current)
{
    flow.phase   = Phase::Failed;
    flow.user_id = 0;
    flow.handoff.clear();
    flow.handoff_digest.clear();
    if (!flow.verifier.isEmpty()) {
        sodium_memzero(flow.verifier.data(), static_cast<size_t>(flow.verifier.size()));
        flow.verifier.clear();
    }
    flow.expires_at = current > std::numeric_limits<qint64>::max() - options_.terminal_result_lifetime_ms
        ? std::numeric_limits<qint64>::max()
        : current + options_.terminal_result_lifetime_ms;
}

qint64 OAuthCoordinator::now() const
{
    return qMax<qint64>(0, options_.clock ? options_.clock() : QDateTime::currentMSecsSinceEpoch());
}

} // namespace tcp_chat::auth

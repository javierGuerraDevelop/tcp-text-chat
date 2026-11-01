#include "oauth_callback_server.h"

#include <QFile>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslSocket>
#include <QTimer>

#include <cctype>
#include <limits>

namespace tcp_chat::auth {
namespace {

    /// Strictly percent-decodes an ASCII OAuth parameter without form-encoding semantics.
    std::optional<QString> parameter(QByteArrayView value, qsizetype maximum)
    {
        if (value.isEmpty() || value.size() > maximum || value.contains('+')) {
            return std::nullopt;
        }
        QByteArray decoded;
        decoded.reserve(value.size());
        for (qsizetype index = 0; index < value.size(); ++index) {
            if (value.at(index) == '%') {
                if (index + 2 >= value.size() || !isxdigit(static_cast<unsigned char>(value.at(index + 1)))
                    || !isxdigit(static_cast<unsigned char>(value.at(index + 2)))) {
                    return std::nullopt;
                }
                decoded.append(static_cast<char>(QByteArray(value.mid(index + 1, 2)).toUInt(nullptr, 16)));
                index += 2;
            } else {
                decoded.append(value.at(index));
            }
        }
        for (const char character : decoded) {
            if (static_cast<unsigned char>(character) < 0x21 || static_cast<unsigned char>(character) > 0x7e) {
                return std::nullopt;
            }
        }
        return QString::fromLatin1(decoded);
    }

    /// Reads at most one header value and rejects duplicate or ambiguous headers.
    bool headers(const QList<QByteArray>& lines, QByteArray* host)
    {
        if (lines.size() > 64) {
            return false;
        }
        for (const auto& line : lines) {
            const qsizetype colon = line.indexOf(':');
            if (colon <= 0) {
                return false;
            }
            const QByteArray name  = line.left(colon).trimmed().toLower();
            const QByteArray value = line.mid(colon + 1).trimmed();
            if (name == "host") {
                if (!host->isEmpty()) {
                    return false;
                }
                *host = value;
            } else if (name == "transfer-encoding" || (name == "content-length" && value != "0")) {
                return false;
            }
        }
        return true;
    }

} // namespace

OAuthCallbackServer::OAuthCallbackServer(QObject* parent)
    : QTcpServer(parent)
{
}

OAuthCallbackServer::~OAuthCallbackServer()
{
    close();
}

std::optional<QString> OAuthCallbackServer::start(const OAuthCallbackServerOptions& options)
{
    if (isListening() || !requests_.isEmpty() || options.address.isNull() || options.expected_authority.isEmpty()
        || options.maximum_connections <= 0 || options.maximum_pending_connections <= 0
        || options.maximum_pending_connections > options.maximum_connections || options.maximum_request_bytes < 1024
        || options.maximum_request_bytes > 65536 || options.request_timeout <= std::chrono::milliseconds::zero()
        || options.request_timeout > std::chrono::milliseconds { std::numeric_limits<int>::max() }
        || !options.callback_path.startsWith(QLatin1Char('/')) || options.callback_path.size() > 128
        || options.callback_path.contains(QLatin1Char('?')) || options.callback_path.contains(QLatin1Char('#'))) {
        return QStringLiteral("OAuth callback listener configuration is invalid");
    }
    QUrl authority = QUrl(QStringLiteral("https://") + options.expected_authority);
    if (!authority.isValid() || authority.host().isEmpty()
        || (!authority.path().isEmpty() && authority.path() != QStringLiteral("/"))
        || authority.hasQuery() || authority.hasFragment() || !authority.userInfo().isEmpty()
        || (options.port != 0 && authority.port() > 0 && authority.port() != options.port)) {
        return QStringLiteral("OAuth callback authority is invalid");
    }
    const QList<QSslCertificate> chain = QSslCertificate::fromPath(options.certificate_chain_file, QSsl::Pem);
    if (chain.isEmpty()) {
        return QStringLiteral("OAuth callback certificate could not be loaded");
    }
    QFile key_file(options.private_key_file);
    if (!key_file.open(QIODevice::ReadOnly)) {
        return QStringLiteral("OAuth callback private key could not be opened");
    }
    const QSslKey key(&key_file, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    if (key.isNull()) {
        return QStringLiteral("OAuth callback private key could not be loaded");
    }
    QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
    ssl.setProtocol(QSsl::TlsV1_2OrLater);
    ssl.setLocalCertificateChain(chain);
    ssl.setPrivateKey(key);
    ssl.setPeerVerifyMode(QSslSocket::VerifyNone);
    ssl_configuration_ = ssl;
    options_           = options;
    callback_path_     = options.callback_path;
    setMaxPendingConnections(options.maximum_pending_connections);
    if (!listen(options.address, options.port)) {
        return QStringLiteral("OAuth callback listener could not start");
    }
    authority.setPort(authority.port() > 0 ? authority.port() : serverPort());
    authority.setPath(callback_path_);
    callback_url_       = authority;
    expected_authority_ = authority.authority(QUrl::FullyEncoded);
    closing_            = false;
    return std::nullopt;
}

QUrl OAuthCallbackServer::callback_url() const
{
    return callback_url_;
}

void OAuthCallbackServer::incomingConnection(qintptr descriptor)
{
    if (closing_) {
        QSslSocket socket;
        if (socket.setSocketDescriptor(descriptor)) {
            socket.abort();
        }
        return;
    }
    if (requests_.size() >= options_.maximum_connections) {
        QSslSocket socket;
        if (socket.setSocketDescriptor(descriptor)) {
            socket.abort();
        }
        return;
    }
    auto* socket = new QSslSocket(this);
    socket->setSslConfiguration(ssl_configuration_);
    requests_.insert(socket, QByteArray());
    auto* timer = new QTimer(socket);
    timer->setSingleShot(true);
    timer->setInterval(static_cast<int>(options_.request_timeout.count()));
    timers_.insert(socket, timer);
    connect(timer, &QTimer::timeout, socket, &QSslSocket::abort);
    connect(socket, &QSslSocket::sslErrors, socket, &QSslSocket::abort);
    connect(socket, &QSslSocket::readyRead, this, [this, socket] { request_ready(socket); });
    connect(socket, &QSslSocket::disconnected, this, [this, socket] { socket_finished(socket); });
    if (!socket->setSocketDescriptor(descriptor)) {
        socket_finished(socket);
        socket->deleteLater();
        return;
    }
    timer->start();
    socket->startServerEncryption();
}

void OAuthCallbackServer::request_ready(QSslSocket* socket)
{
    if (!requests_.contains(socket) || responded_.contains(socket)) {
        return;
    }
    QByteArray& request = requests_[socket];
    if (request.size() + socket->bytesAvailable() > options_.maximum_request_bytes) {
        respond(socket, 400);
        return;
    }
    request.append(socket->readAll());
    const qsizetype end = request.indexOf("\r\n\r\n");
    if (end < 0) {
        return;
    }
    const QList<QByteArray> lines = request.left(end).split('\n');
    if (lines.isEmpty()) {
        respond(socket, 400);
        return;
    }
    const QList<QByteArray> request_line = lines.first().trimmed().split(' ');
    QByteArray host;
    if (request_line.size() != 3 || request_line.at(2) != "HTTP/1.1"
        || !headers(lines.mid(1), &host) || host.toLower() != expected_authority_.toLower().toLatin1()) {
        respond(socket, 400);
        return;
    }
    if (request_line.at(0) != "GET") {
        respond(socket, 405);
        return;
    }
    const QByteArray raw_target = request_line.at(1);
    const qsizetype question    = raw_target.indexOf('?');
    const QUrl target           = QUrl::fromEncoded(raw_target);
    if (raw_target.left(question) != callback_path_.toUtf8() || target.hasFragment()) {
        respond(socket, 400);
        return;
    }
    const QList<QByteArray> items = question < 0 ? QList<QByteArray> { } : raw_target.mid(question + 1).split('&');
    QHash<QString, QString> parameters;
    const QList<QString> allowed = { QStringLiteral("code"), QStringLiteral("state"), QStringLiteral("error"),
        QStringLiteral("error_description") };
    for (const auto& item : items) {
        const qsizetype equals = item.indexOf('=');
        if (equals <= 0 || item.indexOf('=', equals + 1) >= 0) {
            respond(socket, 400);
            return;
        }
        const auto name  = parameter(item.left(equals), 32);
        const auto value = parameter(item.mid(equals + 1), name == QStringLiteral("error_description") ? 512 : 2048);
        if (!name.has_value() || !value.has_value() || !allowed.contains(*name) || parameters.contains(*name)) {
            respond(socket, 400);
            return;
        }
        parameters.insert(*name, *value);
    }
    const QString state = parameters.value(QStringLiteral("state"));
    const QString code  = parameters.value(QStringLiteral("code"));
    const QString error = parameters.value(QStringLiteral("error"));
    if (state.isEmpty() || state.size() > 1024 || code.size() > 2048 || error.size() > 128
        || (code.isEmpty() == error.isEmpty())) {
        respond(socket, 400);
        return;
    }
    respond(socket, 200, true);
    emit authorization_received(state, code, error);
}

void OAuthCallbackServer::respond(QSslSocket* socket, int status, bool accepted)
{
    const auto timer = timers_.find(socket);
    if (timer == timers_.end()) {
        return;
    }
    (*timer)->stop();
    responded_.insert(socket);
    const QByteArray body     = accepted
        ? QByteArrayLiteral("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Sign-in</title>"
                            "<p>Sign-in finished. Return to the application.</p></html>")
        : QByteArrayLiteral("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Sign-in</title>"
                            "<p>The sign-in request could not be completed.</p></html>");
    const QByteArray reason   = status == 200 ? QByteArrayLiteral("OK") : status == 405 ? QByteArrayLiteral("Method Not Allowed")
                                                                                        : QByteArrayLiteral("Bad Request");
    const QByteArray response = "HTTP/1.1 " + QByteArray::number(status) + " " + reason + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: "
        + QByteArray::number(body.size()) + "\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n"
        + (status == 405 ? QByteArrayLiteral("Allow: GET\r\n") : QByteArray()) + "\r\n" + body;
    socket->write(response);
    socket->flush();
    socket->disconnectFromHost();
}

void OAuthCallbackServer::socket_finished(QSslSocket* socket)
{
    requests_.remove(socket);
    timers_.remove(socket);
    responded_.remove(socket);
    if (!closing_) {
        socket->deleteLater();
    }
}

void OAuthCallbackServer::close()
{
    if (closing_) {
        return;
    }
    closing_ = true;
    QTcpServer::close();
    const auto sockets = requests_.keys();
    for (QSslSocket* socket : sockets) {
        socket->abort();
        socket_finished(socket);
        socket->deleteLater();
    }
    callback_url_.clear();
    closing_ = false;
}

} // namespace tcp_chat::auth

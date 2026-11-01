#pragma once

#include <QFile>
#include <QHash>
#include <QSet>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>
#include <QTimer>

#include <functional>

namespace tcp_chat::testing {

/// Contains one bounded HTTP request captured by the local fake provider.
struct OAuthHttpRequest {
    QByteArray method;
    QByteArray target;
    QHash<QByteArray, QByteArray> headers;
    QByteArray body;
};

/// Contains a configurable local provider response.
struct OAuthHttpResponse {
    /// Creates a JSON response with optional body and additional headers.
    OAuthHttpResponse(int status = 200, QByteArray content_type = QByteArrayLiteral("application/json"),
        QByteArray body = { }, QHash<QByteArray, QByteArray> headers = { })
        : status(status)
        , content_type(content_type)
        , body(body)
        , headers(headers)
    {
    }

    int status;
    QByteArray content_type;
    QByteArray body;
    QHash<QByteArray, QByteArray> headers;
};

/// Serves deterministic HTTPS endpoints for provider tests without external network access.
class OAuthHttpTestServer : public QTcpServer {
public:
    /// Starts a loopback-only TLS listener with the non-production fixture certificate.
    bool start()
    {
        const QString root      = QStringLiteral(TCP_CHAT_SOURCE_DIR "/tests/tls_fixtures/");
        const auto certificates = QSslCertificate::fromPath(root + QStringLiteral("trusted_server.crt"), QSsl::Pem);
        QFile key_file(root + QStringLiteral("trusted_server.key"));
        if (certificates.isEmpty() || !key_file.open(QIODevice::ReadOnly)) {
            return false;
        }
        const QSslKey key(&key_file, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
        if (key.isNull()) {
            return false;
        }
        ssl_ = QSslConfiguration::defaultConfiguration();
        ssl_.setProtocol(QSsl::TlsV1_2OrLater);
        ssl_.setLocalCertificateChain(certificates);
        ssl_.setPrivateKey(key);
        ssl_.setPeerVerifyMode(QSslSocket::VerifyNone);
        return listen(QHostAddress::LocalHost, 0);
    }

    /// Stops the listener and all outstanding local provider requests.
    ~OAuthHttpTestServer() override
    {
        QTcpServer::close();
        const auto sockets = buffers_.keys();
        for (QSslSocket* socket : sockets) {
            socket->abort();
            socket->deleteLater();
        }
        buffers_.clear();
        responded_.clear();
    }

    /// Returns an exact local HTTPS endpoint for the supplied path.
    QUrl endpoint(const QString& path) const
    {
        return QUrl(QStringLiteral("https://localhost:%1%2").arg(serverPort()).arg(path));
    }

    std::function<OAuthHttpResponse(const OAuthHttpRequest&)> handler;
    QList<OAuthHttpRequest> requests;
    bool stall = false;

protected:
    /// Accepts a bounded local HTTPS request and returns a configured response.
    void incomingConnection(qintptr descriptor) override
    {
        if (buffers_.size() >= 8) {
            QSslSocket socket;
            if (socket.setSocketDescriptor(descriptor)) {
                socket.abort();
            }
            return;
        }
        auto* socket = new QSslSocket(this);
        socket->setSslConfiguration(ssl_);
        buffers_.insert(socket, QByteArray());
        QObject::connect(socket, &QSslSocket::sslErrors, socket, &QSslSocket::abort);
        QObject::connect(socket, &QSslSocket::readyRead, this, [this, socket] { read_request(socket); });
        QObject::connect(socket, &QSslSocket::disconnected, this, [this, socket] {
            buffers_.remove(socket);
            responded_.remove(socket);
            socket->deleteLater();
        });
        QTimer::singleShot(3000, socket, &QSslSocket::abort);
        if (!socket->setSocketDescriptor(descriptor)) {
            buffers_.remove(socket);
            socket->deleteLater();
            return;
        }
        socket->startServerEncryption();
    }

private:
    /// Parses one complete request, invokes the fixture, and closes the connection.
    void read_request(QSslSocket* socket)
    {
        if (responded_.contains(socket)) {
            return;
        }
        auto buffer = buffers_.find(socket);
        if (buffer == buffers_.end()) {
            return;
        }
        if (buffer->size() + socket->bytesAvailable() > 65536) {
            socket->abort();
            return;
        }
        buffer->append(socket->readAll());
        const qsizetype header_end = buffer->indexOf("\r\n\r\n");
        if (header_end < 0) {
            return;
        }
        const QList<QByteArray> lines = buffer->left(header_end).split('\n');
        if (lines.isEmpty()) {
            socket->abort();
            return;
        }
        const QList<QByteArray> request_line = lines.first().trimmed().split(' ');
        OAuthHttpRequest request;
        if (request_line.size() == 3) {
            request.method = request_line.at(0);
            request.target = request_line.at(1);
        }
        qsizetype content_length = 0;
        for (const auto& line : lines.mid(1)) {
            const qsizetype colon = line.indexOf(':');
            if (colon <= 0) {
                socket->abort();
                return;
            }
            const QByteArray name  = line.left(colon).trimmed().toLower();
            const QByteArray value = line.mid(colon + 1).trimmed();
            request.headers.insert(name, value);
            if (name == QByteArrayLiteral("content-length")) {
                bool valid     = false;
                content_length = value.toLongLong(&valid);
                if (!valid || content_length < 0 || content_length > 65536) {
                    socket->abort();
                    return;
                }
            }
        }
        if (buffer->size() < header_end + 4 + content_length) {
            return;
        }
        request.body = buffer->mid(header_end + 4, content_length);
        responded_.insert(socket);
        requests.append(request);
        if (stall) {
            return;
        }
        const OAuthHttpResponse response = handler ? handler(request) : OAuthHttpResponse { 500 };
        const QByteArray reason          = response.status == 200 ? QByteArrayLiteral("OK") : QByteArrayLiteral("Error");
        QByteArray encoded               = "HTTP/1.1 " + QByteArray::number(response.status) + " " + reason + "\r\nContent-Type: "
            + response.content_type + "\r\nContent-Length: " + QByteArray::number(response.body.size()) + "\r\nConnection: close\r\n";
        for (auto it = response.headers.cbegin(); it != response.headers.cend(); ++it) {
            encoded += it.key() + ": " + it.value() + "\r\n";
        }
        encoded += "\r\n" + response.body;
        socket->write(encoded);
        socket->flush();
        socket->disconnectFromHost();
    }

    QSslConfiguration ssl_;
    QHash<QSslSocket*, QByteArray> buffers_;
    QSet<QSslSocket*> responded_;
};

} // namespace tcp_chat::testing

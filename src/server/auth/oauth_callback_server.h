#pragma once

#include <QHash>
#include <QHostAddress>
#include <QSet>
#include <QSslConfiguration>
#include <QTcpServer>
#include <QTimer>
#include <QUrl>

#include <chrono>
#include <optional>

class QSslSocket;

namespace tcp_chat::auth {

/// Configures a bounded HTTPS-only receiver for OAuth authorization callbacks.
struct OAuthCallbackServerOptions {
    QHostAddress address = QHostAddress::LocalHost;
    quint16 port         = 0;
    QString expected_authority;
    QString callback_path = QStringLiteral("/oauth/callback");
    QString certificate_chain_file;
    QString private_key_file;
    int maximum_connections         = 16;
    int maximum_pending_connections = 8;
    qsizetype maximum_request_bytes = 8192;
    std::chrono::milliseconds request_timeout { 10000 };
};

/// Receives validated OAuth callbacks independently of the framed chat transport.
class OAuthCallbackServer : public QTcpServer {
    Q_OBJECT

public:
    /// Creates a stopped callback listener.
    explicit OAuthCallbackServer(QObject* parent = nullptr);
    /// Stops the listener and aborts outstanding requests.
    ~OAuthCallbackServer() override;

    OAuthCallbackServer(const OAuthCallbackServer&)            = delete;
    OAuthCallbackServer& operator=(const OAuthCallbackServer&) = delete;

    /// Loads the server certificate and starts TLS-only listening.
    std::optional<QString> start(const OAuthCallbackServerOptions& options);
    /// Returns the exact redirect URL to register with providers.
    QUrl callback_url() const;
    /// Stops accepting requests and closes outstanding sockets.
    void close();

signals:
    /// Publishes only syntactically validated callback parameters for state validation.
    void authorization_received(const QString& state, const QString& code, const QString& error);

protected:
    /// Accepts a socket within the configured connection bound.
    void incomingConnection(qintptr descriptor) override;

private:
    /// Parses a complete bounded HTTP request and responds without reflecting credentials.
    void request_ready(QSslSocket* socket);
    /// Sends a static response and closes the encrypted connection.
    void respond(QSslSocket* socket, int status, bool accepted = false);
    /// Removes per-request state after a socket finishes.
    void socket_finished(QSslSocket* socket);

    QHash<QSslSocket*, QByteArray> requests_;
    QHash<QSslSocket*, QTimer*> timers_;
    QSet<QSslSocket*> responded_;
    QSslConfiguration ssl_configuration_;
    QUrl callback_url_;
    QString expected_authority_;
    QString callback_path_;
    OAuthCallbackServerOptions options_;
    bool closing_ = false;
};

} // namespace tcp_chat::auth

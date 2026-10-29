#include "tcp_chat/version.h"

namespace tcp_chat {

QString application_version()
{
    return QStringLiteral(TCP_CHAT_APPLICATION_VERSION);
}

} // namespace tcp_chat

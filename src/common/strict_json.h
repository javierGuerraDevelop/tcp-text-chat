#pragma once

#include <QByteArrayView>

namespace tcp_chat::protocol::detail {

inline constexpr int maximum_json_depth = 64;

/// Validates strict JSON syntax and unique decoded object keys after UTF-8 validation.
bool is_strict_json(QByteArrayView json);

} // namespace tcp_chat::protocol::detail

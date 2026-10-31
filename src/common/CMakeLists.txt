add_library(tcp_chat_common STATIC
    auth_protocol.cpp
    frame.cpp
    protocol.cpp
    strict_json.cpp
    version.cpp
)
add_library(tcp_chat::common ALIAS tcp_chat_common)

target_include_directories(tcp_chat_common
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
)
target_link_libraries(tcp_chat_common PUBLIC Qt6::Core)
target_compile_definitions(
    tcp_chat_common
    PRIVATE TCP_CHAT_APPLICATION_VERSION="${PROJECT_VERSION}"
)

tcp_chat_configure_target(tcp_chat_common)

add_library(tcp_chat_transport STATIC
    framed_socket.cpp
    "${PROJECT_SOURCE_DIR}/include/tcp_chat/framed_socket.h"
)
add_library(tcp_chat::transport ALIAS tcp_chat_transport)

target_include_directories(tcp_chat_transport
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
)
target_link_libraries(tcp_chat_transport
    PUBLIC
        tcp_chat::common
        Qt6::Network
)

tcp_chat_configure_target(tcp_chat_transport)

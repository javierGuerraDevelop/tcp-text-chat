add_library(tcp_chat_chat STATIC
    message_service.cpp
    message_service.h
)
add_library(tcp_chat::chat ALIAS tcp_chat_chat)

target_include_directories(tcp_chat_chat
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>"
)
target_link_libraries(tcp_chat_chat
    PUBLIC
        tcp_chat::auth
        tcp_chat::server
        tcp_chat::storage
)

tcp_chat_configure_target(tcp_chat_chat)

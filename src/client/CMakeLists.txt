add_library(tcp_chat_client_transport STATIC
    oauth_client.cpp
    oauth_client.h
    tls_client.cpp
    tls_client.h
)
add_library(tcp_chat::client ALIAS tcp_chat_client_transport)

target_include_directories(tcp_chat_client_transport
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>"
)
target_link_libraries(tcp_chat_client_transport
    PUBLIC
        tcp_chat::transport
        Qt6::Gui
)

tcp_chat_configure_target(tcp_chat_client_transport)

add_executable(tcp_chat_client
    main.cpp
)

target_link_libraries(tcp_chat_client
    PRIVATE
        tcp_chat::client
        Qt6::Widgets
)

tcp_chat_configure_target(tcp_chat_client)

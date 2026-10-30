add_subdirectory(storage)

add_library(tcp_chat_server_transport STATIC
    tls_server.cpp
    tls_server.h
)
add_library(tcp_chat::server ALIAS tcp_chat_server_transport)

target_include_directories(tcp_chat_server_transport
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>"
)
target_link_libraries(tcp_chat_server_transport
    PUBLIC
        tcp_chat::transport
)

tcp_chat_configure_target(tcp_chat_server_transport)

add_executable(tcp_chat_server
    main.cpp
)

target_link_libraries(tcp_chat_server
    PRIVATE
        tcp_chat::server
        tcp_chat::storage
        Qt6::Core
)

tcp_chat_configure_target(tcp_chat_server)

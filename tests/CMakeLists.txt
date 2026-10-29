add_executable(tcp_chat_tests
    test_version.cpp
)

target_link_libraries(tcp_chat_tests
    PRIVATE
        tcp_chat::common
        Qt6::Test
)
target_compile_definitions(
    tcp_chat_tests
    PRIVATE TCP_CHAT_APPLICATION_VERSION="${PROJECT_VERSION}"
)

tcp_chat_configure_target(tcp_chat_tests)

add_test(NAME common.version COMMAND tcp_chat_tests)
add_test(NAME client.version COMMAND tcp_chat_client --version)
add_test(NAME server.version COMMAND tcp_chat_server --version)

set_tests_properties(client.version PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    PASS_REGULAR_EXPRESSION "tcp-text-chat-client ${PROJECT_VERSION}"
)
set_tests_properties(server.version PROPERTIES
    PASS_REGULAR_EXPRESSION "tcp-text-chat-server ${PROJECT_VERSION}"
)

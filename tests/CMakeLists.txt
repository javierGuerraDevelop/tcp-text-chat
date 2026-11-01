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

add_executable(tcp_chat_protocol_tests
    test_protocol.cpp
)
target_link_libraries(tcp_chat_protocol_tests
    PRIVATE
        tcp_chat::common
        Qt6::Test
)
tcp_chat_configure_target(tcp_chat_protocol_tests)

add_executable(tcp_chat_frame_decoder_tests
    test_frame_decoder.cpp
)
target_link_libraries(tcp_chat_frame_decoder_tests
    PRIVATE
        tcp_chat::common
        Qt6::Test
)
tcp_chat_configure_target(tcp_chat_frame_decoder_tests)

function(tcp_chat_add_storage_test target source test_name)
    add_executable(${target} ${source})
    target_link_libraries(${target}
        PRIVATE
            tcp_chat::storage
            Qt6::Test
    )
    target_compile_definitions(
        ${target}
        PRIVATE TCP_CHAT_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
    )
    tcp_chat_configure_target(${target})
    add_test(NAME ${test_name} COMMAND ${target})
endfunction()

function(tcp_chat_add_auth_test target source test_name)
    add_executable(${target} ${source})
    target_link_libraries(${target}
        PRIVATE
            tcp_chat::auth
            Qt6::Test
    )
    target_compile_definitions(
        ${target}
        PRIVATE TCP_CHAT_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
    )
    tcp_chat_configure_target(${target})
    add_test(NAME ${test_name} COMMAND ${target})
endfunction()

add_executable(tcp_chat_transport_tests
    test_tls_transport.cpp
)
target_link_libraries(tcp_chat_transport_tests
    PRIVATE
        tcp_chat::client
        tcp_chat::server
        Qt6::Test
)
target_compile_definitions(
    tcp_chat_transport_tests
    PRIVATE TCP_CHAT_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
)
tcp_chat_configure_target(tcp_chat_transport_tests)

tcp_chat_add_storage_test(tcp_chat_migration_tests test_migration_runner.cpp migrations)
tcp_chat_add_storage_test(tcp_chat_account_tests test_account_repository.cpp accounts)
tcp_chat_add_storage_test(tcp_chat_session_tests test_session_repository.cpp sessions)
tcp_chat_add_storage_test(tcp_chat_message_tests test_message_repository.cpp messages)
tcp_chat_add_storage_test(tcp_chat_worker_tests test_database_worker.cpp database_worker)
tcp_chat_add_auth_test(tcp_chat_auth_protocol_tests test_auth_protocol.cpp auth_protocol)
tcp_chat_add_auth_test(tcp_chat_password_tests test_password_hasher.cpp password_hasher)
tcp_chat_add_auth_test(tcp_chat_token_tests test_session_token.cpp session_token)
tcp_chat_add_auth_test(tcp_chat_limiter_tests test_attempt_limiter.cpp attempt_limiter)
tcp_chat_add_auth_test(tcp_chat_authentication_tests test_authentication_service.cpp authentication_service)
target_link_libraries(tcp_chat_authentication_tests PRIVATE tcp_chat::client)
tcp_chat_add_storage_test(tcp_chat_oauth_account_tests test_oauth_account_repository.cpp oauth_accounts)
tcp_chat_add_storage_test(tcp_chat_oauth_worker_tests test_oauth_database_worker.cpp oauth_database_worker)
tcp_chat_add_auth_test(tcp_chat_oauth_protocol_tests test_oauth_protocol.cpp oauth_protocol)
tcp_chat_add_auth_test(tcp_chat_oauth_coordinator_tests test_oauth_coordinator.cpp oauth_coordinator)
tcp_chat_add_auth_test(tcp_chat_oauth_callback_tests test_oauth_callback_server.cpp oauth_callback)
tcp_chat_add_auth_test(tcp_chat_oauth_client_tests test_oauth_client.cpp oauth_client)
target_link_libraries(tcp_chat_oauth_client_tests PRIVATE tcp_chat::client)
tcp_chat_add_auth_test(tcp_chat_http_provider_tests test_http_oauth_provider.cpp http_oauth_provider)
tcp_chat_add_auth_test(tcp_chat_provider_factory_tests test_oauth_provider_factory.cpp oauth_provider_factory)
if(TCP_CHAT_ENABLE_OAUTH_SMOKE_TESTS)
    tcp_chat_add_auth_test(tcp_chat_oauth_smoke_tests test_oauth_provider_smoke.cpp oauth_smoke)
endif()
function(tcp_chat_add_ui_test target source test_name)
    add_executable(${target} ${source})
    target_link_libraries(${target}
        PRIVATE
            tcp_chat::client_ui
            Qt6::Test
    )
    tcp_chat_configure_target(${target})
    add_test(NAME ${test_name} COMMAND ${target})
    set_tests_properties(${test_name} PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_QPA_PLATFORMTHEME=generic"
    )
endfunction()

tcp_chat_add_ui_test(tcp_chat_theme_tests test_theme_manager.cpp theme)
tcp_chat_add_ui_test(tcp_chat_main_window_tests test_main_window.cpp main_window)

add_test(NAME transport COMMAND tcp_chat_transport_tests)
add_test(NAME frame_decoder COMMAND tcp_chat_frame_decoder_tests)
add_test(NAME protocol COMMAND tcp_chat_protocol_tests)
add_test(NAME common.version COMMAND tcp_chat_tests)
add_test(NAME client.version COMMAND tcp_chat_client --version)
add_test(NAME server.version COMMAND tcp_chat_server --version)

set_tests_properties(client.version PROPERTIES
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_QPA_PLATFORMTHEME=generic"
    PASS_REGULAR_EXPRESSION "tcp-text-chat-client ${PROJECT_VERSION}"
)
set_tests_properties(server.version PROPERTIES
    PASS_REGULAR_EXPRESSION "tcp-text-chat-server ${PROJECT_VERSION}"
)

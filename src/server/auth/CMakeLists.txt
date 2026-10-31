find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

add_library(tcp_chat_auth STATIC
    authentication_service.cpp
    authentication_service.h
    attempt_limiter.cpp
    attempt_limiter.h
    password_hasher.cpp
    password_hasher.h
    session_token.cpp
    session_token.h
)
add_library(tcp_chat::auth ALIAS tcp_chat_auth)

target_include_directories(tcp_chat_auth
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>"
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
)
target_link_libraries(tcp_chat_auth
    PUBLIC
        tcp_chat::server
        tcp_chat::storage
        tcp_chat::common
        PkgConfig::SODIUM
        Qt6::Core
        Qt6::Network
)

tcp_chat_configure_target(tcp_chat_auth)

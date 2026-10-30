add_library(tcp_chat_storage STATIC
    account_repository.cpp
    migration_runner.cpp
    session_repository.cpp
    sql_utils.cpp
)
add_library(tcp_chat::storage ALIAS tcp_chat_storage)

target_include_directories(tcp_chat_storage
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>"
)
target_link_libraries(tcp_chat_storage
    PUBLIC
        tcp_chat::common
        Qt6::Sql
)

tcp_chat_configure_target(tcp_chat_storage)

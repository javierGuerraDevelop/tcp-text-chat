add_library(tcp_chat_common STATIC
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

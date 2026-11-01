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

add_library(tcp_chat_client_ui STATIC
    main_window.cpp
    main_window.h
    theme_manager.cpp
    theme_manager.h
)
add_library(tcp_chat::client_ui ALIAS tcp_chat_client_ui)

target_include_directories(tcp_chat_client_ui
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>"
)
target_link_libraries(tcp_chat_client_ui
    PUBLIC
        Qt6::Widgets
)
set_source_files_properties("${PROJECT_SOURCE_DIR}/resources/theme.qss"
    PROPERTIES QT_RESOURCE_ALIAS "theme.qss"
)
qt_add_resources(tcp_chat_client_ui "client_resources"
    PREFIX "/tcp_chat"
    FILES "${PROJECT_SOURCE_DIR}/resources/theme.qss"
)

tcp_chat_configure_target(tcp_chat_client_ui)

add_executable(tcp_chat_client
    main.cpp
)

target_link_libraries(tcp_chat_client
    PRIVATE
        tcp_chat::client_ui
        tcp_chat::common
)

tcp_chat_configure_target(tcp_chat_client)

add_executable(tcp_chat_client
    main.cpp
)

target_link_libraries(tcp_chat_client
    PRIVATE
        tcp_chat::common
        Qt6::Widgets
)

tcp_chat_configure_target(tcp_chat_client)

add_executable(tcp_chat_server
    main.cpp
)

target_link_libraries(tcp_chat_server
    PRIVATE
        tcp_chat::common
        Qt6::Core
)

tcp_chat_configure_target(tcp_chat_server)

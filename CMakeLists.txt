cmake_minimum_required(VERSION 3.24)

project(
    tcp_text_chat
    VERSION 0.1.0
    DESCRIPTION "Qt desktop TCP text chat"
    LANGUAGES CXX
)

option(TCP_CHAT_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(TCP_CHAT_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(TCP_CHAT_ENABLE_OAUTH_SMOKE_TESTS "Build explicitly configured real OAuth provider smoke tests" OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if(TCP_CHAT_ENABLE_SANITIZERS AND NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR "TCP_CHAT_ENABLE_SANITIZERS requires GCC or Clang")
endif()

function(tcp_chat_configure_target target)
    target_compile_features(${target} PRIVATE cxx_std_20)

    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
        if(TCP_CHAT_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        if(TCP_CHAT_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()

    if(TCP_CHAT_ENABLE_SANITIZERS)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    endif()
endfunction()

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Gui Widgets Network Sql)

add_subdirectory(src/common)
add_subdirectory(src/client)
add_subdirectory(src/server)

include(CTest)
if(BUILD_TESTING)
    find_package(Qt6 6.5 REQUIRED COMPONENTS Test)
    add_subdirectory(tests)
endif()

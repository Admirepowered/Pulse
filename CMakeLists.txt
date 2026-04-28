cmake_minimum_required(VERSION 3.20)

project(PulseProxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

include(CheckIncludeFile)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

pkg_check_modules(PULSE_OPENSSL REQUIRED IMPORTED_TARGET openssl)
pkg_check_modules(PULSE_NGHTTP3 REQUIRED IMPORTED_TARGET libnghttp3)

set(CMAKE_REQUIRED_INCLUDES ${PULSE_OPENSSL_INCLUDE_DIRS})
set(CMAKE_REQUIRED_DEFINITIONS ${PULSE_OPENSSL_CFLAGS_OTHER})
check_include_file("openssl/quic.h" PULSE_OPENSSL_HAS_QUIC)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_DEFINITIONS)

if(NOT PULSE_OPENSSL_HAS_QUIC)
    message(FATAL_ERROR "OpenSSL QUIC headers were not found; Hysteria2 build requires openssl/quic.h")
endif()

add_executable(vless_proxy
    src/app/main.c
    src/core/pulse.c
    src/core/mmdb.c
    src/core/socket_io.c
    src/inbounds/server.c
    src/manager/config.c
    src/manager/subscription.c
    src/outbounds/stream.c
    src/outbounds/protocol_helpers.c
    src/outbounds/anytls.c
    src/outbounds/shadowsocks.c
    src/outbounds/stubs.c
    src/outbounds/trojan.c
    src/outbounds/vmess.c
    src/outbounds/vless.c
    src/outbounds/hysteria2.c
)

target_include_directories(vless_proxy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/src/core)
target_compile_definitions(vless_proxy PRIVATE PULSE_HAVE_HYSTERIA2=1 NGHTTP3_STATICLIB)
target_link_libraries(vless_proxy PRIVATE PkgConfig::PULSE_OPENSSL PkgConfig::PULSE_NGHTTP3)

if(MSVC)
    target_compile_options(vless_proxy PRIVATE /W4)
else()
    target_compile_options(vless_proxy PRIVATE -Wall -Wextra -O2)
endif()

if(WIN32)
    target_link_libraries(vless_proxy PRIVATE ws2_32)
else()
    target_link_libraries(vless_proxy PRIVATE Threads::Threads)
endif()

set_target_properties(vless_proxy PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
)

if(WIN32)
    get_filename_component(PULSE_TOOLCHAIN_BIN_DIR "${CMAKE_C_COMPILER}" DIRECTORY)
    set(PULSE_RUNTIME_DLLS
        libcrypto-3-x64.dll
        libssl-3-x64.dll
        libnghttp3-9.dll
        libgcc_s_seh-1.dll
        libwinpthread-1.dll
        libstdc++-6.dll
        zlib1.dll
    )

    foreach(pulse_dll IN LISTS PULSE_RUNTIME_DLLS)
        add_custom_command(TARGET vless_proxy POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${PULSE_TOOLCHAIN_BIN_DIR}/${pulse_dll}"
                "$<TARGET_FILE_DIR:vless_proxy>/${pulse_dll}"
            VERBATIM
        )
    endforeach()
endif()

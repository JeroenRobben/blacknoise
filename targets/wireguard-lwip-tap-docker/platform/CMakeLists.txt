cmake_minimum_required(VERSION 3.28)
project(wireguard-linux-test C)

set(CMAKE_C_STANDARD 11)
add_compile_options(-g)

include(FetchContent)

# lwIP bundles its own contrib directory, so only one fetch needed.
# FetchContent_MakeAvailable will also process lwIP's own CMakeLists.txt which
# creates EXCLUDE_FROM_ALL lwipcore/lwipcontribportunix targets (unused by us).
# EXCLUDE_FROM_ALL (CMake 3.28+) prevents lwIP's own example_app targets from
# being built by default when running `cmake --build`.
FetchContent_Declare(lwip
    GIT_REPOSITORY https://github.com/lwip-tcpip/lwip.git
    GIT_TAG        STABLE-2_2_0_RELEASE
    GIT_SHALLOW    TRUE
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(lwip)

set(LWIP_DIR     ${lwip_SOURCE_DIR})
set(LWIP_CONTRIB ${lwip_SOURCE_DIR}/contrib)

# Manually list the lwIP sources we need (avoids include_guard issues with
# Filelists.cmake which was already included by lwIP's own CMakeLists.txt).
set(LWIP_SRCS
    # Core
    ${LWIP_DIR}/src/core/init.c
    ${LWIP_DIR}/src/core/def.c
    ${LWIP_DIR}/src/core/inet_chksum.c
    ${LWIP_DIR}/src/core/ip.c
    ${LWIP_DIR}/src/core/mem.c
    ${LWIP_DIR}/src/core/memp.c
    ${LWIP_DIR}/src/core/netif.c
    ${LWIP_DIR}/src/core/pbuf.c
    ${LWIP_DIR}/src/core/stats.c
    ${LWIP_DIR}/src/core/sys.c
    ${LWIP_DIR}/src/core/timeouts.c
    ${LWIP_DIR}/src/core/udp.c
    # IPv4
    ${LWIP_DIR}/src/core/ipv4/etharp.c
    ${LWIP_DIR}/src/core/ipv4/icmp.c
    ${LWIP_DIR}/src/core/ipv4/ip4.c
    ${LWIP_DIR}/src/core/ipv4/ip4_addr.c
    ${LWIP_DIR}/src/core/ipv4/ip4_frag.c
    # Netif
    ${LWIP_DIR}/src/netif/ethernet.c
    # API (needed for tcpip_init / tcpip thread)
    ${LWIP_DIR}/src/api/tcpip.c
    ${LWIP_DIR}/src/api/err.c
    ${LWIP_DIR}/src/api/netifapi.c
    # Contrib unix port: sys_arch (pthreads) + TAP netif
    ${LWIP_CONTRIB}/ports/unix/port/sys_arch.c
    ${LWIP_CONTRIB}/ports/unix/port/netif/tapif.c
    ${LWIP_CONTRIB}/ports/unix/port/netif/list.c
    ${LWIP_CONTRIB}/ports/unix/port/netif/fifo.c
)

# WireGuard sources
set(WG_SRCS
    ../../src/wireguard.c
    ../../src/wireguardif.c
    ../../src/crypto.c
    ../../src/crypto/refc/blake2s.c
    ../../src/crypto/refc/chacha20.c
    ../../src/crypto/refc/chacha20poly1305.c
    ../../src/crypto/refc/poly1305-donna.c
    ../../src/crypto/refc/x25519.c
    wireguard-platform.c
)

add_executable(wg-test
    main.c
    ${LWIP_SRCS}
    ${WG_SRCS}
)

target_include_directories(wg-test PRIVATE
    # Our lwipopts.h must come first so it shadows any from lwIP contrib
    ${CMAKE_CURRENT_SOURCE_DIR}
    # lwIP public headers
    ${LWIP_DIR}/src/include
    # arch/cc.h, arch/sys_arch.h, netif/tapif.h
    ${LWIP_CONTRIB}/ports/unix/port/include
    # WireGuard headers (wireguard-platform.h, crypto.h, etc.)
    ../../src
)

target_link_libraries(wg-test pthread rt)

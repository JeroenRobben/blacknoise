/*
 * Linux test harness for wireguard-lwip using the lwIP contrib TAP port.
 *
 * Network setup:
 *   tap0  - underlying interface (carries encrypted WireGuard UDP traffic)
 *   wg0   - WireGuard virtual interface (carries plaintext VPN traffic)
 *
 * You need a TAP device available. Create one with:
 *   ip tuntap add dev tap0 mode tap user $(whoami)
 *   ip addr add <TAP_ADDR>/24 dev tap0
 *   ip link set tap0 up
 *
 * Usage:
 *   wg-test <wg_private_key_b64> <wg_ip>
 *           <peer_public_key_b64> <peer_wg_ip>
 *           <peer_endpoint_ip> <peer_endpoint_port>
 *           <tap_ip> <tap_gw>
 *
 * Example (connecting to a kernel WireGuard peer at 10.0.0.1:51820):
 *   wg-test "8BU1giso...Vg=" "10.0.0.2" \
 *           "cDfetaDFWn...jo=" "10.0.0.1" \
 *           "192.168.1.1" 51820 \
 *           "192.168.1.100" "192.168.1.1"
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"
#include "lwip/udp.h"
#include "netif/tapif.h"

#include "wireguardif.h"

#define ECHO_PORT 9000

static struct netif tap_netif;
static struct netif wg_netif;
static uint8_t wg_peer_index = WIREGUARDIF_INVALID_INDEX;

/* UDP echo service: echoes every received datagram back to its sender. */
static void echo_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                      const ip_addr_t *addr, u16_t port) {
    (void)arg;
    if (p == NULL) return;

    printf("echo: %s:%u -> len=%u data=\"%.*s\"\n",
           ipaddr_ntoa(addr), port,
           p->tot_len, (int)p->len, (char *)p->payload);

    if (!ip4_addr_netcmp(ip_2_ip4(addr), netif_ip4_addr(&wg_netif), netif_ip4_netmask(&wg_netif))) {
        /* Probe on physical interface — trigger WireGuard handshake initiation. */
        wireguardif_connect(&wg_netif, wg_peer_index);
    }
    udp_sendto(pcb, p, addr, port);
    pbuf_free(p);
}

static void tcpip_init_done(void *arg) {
    /* Set up echo service while still inside the tcpip thread. */
    struct udp_pcb *echo_pcb = udp_new();
    if (echo_pcb) {
        udp_bind(echo_pcb, IP_ADDR_ANY, ECHO_PORT);
        udp_recv(echo_pcb, echo_recv, NULL);
    }
    sys_sem_signal((sys_sem_t *)arg);
}

int main(int argc, char *argv[]) {
    if (argc != 9) {
        fprintf(stderr,
            "Usage: %s <wg_private_key> <wg_ip>"
            " <peer_pubkey> <peer_wg_ip>"
            " <peer_endpoint_ip> <peer_endpoint_port>"
            " <tap_ip> <tap_gw>\n",
            argv[0]);
        return 1;
    }

    const char *wg_private_key     = argv[1];
    const char *wg_ip_str          = argv[2];
    const char *peer_pubkey        = argv[3];
    const char *peer_wg_ip_str     = argv[4];
    const char *peer_endpoint_str  = argv[5];
    uint16_t    peer_endpoint_port = (uint16_t)atoi(argv[6]);
    const char *tap_ip_str         = argv[7];
    const char *tap_gw_str         = argv[8];

    ip4_addr_t wg_ip, wg_mask, wg_gw;
    ip4_addr_t tap_ip, tap_mask, tap_gw;

    ip4addr_aton(wg_ip_str,        &wg_ip);
    ip4addr_aton(tap_ip_str,       &tap_ip);
    ip4addr_aton(tap_gw_str,       &tap_gw);
    IP4_ADDR(&wg_mask,  255, 255, 255, 0);
    IP4_ADDR(&wg_gw,    0,   0,   0,   0);
    IP4_ADDR(&tap_mask, 255, 255, 255, 0);

    /* Init lwIP in its own thread */
    sys_sem_t init_sem;
    sys_sem_new(&init_sem, 0);
    tcpip_init(tcpip_init_done, &init_sem);
    sys_sem_wait(&init_sem);
    sys_sem_free(&init_sem);
    printf("lwIP initialised\n");

    /* Add TAP interface (underlying physical/network layer) */
    netif_add(&tap_netif,
              &tap_ip, &tap_mask, &tap_gw,
              NULL,
              tapif_init,
              tcpip_input);
    netif_set_default(&tap_netif);
    netif_set_up(&tap_netif);
    printf("TAP interface up: %s\n", ip4addr_ntoa(&tap_ip));

    /* Add WireGuard interface */
    struct wireguardif_init_data wg = {
        .private_key = wg_private_key,
        .listen_port = WIREGUARDIF_DEFAULT_PORT,
        .bind_netif  = &tap_netif,
    };

    netif_add(&wg_netif,
              &wg_ip, &wg_mask, &wg_gw,
              &wg,
              wireguardif_init,
              ip_input);
    netif_set_up(&wg_netif);
    printf("WireGuard interface up: %s\n", ip4addr_ntoa(&wg_ip));

    /* Add peer */
    struct wireguardif_peer peer;
    wireguardif_peer_init(&peer);
    peer.public_key    = peer_pubkey;
    peer.preshared_key = NULL;
    peer.keep_alive    = 25; /* seconds */

    ip4_addr_t peer_wg_ip;
    ip4addr_aton(peer_wg_ip_str, &peer_wg_ip);
    peer.allowed_ip = peer_wg_ip;
    IP4_ADDR(&peer.allowed_mask, 255, 255, 255, 255);

    ip4_addr_t peer_ep_ip4;
    ip4addr_aton(peer_endpoint_str, &peer_ep_ip4);
    IP_ADDR4(&peer.endpoint_ip,
             ip4_addr1(&peer_ep_ip4), ip4_addr2(&peer_ep_ip4),
             ip4_addr3(&peer_ep_ip4), ip4_addr4(&peer_ep_ip4));
    peer.endport_port = peer_endpoint_port;

    wireguardif_add_peer(&wg_netif, &peer, &wg_peer_index);
    if (wg_peer_index == WIREGUARDIF_INVALID_INDEX) {
        fprintf(stderr, "Failed to add WireGuard peer\n");
        return 1;
    }
    printf("Peer added (index %u)\n", wg_peer_index);

    /* Run forever - lwIP and TAP run in their own threads */
    printf("Running. Press Ctrl+C to stop.\n");
    while (1) {
        sleep(5);

        ip_addr_t current_ip;
        uint16_t current_port;
        err_t err = wireguardif_peer_is_up(&wg_netif, wg_peer_index,
                                           &current_ip, &current_port);
        if (err == ERR_OK) {
            printf("Peer is UP: %s:%u\n",
                   ip4addr_ntoa(ip_2_ip4(&current_ip)), current_port);
        } else {
            printf("Peer is DOWN");
        }
    }

    return 0;
}

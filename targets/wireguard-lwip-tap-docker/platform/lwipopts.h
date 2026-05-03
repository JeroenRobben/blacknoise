#ifndef LWIPOPTS_H
#define LWIPOPTS_H

/* Use pthreads sys_arch from contrib unix port */
#define NO_SYS                          0
#define SYS_LIGHTWEIGHT_PROT            1
#define LWIP_TIMERS                     1

/* Use system malloc instead of fixed pools - simplest for Linux */
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_SIZE                        (4 * 1024 * 1024)

/* Protocols */
#define LWIP_ARP                        1
#define LWIP_ETHERNET                   1
#define LWIP_ICMP                       1
#define LWIP_UDP                        1   /* Required for WireGuard */
#define LWIP_TCP                        0
#define LWIP_RAW                        0
#define LWIP_DHCP                       0
#define LWIP_DNS                        0
#define LWIP_AUTOIP                     0
#define LWIP_IGMP                       0
#define LWIP_IPV6                       0

/* API */
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0
#define LWIP_NETIF_API                  1

/* Stats */
#define LWIP_STATS                      0

/* Checksum */
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_UDP              1

/* Buffers - generous for desktop use */
#define PBUF_POOL_SIZE                  64
#define MEMP_NUM_PBUF                   64
#define MEMP_NUM_UDP_PCB                8
#define MEMP_NUM_TCP_PCB                0
#define MEMP_NUM_NETCONN                0

/* Needed by tcpip_init */
#define TCPIP_MBOX_SIZE                 32
#define DEFAULT_UDP_RECVMBOX_SIZE       32
#define DEFAULT_ACCEPTMBOX_SIZE         32
#define DEFAULT_THREAD_STACKSIZE        4096
#define DEFAULT_THREAD_PRIO             1
#define TCPIP_THREAD_STACKSIZE          4096
#define TCPIP_THREAD_PRIO               1

#endif /* LWIPOPTS_H */

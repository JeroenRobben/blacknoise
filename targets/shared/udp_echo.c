#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define LISTEN_PORT 9000
#define REPLY_IP    "10.10.10.1"
#define REPLY_PORT  9000
#define BUF_SIZE    65535

int main(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_port        = htons(LISTEN_PORT);
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind"); return 1;
    }

    struct sockaddr_in reply_addr;
    memset(&reply_addr, 0, sizeof(reply_addr));
    reply_addr.sin_family = AF_INET;
    reply_addr.sin_port   = htons(REPLY_PORT);
    if (inet_pton(AF_INET, REPLY_IP, &reply_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid reply address: %s\n", REPLY_IP); return 1;
    }

    printf("Listening on 0.0.0.0:%d, forwarding payloads to %s:%d\n",
           LISTEN_PORT, REPLY_IP, REPLY_PORT);

    char buf[BUF_SIZE];
    while (1) {
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&from_addr, &from_len);
        if (n < 0) { perror("recvfrom"); continue; }

        buf[n] = '\0';
        char from_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from_addr.sin_addr, from_ip, sizeof(from_ip));
        printf("Received %zd bytes from %s:%d, payload: %s\n",
               n, from_ip, ntohs(from_addr.sin_port), buf);

        ssize_t sent = sendto(sock, buf, n, 0,
                              (struct sockaddr *)&reply_addr, sizeof(reply_addr));
        if (sent < 0) {
            perror("sendto");
        } else {
            printf("Forwarded %zd bytes to %s:%d\n", sent, REPLY_IP, REPLY_PORT);
        }
    }

    close(sock);
    return 0;
}

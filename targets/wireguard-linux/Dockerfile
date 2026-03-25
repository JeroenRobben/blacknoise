FROM alpine:latest
RUN apk add --no-cache wireguard-tools gcc musl-dev iproute2

# Build the UDP echo service from the shared source
COPY shared/udp_echo.c /tmp/udp_echo.c
RUN gcc -o /usr/local/bin/udp_echo /tmp/udp_echo.c && rm /tmp/udp_echo.c

# wg0.conf is mounted at runtime via docker-compose volume
RUN mkdir -p /etc/wireguard

COPY wireguard-linux/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

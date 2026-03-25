FROM golang:1.23-alpine AS wg-builder
RUN apk add --no-cache curl xz
RUN mkdir /tmp/wireguard-go \
    && curl -fsSL https://git.zx2c4.com/wireguard-go/snapshot/wireguard-go-0.0.20250522.tar.xz \
    | tar -xJ --strip-components=1 -C /tmp/wireguard-go \
    && cd /tmp/wireguard-go \
    && go build -o /usr/local/bin/wireguard-go .

FROM alpine:latest
RUN apk add --no-cache wireguard-tools gcc musl-dev iproute2

COPY --from=wg-builder /usr/local/bin/wireguard-go /usr/local/bin/wireguard-go

# Build the UDP echo service from the shared source
COPY shared/udp_echo.c /tmp/udp_echo.c
RUN gcc -o /usr/local/bin/udp_echo /tmp/udp_echo.c && rm /tmp/udp_echo.c

# wg0.conf is mounted at runtime via docker-compose volume
RUN mkdir -p /etc/wireguard

COPY wireguard-go/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

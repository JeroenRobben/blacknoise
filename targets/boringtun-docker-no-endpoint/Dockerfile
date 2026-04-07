FROM rust:alpine AS builder
RUN apk add --no-cache git musl-dev
RUN git clone https://github.com/cloudflare/boringtun.git /tmp/boringtun \
    && cd /tmp/boringtun \
    && cargo build --release --bin boringtun-cli \
    && cp target/release/boringtun-cli /usr/local/bin/boringtun-cli

FROM alpine:latest
RUN apk add --no-cache wireguard-tools gcc musl-dev iproute2

COPY --from=builder /usr/local/bin/boringtun-cli /usr/local/bin/boringtun-cli

# Build the UDP echo service from the shared source
COPY shared/udp_echo.c /tmp/udp_echo.c
RUN gcc -o /usr/local/bin/udp_echo /tmp/udp_echo.c && rm /tmp/udp_echo.c

# wg0.conf is mounted at runtime via docker-compose volume
RUN mkdir -p /etc/wireguard

COPY boringtun/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

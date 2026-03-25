FROM rust:alpine AS builder
RUN apk add --no-cache git musl-dev
RUN git clone https://github.com/mullvad/gotatun.git /tmp/gotatun \
    && cd /tmp/gotatun \
    && cargo build --release --bin gotatun \
    && cp target/release/gotatun /usr/local/bin/gotatun

FROM alpine:latest
RUN apk add --no-cache wireguard-tools gcc musl-dev iproute2

COPY --from=builder /usr/local/bin/gotatun /usr/local/bin/gotatun

# Build the UDP echo service from the shared source
COPY shared/udp_echo.c /tmp/udp_echo.c
RUN gcc -o /usr/local/bin/udp_echo /tmp/udp_echo.c && rm /tmp/udp_echo.c

# wg0.conf is mounted at runtime via docker-compose volume
RUN mkdir -p /etc/wireguard

COPY gotatun/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

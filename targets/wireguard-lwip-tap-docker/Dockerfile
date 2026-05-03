# Build stage: clone wireguard-lwip, overlay our platform files, build with cmake.
# cmake fetches lwIP automatically via FetchContent.
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 https://github.com/JeroenRobben/wireguard-lwip.git

# Only our platform code is part of this repository.
# Everything else (lwIP, wireguard-lwip core) is fetched by cmake.
COPY platform/ /src/wireguard-lwip/platform/linux/

RUN cmake -S /src/wireguard-lwip/platform/linux \
          -B /src/wireguard-lwip/platform/linux/build \
 && cmake --build /src/wireguard-lwip/platform/linux/build

# Runtime stage: minimal image with just the binary.
FROM debian:bookworm-slim
COPY --from=builder /src/wireguard-lwip/platform/linux/build/wg-test /usr/local/bin/wg-test
ENTRYPOINT ["wg-test"]

#include "wireguard-platform.h"

#include <string.h>
#include <time.h>
#include "crypto.h"

uint32_t wireguard_sys_now() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

void wireguard_random_bytes(void *bytes, size_t size) {
	// NOTE: static value - replace with a real RNG for production use
	memset(bytes, 0xAB, size);
}

void wireguard_tai64n_now(uint8_t *output) {
	// See https://cr.yp.to/libtai/tai64.html
	// 64 bit seconds from 1970 = 8 bytes
	// 32 bit nano seconds from current second
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	uint64_t seconds = 0x400000000000000aULL + (uint64_t)ts.tv_sec;
	uint32_t nanos = (uint32_t)ts.tv_nsec;
	U64TO8_BIG(output + 0, seconds);
	U32TO8_BIG(output + 8, nanos);
}

bool wireguard_is_under_load() {
	return false;
}

#include <stddef.h>
#include <stdint.h>

#define SHAKE256_RATE 136

void shake256_absorb(uint64_t *s, const uint8_t *input, size_t inlen);
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, uint64_t *s);

void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

#include <stdint.h>

/*
** Encryption and decryption functions for all the TBC in the SKINNY family 
** The version parameter "ver" selects the TBC of the family according to:
** 		0: SKINNY-64-64 (32 rounds)
** 		1: SKINNY-64-128 (36 rounds)
** 		2: SKINNY-64-192 (40 rounds)
** 		3: SKINNY-128-128 (40 rounds)
** 		4: SKINNY-128-256 (48 rounds)
** 		5: SKINNY-128-384 (56 rounds)
};
*/
void enc(const uint8_t* input, const uint8_t* tweakey, uint8_t* output, const int ver);
void dec(const uint8_t* input, const uint8_t* tweakey, uint8_t* output, const int ver);

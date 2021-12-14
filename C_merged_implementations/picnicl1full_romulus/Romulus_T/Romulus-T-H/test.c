#include <stdio.h>
#include <stdlib.h> 

#include "crypto_aead.h"
#include "romulus_t_hash.h"
#include "api.h"
#include "variant.h"
#include "skinny.h"
#include "romulus_t.h"

#include "romulus_t_reference.c"
#include "encrypt.c"
#include "decrypt.c"
#include "skinny_reference.c"
#include "hash.c"



/*
K - Key
N - Nounce
A - Associated Data
M - Message to encrypt
C - Ciphertext
T - Tag
*/


int main(int argc, char const *argv[])
{
	unsigned char* c = malloc(sizeof(unsigned char) * 16);
	unsigned long long clen = 16;

	unsigned char m[16] = {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; // done
	unsigned long long mlen = 16;   // done
    unsigned char *ad;   // done
    unsigned long long adlen;  // done
    unsigned char* nsec;
    
    // Nonce
    unsigned char npub[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; // done
    
    //Key
    unsigned char k[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; // done

    // No associated data passed
    adlen = 0;

    printf("\nmessage = ");

    for(int i = 0;i<16;i++){
        printf("%u",m[i]);
    }
    printf("\n\n");
    

	no_AEAD_romulus_t_encrypt(c, &clen, m, mlen, ad, adlen, nsec, npub, k);

	printf("cipher = %s\n\n", c);

	no_AEAD_romulus_t_decrypt(m, &mlen, nsec, c, clen, ad, adlen, npub, k);

	printf("\nmessage = ");

    for(int i = 0;i<16;i++){
        printf("%u",m[i]);
    }
    printf("\n\n");
	return 0;
}
/*! @file picnic_impl.c
 *  @brief This is the main file of the signature scheme. All of the LowMC MPC
 *  code is here as well as lower-level versions of sign and verify that are
 *  called by the signature API.
 *
 *  This file is part of the reference implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#if defined(__WINDOWS__)
        #include <Windows.h>
        #include <bcrypt.h>
#endif

#include "picnic_impl.h"
#include "picnic3_impl.h"
#include "picnic.h"
#include "platform.h"
#include "lowmc_constants.h"
#include "picnic_types.h"
#include "hash.h"
#include "wots.h"

/* PICNIC MACROS */

#define MAX(a, b) ((a) > (b)) ? (a) : (b)

#define VIEW_OUTPUTS(i, j) viewOutputs[(i) * 3 + (j)]

#define HASH_SIZE 17

int nrAND = 0;
int nrEnc = 0;
int nrSKINNY = 0;
int Debug = 0;

/* SKINNY MACROS */


#define SKINNY_AEAD_MEMBER 1

/* Control byte: Bit 4 concerns the nonce size: either 128 or 96 bits   */
#define CST_NONCE_128  (0<<4) /* 128 bits                               */
#define CST_NONCE_96   (1<<4) /*  96 bits                               */

/* Control byte: Bit 3 concerns the tag size: either 128 or 64 bits     */
#define CST_TAG_128    (0<<3) /* 128 bits                               */
#define CST_TAG_64     (1<<3) /*  64 bits                               */

/* Control byte: Bits 2-0 concerns the domain separation                */
#define CST_ENC_FULL     0x0 /* Encryption - Full block                 */
#define CST_ENC_PARTIAL  0x1 /* Encryption - Partial block              */
#define CST_AD_FULL      0x2 /* Associated Data - Full block            */
#define CST_AD_PARTIAL   0x3 /* Associated Data - Partial block         */
#define CST_TAG_FULL     0x4 /* Tag generation - Full message blocks    */
#define CST_TAG_PARTIAL  0x5 /* Tag generation - Partial message blocks */

//#define Nonce = {'\x00','\x01','\x02','\x03','\x04','\x05','\x06','\x07','\x08','\x09','\x0A','\x0B'}

// Table that encodes the parameters of the various SKINNY versions:
// (block size, key size, number of rounds)
static const int versions[6][3] = {
    { 64, 64, 32}, /* [0] -> SKINNY-64-64:   32 rounds */
    { 64,128, 36}, /* [1] -> SKINNY-64-128:  36 rounds */
    { 64,192, 40}, /* [2] -> SKINNY-64-192:  40 rounds */
    {128,128, 40}, /* [3] -> SKINNY-128-128: 40 rounds */
    {128,256, 48}, /* [4] -> SKINNY-128-256: 48 rounds */
    {128,384, 56}  /* [5] -> SKINNY-128-384: 56 rounds */
};

// 4-bit Sbox
static const uint8_t sbox_4[16] = {12,6,9,0,1,10,2,11,3,8,5,13,4,14,7,15};

// 8-bit Sbox
/*static const uint8_t sbox_8[256] = { 0x65,0x4c,0x6a,0x42,0x4b,0x63,0x43,0x6b,0x55,0x75,0x5a,0x7a,0x53,0x73,0x5b,0x7b
                                    ,0x35,0x8c,0x3a,0x81,0x89,0x33,0x80,0x3b,0x95,0x25,0x98,0x2a,0x90,0x23,0x99,0x2b 
                                    ,0xe5,0xcc,0xe8,0xc1,0xc9,0xe0,0xc0,0xe9,0xd5,0xf5,0xd8,0xf8,0xd0,0xf0,0xd9,0xf9 
                                    ,0xa5,0x1c,0xa8,0x12,0x1b,0xa0,0x13,0xa9,0x05,0xb5,0x0a,0xb8,0x03,0xb0,0x0b,0xb9 
                                    ,0x32,0x88,0x3c,0x85,0x8d,0x34,0x84,0x3d,0x91,0x22,0x9c,0x2c,0x94,0x24,0x9d,0x2d 
                                    ,0x62,0x4a,0x6c,0x45,0x4d,0x64,0x44,0x6d,0x52,0x72,0x5c,0x7c,0x54,0x74,0x5d,0x7d 
                                    ,0xa1,0x1a,0xac,0x15,0x1d,0xa4,0x14,0xad,0x02,0xb1,0x0c,0xbc,0x04,0xb4,0x0d,0xbd 
                                    ,0xe1,0xc8,0xec,0xc5,0xcd,0xe4,0xc4,0xed,0xd1,0xf1,0xdc,0xfc,0xd4,0xf4,0xdd,0xfd 
                                    ,0x36,0x8e,0x38,0x82,0x8b,0x30,0x83,0x39,0x96,0x26,0x9a,0x28,0x93,0x20,0x9b,0x29
                                    ,0x66,0x4e,0x68,0x41,0x49,0x60,0x40,0x69,0x56,0x76,0x58,0x78,0x50,0x70,0x59,0x79 
                                    ,0xa6,0x1e,0xaa,0x11,0x19,0xa3,0x10,0xab,0x06,0xb6,0x08,0xba,0x00,0xb3,0x09,0xbb 
                                    ,0xe6,0xce,0xea,0xc2,0xcb,0xe3,0xc3,0xeb,0xd6,0xf6,0xda,0xfa,0xd3,0xf3,0xdb,0xfb 
                                    ,0x31,0x8a,0x3e,0x86,0x8f,0x37,0x87,0x3f,0x92,0x21,0x9e,0x2e,0x97,0x27,0x9f,0x2f 
                                    ,0x61,0x48,0x6e,0x46,0x4f,0x67,0x47,0x6f,0x51,0x71,0x5e,0x7e,0x57,0x77,0x5f,0x7f 
                                    ,0xa2,0x18,0xae,0x16,0x1f,0xa7,0x17,0xaf,0x01,0xb2,0x0e,0xbe,0x07,0xb7,0x0f,0xbf 
                                    ,0xe2,0xca,0xee,0xc6,0xcf,0xe7,0xc7,0xef,0xd2,0xf2,0xde,0xfe,0xd7,0xf7,0xdf,0xff};
*/
// ShiftAndSwitchRows permutation
static const uint8_t P[16] = {0,1,2,3,7,4,5,6,10,11,8,9,13,14,15,12};

// Tweakey permutation
static const uint8_t TWEAKEY_P[16] = {9,15,8,13,10,14,12,11,0,1,2,3,4,5,6,7};

// round constants
static const uint8_t RC[62] = {
        0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
        0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
        0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
        0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
        0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
        0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28,
        0x10, 0x20};


/*
** Defines the state of the tweakey state for the SKINNY-AEAD instances.
*/

#if SKINNY_AEAD_MEMBER == 1
    #define TWEAKEY_STATE_SIZE 384 /* TK3 */
    #define TAG_SIZE           128 /* 128-bit authentication tag */

#elif SKINNY_AEAD_MEMBER == 2
    #define TWEAKEY_STATE_SIZE 384 /* TK3 */
    #define TAG_SIZE           128 /* 128-bit authentication tag */

#elif SKINNY_AEAD_MEMBER == 3
    #define TWEAKEY_STATE_SIZE 384 /* TK3 */
    #define TAG_SIZE            64 /* 64-bit authentication tag  */

#elif SKINNY_AEAD_MEMBER == 4
    #define TWEAKEY_STATE_SIZE 384 /* TK3 */
    #define TAG_SIZE            64 /* 64-bit authentication tag  */

#elif SKINNY_AEAD_MEMBER == 5
    #define TWEAKEY_STATE_SIZE 256 /* TK2 */
    #define TAG_SIZE           128 /* 128-bit authentication tag */

#elif SKINNY_AEAD_MEMBER == 6
    #define TWEAKEY_STATE_SIZE 256 /* TK2 */
    #define TAG_SIZE            64 /* 64-bit authentication tag  */

#else
    #error "Not implemented."
#endif




/* Helper functions */

void printHex(const char* s, const uint8_t* data, size_t len)
{
    printf("%s: ", s);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

/* Get one bit from a byte array */
uint8_t getBit(const uint8_t* array, uint32_t bitNumber)
{
    return (array[bitNumber / 8] >> (7 - (bitNumber % 8))) & 0x01;
}

/* Get one bit from a 32-bit int array */
uint8_t getBitFromWordArray(const uint32_t* array, uint32_t bitNumber)
{
    return getBit((uint8_t*)array, bitNumber);
}

/* Set a specific bit in a byte array to a given value */
void setBit(uint8_t* bytes, uint32_t bitNumber, uint8_t val)
{
    bytes[bitNumber / 8] = (bytes[bitNumber >> 3]
                            & ~(1 << (7 - (bitNumber % 8)))) | (val << (7 - (bitNumber % 8)));
}

/* Set a specific bit in a byte array to a given value */
void setBitInWordArray(uint32_t* array, uint32_t bitNumber, uint8_t val)
{
    setBit((uint8_t*)array, bitNumber, val);
}

void zeroTrailingBits(uint8_t* data, size_t bitLength)
{
    size_t byteLength = numBytes(bitLength);
    for (size_t i = bitLength; i < byteLength * 8; i++) {
        setBit(data, i, 0);
    }
}

uint8_t parity(uint32_t* data, size_t len)
{
    uint32_t x = data[0];

    for (size_t i = 1; i < len; i++) {
        x ^= data[i];
    }

    /* Compute parity of x using code from Section 5-2 of
     * H.S. Warren, *Hacker's Delight*, Pearson Education, 2003.
     * http://www.hackersdelight.org/hdcodetxt/parity.c.txt
     */
    uint32_t y = x ^ (x >> 1);
    y ^= (y >> 2);
    y ^= (y >> 4);
    y ^= (y >> 8);
    y ^= (y >> 16);
    return y & 1;
}

uint32_t numBytes(uint32_t numBits)
{
    return (numBits == 0) ? 0 : ((numBits - 1) / 8 + 1);
}

void xor_array(uint32_t* out, const uint32_t * in1, const uint32_t * in2, uint32_t length)
{
    for (uint32_t i = 0; i < length; i++) {
        out[i] = in1[i] ^ in2[i];
    }
}
void xor_three(uint32_t* output, const uint32_t* in1, const uint32_t* in2, const uint32_t* in3, size_t lenBytes)
{
    uint8_t* out = (uint8_t*)output;
    const uint8_t* i1 = (uint8_t*)in1;
    const uint8_t* i2 = (uint8_t*)in2;
    const uint8_t* i3 = (uint8_t*)in3;

    size_t wholeWords = lenBytes/sizeof(uint32_t);
    for(size_t i = 0; i < wholeWords; i++) {
        output[i] = in1[i] ^ in2[i] ^ in3[i];
    }
    for(size_t i = wholeWords*sizeof(uint32_t); i < lenBytes; i++) {
        out[i] = i1[i] ^ i2[i] ^ i3[i]; 
    }
}


#if 0
/* Matrix multiplication that works bitwise. Simpler, but much slower than the
 * word-wise implementation below. */
void matrix_mul(
    uint32_t* output,
    const uint32_t* state,
    const uint32_t* matrix,
    const paramset_t* params)
{
    // Use temp to correctly handle the case when state = output
    uint8_t prod;
    uint32_t temp[LOWMC_MAX_WORDS]; 
    temp[params->stateSizeWords-1] = 0;

    for (uint32_t i = 0; i < params->stateSizeBits; i++) {
        prod = 0;
        for (uint32_t j = 0; j < params->stateSizeBits; j++) {
            size_t index = i * params->stateSizeWords*WORD_SIZE_BITS + j;            
            prod ^= (getBitFromWordArray(state,j) & getBitFromWordArray(matrix, index));
        }
        setBit((uint8_t*)temp, i, prod);
    }
    memcpy((uint8_t*)output, (uint8_t*)temp, params->stateSizeWords * sizeof(uint32_t));
}
#else
static uint8_t parity32(uint32_t x)
{
    /* Compute parity of x using code from Section 5-2 of
     * H.S. Warren, *Hacker's Delight*, Pearson Education, 2003.
     * http://www.hackersdelight.org/hdcodetxt/parity.c.txt
     */
    uint32_t y = x ^ (x >> 1);
    y ^= (y >> 2);
    y ^= (y >> 4);
    y ^= (y >> 8);
    y ^= (y >> 16);
    return y & 1;
}

void matrix_mul(
    uint32_t* output,
    const uint32_t* state,
    const uint32_t* matrix,
    const paramset_t* params)
{
    // Use temp to correctly handle the case when state = output
    uint32_t prod;
    uint32_t temp[LOWMC_MAX_WORDS];
    temp[params->stateSizeWords-1] = 0;

    uint32_t wholeWords = params->stateSizeBits/WORD_SIZE_BITS;
    for (uint32_t i = 0; i < params->stateSizeBits; i++) {
        prod = 0;
        for (uint32_t j = 0; j < wholeWords; j++) {
            size_t index = i * params->stateSizeWords + j;
            prod ^= (state[j] & matrix[index]);
        }
        for(uint32_t j = wholeWords*WORD_SIZE_BITS; j < params->stateSizeBits; j++) {
            size_t index = i * params->stateSizeWords*WORD_SIZE_BITS + j;
            uint8_t bit = (getBitFromWordArray(state,j) & getBitFromWordArray(matrix, index));
            prod ^= bit;
        }

        setBit((uint8_t*)temp, i, parity32(prod));
    }
    memcpy((uint8_t*)output, (uint8_t*)temp, params->stateSizeWords * sizeof(uint32_t));
}
#endif

static void substitution(uint32_t* state, paramset_t* params)
{
    for (uint32_t i = 0; i < params->numSboxes * 3; i += 3) {
        uint8_t a = getBitFromWordArray(state, i + 2);
        uint8_t b = getBitFromWordArray(state, i + 1);
        uint8_t c = getBitFromWordArray(state, i);

        setBitInWordArray(state, i + 2, a ^ (b & c));
        setBitInWordArray(state, i + 1, a ^ b ^ (a & c));
        setBitInWordArray(state, i, a ^ b ^ c ^ (a & b));
    }
}

/*****************************
*                            *
*                            *
*      SKINNY FUNTIONS       *
*                            *
*                            *
*****************************/

/*******************************************************************************
** Cipher-dependent functions
*******************************************************************************/

/*
** Modify the key part in the tweakey state
*/
static void set_key_in_tweakey(uint8_t *tweakey, const uint8_t *key) {

    if(SKINNY_AEAD_MEMBER == 1)      memcpy(tweakey+32, key, 16); /* 128-bit key */
    else if(SKINNY_AEAD_MEMBER == 2) memcpy(tweakey+32, key, 16); /* 128-bit key */
    else if(SKINNY_AEAD_MEMBER == 3) memcpy(tweakey+32, key, 16); /* 128-bit key */
    else if(SKINNY_AEAD_MEMBER == 4) memcpy(tweakey+32, key, 16); /* 128-bit key */
    else if(SKINNY_AEAD_MEMBER == 5) memcpy(tweakey+16, key, 16); /* 128-bit key */
    else if(SKINNY_AEAD_MEMBER == 6) memcpy(tweakey+16, key, 16); /* 128-bit key */
}

/*
** Modify the nonce part in the tweakey state
*/
static void set_nonce_in_tweakey(uint8_t *tweakey, const uint8_t *nonce) {

    if(SKINNY_AEAD_MEMBER == 1)      memcpy(tweakey+16, nonce, 16); /* 128-bit nonces */
    else if(SKINNY_AEAD_MEMBER == 2) memcpy(tweakey+16, nonce, 12); /*  96-bit nonces */
    else if(SKINNY_AEAD_MEMBER == 3) memcpy(tweakey+16, nonce, 16); /* 128-bit nonces */
    else if(SKINNY_AEAD_MEMBER == 4) memcpy(tweakey+16, nonce, 12); /*  96-bit nonces */
    else if(SKINNY_AEAD_MEMBER == 5) memcpy(tweakey+4,  nonce, 12); /*  96-bit nonces */
    else if(SKINNY_AEAD_MEMBER == 6) memcpy(tweakey+4,  nonce, 12); /*  96-bit nonces */

}

/*
** Modify the stage value in the tweakey state
*/
static void set_stage_in_tweakey(uint8_t *tweakey, const uint8_t value) {

    if(SKINNY_AEAD_MEMBER == 1)      tweakey[15] = CST_NONCE_128 | CST_TAG_128 | value;
    else if(SKINNY_AEAD_MEMBER == 2) tweakey[15] = CST_NONCE_96  | CST_TAG_128 | value;
    else if(SKINNY_AEAD_MEMBER == 3) tweakey[15] = CST_NONCE_128 | CST_TAG_64  | value;
    else if(SKINNY_AEAD_MEMBER == 4) tweakey[15] = CST_NONCE_96  | CST_TAG_64  | value;
    else if(SKINNY_AEAD_MEMBER == 5) tweakey[3]  = CST_NONCE_96  | CST_TAG_128 | value;
    else if(SKINNY_AEAD_MEMBER == 6) tweakey[3]  = CST_NONCE_96  | CST_TAG_64  | value;

}

/*
** LFSR used as block counter
*/
static uint64_t lfsr(const uint64_t counter) {
    
    /* x^64 + x^4 + x^3 + x + 1 */
    if(SKINNY_AEAD_MEMBER == 1)      return (counter<<1) ^ (((counter>>63)&1)?0x1b:0);
    else if(SKINNY_AEAD_MEMBER == 2) return (counter<<1) ^ (((counter>>63)&1)?0x1b:0);
    else if(SKINNY_AEAD_MEMBER == 3) return (counter<<1) ^ (((counter>>63)&1)?0x1b:0);
    else if(SKINNY_AEAD_MEMBER == 4) return (counter<<1) ^ (((counter>>63)&1)?0x1b:0);

    /* x^24 + x^4 + x^3 + x + 1 */
    else if(SKINNY_AEAD_MEMBER == 5) return (counter<<1) ^ (((counter>>23)&1)?0x1b:0);
    else if(SKINNY_AEAD_MEMBER == 6) return (counter<<1) ^ (((counter>>23)&1)?0x1b:0);

}

/*
** Modify the block number in the tweakey state
*/
static void set_block_number_in_tweakey(uint8_t *tweakey, const uint64_t block_no) {

    if(SKINNY_AEAD_MEMBER == 1) {
        for (int i=0; i<8/*15*/; ++i) {
            tweakey[0+i] = (block_no >> (8*i)) & 0xff;
        }/*i*/

    } else if(SKINNY_AEAD_MEMBER == 2) {
        for (int i=0; i<8/*15*/; ++i) {
            tweakey[0+i] = (block_no >> (8*i)) & 0xff;
        }/*i*/

    } else if(SKINNY_AEAD_MEMBER == 3) {
        for (int i=0; i<8/*15*/; ++i) {
            tweakey[0+i] = (block_no >> (8*i)) & 0xff;
        }/*i*/

    } else if(SKINNY_AEAD_MEMBER == 4) {
        for (int i=0; i<8/*15*/; ++i) {
            tweakey[0+i] = (block_no >> (8*i)) & 0xff;
        }/*i*/

    } else if(SKINNY_AEAD_MEMBER == 5) {
        tweakey[0] = (block_no >> (8*0)) & 0xff;
        tweakey[1] = (block_no >> (8*1)) & 0xff;
        tweakey[2] = (block_no >> (8*2)) & 0xff;

    } else if(SKINNY_AEAD_MEMBER == 6) {
        tweakey[0] = (block_no >> (8*0)) & 0xff;
        tweakey[1] = (block_no >> (8*1)) & 0xff;
        tweakey[2] = (block_no >> (8*2)) & 0xff;

    }

}


// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state
static void AddKey(uint8_t state[4][4], uint8_t keyCells[3][4][4], int ver) {
    int i, j, k;
    uint8_t pos;
    uint8_t keyCells_tmp[3][4][4];
    //uint8_t aux;

    // apply the subtweakey to the internal state
    for(i = 0; i <= 1; i++) {
        for(j = 0; j < 4; j++) {
            state[i][j] ^= keyCells[0][i][j];
            if (2*versions[ver][0]==versions[ver][1]) state[i][j] ^= keyCells[1][i][j];
            else if (3*versions[ver][0]==versions[ver][1]) state[i][j] ^= keyCells[1][i][j] ^ keyCells[2][i][j];
        }
    }

    // update the subtweakey states with the permutation
    for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++) {
        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                //application of the TWEAKEY permutation
                pos=TWEAKEY_P[j+4*i];
                keyCells_tmp[k][i][j]=keyCells[k][pos>>2][pos&0x3];
            }
        }
    }

    // update the subtweakey states with the LFSRs
    for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++) {
        for(i = 0; i <= 1; i++) {
            for(j = 0; j < 4; j++) {
                //application of LFSRs for TK updates
                if (k==1) {
                    if (versions[ver][0]==64)
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xE)^((keyCells_tmp[k][i][j]>>3)&0x1)^((keyCells_tmp[k][i][j]>>2)&0x1);
                    else
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xFE)^((keyCells_tmp[k][i][j]>>7)&0x01)^((keyCells_tmp[k][i][j]>>5)&0x01);

                } else if (k==2) {
                    if (versions[ver][0]==64)
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7)^((keyCells_tmp[k][i][j])&0x8)^((keyCells_tmp[k][i][j]<<3)&0x8);
                    else
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7F)^((keyCells_tmp[k][i][j]<<7)&0x80)^((keyCells_tmp[k][i][j]<<1)&0x80);
                }
            }
        }
    }

    for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++) {
        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                keyCells[k][i][j]=keyCells_tmp[k][i][j];
            }
        }
    }
}

// Apply the constants: using a LFSR counter on 6 bits, we XOR the 6 bits to the first 6 bits of the internal state
void AddConstants(uint8_t state[4][4], int r) {
    state[0][0] ^= (RC[r] & 0xf);
    state[1][0] ^= ((RC[r]>>4) & 0x3);
    state[2][0] ^= 0x2;
}

// apply the 4-bit Sbox
static void SubCell4(uint8_t state[4][4]) {
    int i,j;
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            state[i][j] = sbox_4[state[i][j]];
        }
    }
}


/* THIS FUNCTION WORKS EACH BIT BY APPLYING A MASK TO THE BYTE */

static uint8_t skinny_byte_update(uint8_t x, int index, int player){
    (void) player;
    (void) index;
    uint8_t x_0,x_1,x_2,x_3,x_4,x_5,x_6,x_7,x2;

    /* Two S-boxes of 4 bits are applyed to the uint8_t */

    /* S-box 1 */
    //x_0 = (x & 1);
    x_1 = (x & 2);
    x_2 = (x & 4);
    x_3 = (x & 8);

    x_0 = (x_3 >> 3) ^ (x_2 >> 2) ^ (x_1 >> 1) ^ ((x_3 >> 3) & (x_2 >> 2));
    
    /* S-box 2 */
    //x_4 = (x & 16);
    x_5 = (x & 32);
    x_6 = (x & 64);
    x_7 = (x & 128);

    x_4 = (x_7 >> 3) ^ (x_6 >> 2) ^ (x_5 >> 1) ^ ((x_7 >> 3) & (x_6 >> 2));

    // Bit permutation
    x2  = (x_2 << 5) ^ (x_1 << 5) ^ (x_7 >> 2) ^ (x_6 >> 2) ^ (x_4 >> 1) ^ (x_0 << 2) ^ (x_3 >> 2) ^ (x_5 >> 5);
    
    return x2;

}



// apply the 8-bit Sbox
static void SubCell8(uint8_t state[4][4],int index) {
    (void) index;
    int i,j;
    for(i = 0; i < 4; i++) {
        for(j = 0; j <  4; j++) {
            state[i][j] = skinny_byte_update(state[i][j],index,0);
        }
    }
}

// Apply the ShiftRows function
static void ShiftRows(uint8_t state[4][4]) {
    int i, j, pos;

    uint8_t state_tmp[4][4];
    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            //application of the ShiftRows permutation
            pos=P[j+4*i];
            state_tmp[i][j]=state[pos>>2][pos&0x3];
        }
    }

    for(i = 0; i < 4; i++) {
        for(j = 0; j < 4; j++) {
            state[i][j]=state_tmp[i][j];
        }
    }
}

// Apply the linear diffusion matrix
//M =
//1 0 1 1
//1 0 0 0
//0 1 1 0
//1 0 1 0
static void MixColumn(uint8_t state[4][4]) {
    int j;
    uint8_t temp;

    for(j = 0; j < 4; j++) {
        state[1][j]^=state[2][j];
        state[2][j]^=state[0][j];
        state[3][j]^=state[2][j];

        temp=state[3][j];
        state[3][j]=state[2][j];
        state[2][j]=state[1][j];
        state[1][j]=state[0][j];
        state[0][j]=temp;
    }
}

/*static void XOR_STATE_TK(uint8_t state[4][4], uint8_t keyCells[3][4][4]){
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            state[i][j] ^= keyCells[2][i][j];
        }
    }
}*/

// encryption function of Skinny
void enc(const uint8_t* input, const uint8_t* tweakey, uint8_t* output, const int ver) {

    uint8_t state[4][4];
    uint8_t keyCells[3][4][4];
    int i;

    /* Set state and keyCells */
    memset(keyCells, 0, 48);
    for(i = 0; i < 16; i++) {
        if (versions[ver][0]==64) {
            if(i&1) {
                state[i>>2][i&0x3] = input[i>>1]&0xF;

                keyCells[0][i>>2][i&0x3] = tweakey[i>>1]&0xF;
                if (versions[ver][1]>=128) keyCells[1][i>>2][i&0x3] = tweakey[(i+16)>>1]&0xF;
                if (versions[ver][1]>=192) keyCells[2][i>>2][i&0x3] = tweakey[(i+32)>>1]&0xF;
            } else {
                state[i>>2][i&0x3] = (input[i>>1]>>4)&0xF;

                keyCells[0][i>>2][i&0x3] = (tweakey[i>>1]>>4)&0xF;
                if (versions[ver][1]>=128) keyCells[1][i>>2][i&0x3] = (tweakey[(i+16)>>1]>>4)&0xF;
                if (versions[ver][1]>=192) keyCells[2][i>>2][i&0x3] = (tweakey[(i+32)>>1]>>4)&0xF;
            }
        } else if (versions[ver][0]==128) {
            state[i>>2][i&0x3] = input[i]&0xFF;

            keyCells[0][i>>2][i&0x3] = tweakey[i]&0xFF;
            if (versions[ver][1]>=256) keyCells[1][i>>2][i&0x3] = tweakey[i+16]&0xFF;
            if (versions[ver][1]>=384) keyCells[2][i>>2][i&0x3] = tweakey[i+32]&0xFF;
        }
    }

    #ifdef DEBUG
        fprintf(fic,"ENC - initial state:                 ");display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
    #endif

    for(i = 0; i < 24; i++) {
        if (versions[ver][0]==64)
            SubCell4(state);
        else
            SubCell8(state,i);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after SubCell:      ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        AddConstants(state, i);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after AddConstants: ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        AddKey(state, keyCells, ver);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after AddKey:       ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        ShiftRows(state);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after ShiftRows:    ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        MixColumn(state);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after MixColumn:    ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
    }  //The last subtweakey should not be added
        
    #ifdef DEBUG
        fprintf(fic,"ENC - final state:                   ");display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
    #endif

    if (versions[ver][0]==64) {
        for(i = 0; i < 8; i++) {
            output[i] = ((state[(2*i)>>2][(2*i)&0x3] & 0xF) << 4) | (state[(2*i+1)>>2][(2*i+1)&0x3] & 0xF);
        }

    } else if (versions[ver][0]==128) {
        for(i = 0; i < 16; i++) {
            output[i] = state[i>>2][i&0x3] & 0xFF;
        }
    }
}

/*
** Encryption call to the TBC primitive used in the mode
*/
static void skinny_enc(const uint8_t* input, const uint8_t* tweakey, uint8_t* output) {

    if(SKINNY_AEAD_MEMBER == 1)      enc(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 2) enc(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 3) enc(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 4) enc(input, tweakey, output, 5); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 5) enc(input, tweakey, output, 4); /* SKINNY-128-256 (48 rounds) */
    else if(SKINNY_AEAD_MEMBER == 6) enc(input, tweakey, output, 4); /* SKINNY-128-256 (48 rounds) */
}

void skinny_encrypt(const uint8_t* plaintext,
                    uint8_t* output,
                    const uint8_t *key,
                    const uint8_t *nonce,
                    paramset_t* params)
{

    uint64_t i;
    uint64_t counter;
    uint8_t last_block[16];
    uint8_t zero_block[16];
    size_t m_len;

    if((sizeof(plaintext) % 16) == 0){
        m_len = sizeof(plaintext);
    }
    else {
        m_len = sizeof(plaintext) + (16-(sizeof(plaintext) % 16));
    }
    uint8_t tweakey[TWEAKEY_STATE_SIZE/8];
    uint8_t* ciphertext;
    uint32_t* tmp_aux;

    /* 
    ** Initialization
    */

    /* Fill the tweakey state with zeros */
    memset(tweakey, 0, sizeof(tweakey));

    /* Set the key in the tweakey state */
    set_key_in_tweakey(tweakey, key);

    /* Set the nonce in the tweakey state */
    set_nonce_in_tweakey(tweakey, nonce);

    /* Specify that we are now handling the plaintext */
    set_stage_in_tweakey(tweakey, CST_ENC_FULL);

    ciphertext = malloc(m_len*sizeof(uint8_t));


    /*
    ** Now process the plaintext
    */

    i = 0;
    counter = 1;
    while (16*(i+1) <= m_len) {
        /* Update the tweakey state with the current block number */
        set_block_number_in_tweakey(tweakey, counter);

        tmp_aux = (uint32_t*) plaintext+16*i;

        /* Encrypt the current block and produce the ciphertext block */
        skinny_enc(plaintext+16*i, tweakey, ciphertext);

        /* Update the counter */
        i++;
        counter = lfsr(counter);
    }

   /* Process incomplete block */
   if (m_len > 16*i) {

        tmp_aux = (uint32_t*) plaintext+16*i;

        /* Prepare the last padded block */
        memset(last_block, 0, 16);
        memcpy(last_block, plaintext+16*i, m_len-16*i);
        last_block[m_len-16*i] = 0x80;

        /* Create the zero block for encryption */
        memset(zero_block, 0, 16);

        set_stage_in_tweakey(tweakey, CST_ENC_PARTIAL);
        set_block_number_in_tweakey(tweakey, counter);

        /* Encrypt it */
        skinny_enc(zero_block, tweakey, ciphertext);

        tmp_aux = (uint32_t*) ciphertext;

   }

   tmp_aux = (uint32_t*) ciphertext;


   memcpy(output,ciphertext,params->stateSizeWords*(sizeof(uint32_t)));
}


void LowMCEnc(const uint32_t* plaintext, uint32_t* output, uint32_t* key, paramset_t* params)
{
    uint32_t roundKey[LOWMC_MAX_WORDS];

    if (plaintext != output) {
        /* output will hold the intermediate state */
        memcpy(output, plaintext, params->stateSizeWords*(sizeof(uint32_t)));
    }

    matrix_mul(roundKey, key, KMatrix(0, params), params);
    xor_array(output, output, roundKey, params->stateSizeWords);

    for (uint32_t r = 1; r <= params->numRounds; r++) {
        matrix_mul(roundKey, key, KMatrix(r, params), params);
        substitution(output, params);
        matrix_mul(output, output, LMatrix(r - 1, params), params);
        xor_array(output, output, RConstant(r - 1, params), params->stateSizeWords);
        xor_array(output, output, roundKey, params->stateSizeWords);
    }
}


bool createRandomTape(const uint8_t* seed, const uint8_t* salt, uint16_t roundNumber, uint16_t playerNumber,
                      uint8_t* tape, uint32_t tapeLengthBytes, paramset_t* params)
{
    HashInstance ctx;

    if (tapeLengthBytes < params->digestSizeBytes) {
        return false;
    }

    /* Hash the seed and a constant, store the result in tape. */
    HashInit(&ctx, params, HASH_PREFIX_2);
    HashUpdate(&ctx, seed, params->seedSizeBytes);
    HashFinal(&ctx);
    HashSqueeze(&ctx, tape, params->digestSizeBytes);

    /* Expand the hashed seed, salt, round and player indices, and output
     * length to create the tape. */
    HashInit(&ctx, params, HASH_PREFIX_NONE);
    HashUpdate(&ctx, tape, params->digestSizeBytes);        // Hash the hashed seed
    HashUpdate(&ctx, salt, params->saltSizeBytes);
    HashUpdateIntLE(&ctx, roundNumber);
    HashUpdateIntLE(&ctx, playerNumber);
    HashUpdateIntLE(&ctx, tapeLengthBytes);
    HashFinal(&ctx);
    HashSqueeze(&ctx, tape, tapeLengthBytes);

    return true;
}

void mpc_xor(uint32_t* state[3], uint32_t* in[3], uint32_t len, int players)
{
    for (uint8_t i = 0; i < players; i++) {
        xor_array(state[i], state[i], in[i], len);
    }
}

/* Compute the XOR of in with the first state vectors. */
void mpc_xor_constant(uint32_t* state[3], const uint32_t* in, uint32_t len)
{
    xor_array(state[0], state[0], in, len);
}

void mpc_xor_constant_verify(uint32_t* state[2], const uint32_t* in, uint32_t len, uint8_t challenge)
{
    /* During verify, where the first share is stored in state depends on the challenge */
    if (challenge == 0) {
        xor_array(state[0], state[0], in, len);
    }
    else if (challenge == 2) {
        xor_array(state[1], state[1], in, len);
    }
}


void Commit(const uint8_t* seed, const view_t view,
            uint8_t* hash, paramset_t* params)
{
    HashInstance ctx;

    /* Hash the seed, store result in `hash` */
    HashInit(&ctx, params, HASH_PREFIX_4);
    HashUpdate(&ctx, seed, params->seedSizeBytes);
    HashFinal(&ctx);
    HashSqueeze(&ctx, hash, params->digestSizeBytes);

    /* Compute H_0(H_4(seed), view) */
    HashInit(&ctx, params, HASH_PREFIX_0);
    HashUpdate(&ctx, hash, params->digestSizeBytes);
    HashUpdate(&ctx, (uint8_t*)view.inputShare, params->stateSizeBytes);
    HashUpdate(&ctx, (uint8_t*)view.communicatedBits, params->andSizeBytes);
    HashUpdate(&ctx, (uint8_t*)view.outputShare, params->stateSizeBytes);
    HashFinal(&ctx);
    HashSqueeze(&ctx, hash, params->digestSizeBytes);
}

/* This is the random "permuatation" function G for Unruh's transform */
void G(uint8_t viewNumber, const uint8_t* seed, view_t* view, uint8_t* output, paramset_t* params)
{
    HashInstance ctx;
    uint16_t outputBytes = params->seedSizeBytes + params->andSizeBytes;

    /* Hash the seed with H_5, store digest in output */
    HashInit(&ctx, params, HASH_PREFIX_5);
    HashUpdate(&ctx, seed, params->seedSizeBytes);
    HashFinal(&ctx);
    HashSqueeze(&ctx, output, params->digestSizeBytes);

    /* Hash H_5(seed), the view, and the length */
    HashInit(&ctx, params, HASH_PREFIX_NONE);
    HashUpdate(&ctx, output, params->digestSizeBytes);
    if (viewNumber == 2) {
        HashUpdate(&ctx, (uint8_t*)view->inputShare, params->stateSizeBytes);
        outputBytes += (uint16_t)params->stateSizeBytes;
    }
    HashUpdate(&ctx, view->communicatedBits, params->andSizeBytes);

    uint16_t outputBytesLE = toLittleEndian(outputBytes);
    HashUpdate(&ctx, (uint8_t*)&outputBytesLE, sizeof(uint16_t));
    HashFinal(&ctx);
    HashSqueeze(&ctx, output, outputBytes);
}

void setChallenge(uint8_t* challenge, size_t round, uint8_t trit)
{
    /* challenge must have length numBytes(numMPCRounds*2)
     * 0 <= index < numMPCRounds
     * trit must be in {0,1,2} */
    uint32_t roundU32 = (uint32_t)round;

    setBit(challenge, 2 * roundU32, trit & 1);
    setBit(challenge, 2 * roundU32 + 1, (trit >> 1) & 1);
}

uint8_t getChallenge(const uint8_t* challenge, size_t round)
{
    uint32_t roundU32 = (uint32_t)round;

    return (getBit(challenge, 2 * roundU32 + 1) << 1) | getBit(challenge, 2 * roundU32);
}

void H3(const uint32_t* circuitOutput, const uint32_t* plaintext, unsigned char** wots_sig_pk,
        uint8_t* challengeBits, const uint8_t* salt,
        const uint8_t* message, size_t messageByteLength,
        paramset_t* params)
{
    uint8_t* hash = malloc(params->digestSizeBytes);
    HashInstance ctx;

    /* Depending on the number of rounds, we might not set part of the last
     * byte, make sure it's always zero. */
    challengeBits[numBytes(params->numMPCRounds * 2) - 1] = 0;

    HashInit(&ctx, params, HASH_PREFIX_1);

    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        HashUpdate(&ctx, (uint8_t*)wots_sig_pk[i], HASH_SIZE);
    }
    /* Hash the public key */
    HashUpdate(&ctx, (uint8_t*)circuitOutput, params->stateSizeBytes);
    HashUpdate(&ctx, (uint8_t*)plaintext, params->stateSizeBytes);

    /* Hash the salt & message */
    HashUpdate(&ctx, salt, params->saltSizeBytes);
    HashUpdate(&ctx, message, messageByteLength);

    HashFinal(&ctx);
    HashSqueeze(&ctx, hash, params->digestSizeBytes);

    /* Convert hash to a packed string of values in {0,1,2} */
    size_t round = 0;
    while (1) {
        for (size_t i = 0; i < params->digestSizeBytes; i++) {
            uint8_t byte = hash[i];
            /* iterate over each pair of bits in the byte */
            for (int j = 0; j < 8; j += 2) {
                uint8_t bitPair = ((byte >> (6 - j)) & 0x03);
                if (bitPair < 3) {
                    setChallenge(challengeBits, round, bitPair);
                    round++;
                    if (round == params->numMPCRounds) {
                        goto done;
                    }
                }
            }
        }

        /* We need more bits; hash set hash = H_1(hash) */
        HashInit(&ctx, params, HASH_PREFIX_1);
        HashUpdate(&ctx, hash, params->digestSizeBytes);
        HashFinal(&ctx);
        HashSqueeze(&ctx, hash, params->digestSizeBytes);
    }

done:

    free(hash);
    return;
}


/* Caller must allocate the first parameter */
void prove(proof_t* proof, uint8_t challenge, seeds_t* seeds,
           view_t views[3], paramset_t* params, unsigned char* wots_signature)
{
    if (challenge == 0) {
        memcpy(proof->seed1, seeds->seed[0], params->seedSizeBytes);
        memcpy(proof->seed2, seeds->seed[1], params->seedSizeBytes);
    }
    else if (challenge == 1) {
        memcpy(proof->seed1, seeds->seed[1], params->seedSizeBytes);
        memcpy(proof->seed2, seeds->seed[2], params->seedSizeBytes);
    }
    else if (challenge == 2) {
        memcpy(proof->seed1, seeds->seed[2], params->seedSizeBytes);
        memcpy(proof->seed2, seeds->seed[0], params->seedSizeBytes);
    }
    else {
        assert(!"Invalid challenge");
    }

    if (challenge == 1 || challenge == 2) {
        memcpy(proof->inputShare, views[2].inputShare, params->stateSizeBytes);
    }
    memcpy(proof->communicatedBits, views[(challenge + 1) % 3].communicatedBits, params->andSizeBytes);

    memcpy(proof->wotsSignature, wots_signature, HASH_SIZE);

}

void mpc_AND_verify(uint8_t in1[2], uint8_t in2[2], uint8_t out[2],
                    randomTape_t* rand, view_t* view1, view_t* view2)
{
    uint8_t r[2] = { getBit(rand->tape[0], rand->pos), getBit(rand->tape[1], rand->pos) };

    out[0] = (in1[0] & in2[1]) ^ (in1[1] & in2[0]) ^ (in1[0] & in2[0]) ^ r[0] ^ r[1];
    setBit(view1->communicatedBits, rand->pos, out[0]);
    out[1] = getBit(view2->communicatedBits, rand->pos); 

    (rand->pos)++;
}

void mpc_substitution_verify(uint32_t* state[2], randomTape_t* rand, view_t* view1,
                             view_t* view2, paramset_t* params)
{
    for (uint32_t i = 0; i < params->numSboxes * 3; i += 3) {

        uint8_t a[2];
        uint8_t b[2];
        uint8_t c[2];

        for (uint8_t j = 0; j < 2; j++) {
            a[j] = getBitFromWordArray(state[j], i + 2);
            b[j] = getBitFromWordArray(state[j], i + 1);
            c[j] = getBitFromWordArray(state[j], i);
        }

        uint8_t ab[2];
        uint8_t bc[2];
        uint8_t ca[2];

        mpc_AND_verify(a, b, ab, rand, view1, view2);
        mpc_AND_verify(b, c, bc, rand, view1, view2);
        mpc_AND_verify(c, a, ca, rand, view1, view2);

        for (uint8_t j = 0; j < 2; j++) {
            setBitInWordArray(state[j], i + 2, a[j] ^ (bc[j]));
            setBitInWordArray(state[j], i + 1, a[j] ^ b[j] ^ (ca[j]));
            setBitInWordArray(state[j], i, a[j] ^ b[j] ^ c[j] ^ (ab[j]));
        }
    }
}

void mpc_matrix_mul(uint32_t* output[3], uint32_t* state[3], const uint32_t* matrix,
                    paramset_t* params, size_t players)
{
    for (uint32_t player = 0; player < players; player++) {
        matrix_mul(output[player], state[player], matrix, params);
    }
}

/*****************************************
*                                        *
*                                        *
*        SKINNY VERIFY FUNTIONS          *
*                                        *
*                                        *
*****************************************/


// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state
static void mpc_AddKey_verify(uint8_t state[2][4][4], uint8_t keyCells[2][3][4][4], int ver) {
    int i, j, k;
    uint8_t pos;
    uint8_t keyCells_tmp[3][4][4];
    //uint8_t aux;

    for(int player=0;player<2;player++){
        // apply the subtweakey to the internal state
        for(i = 0; i <= 1; i++) {
            for(j = 0; j < 4; j++) {
                state[player][i][j] ^= keyCells[player][0][i][j];
                if (2*versions[ver][0]==versions[ver][1]) state[player][i][j] ^= keyCells[player][1][i][j];
                else if (3*versions[ver][0]==versions[ver][1]) state[player][i][j] ^= keyCells[player][1][i][j] ^ keyCells[player][2][i][j];
                }
        }

        // update the subtweakey states with the permutation
        for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++) {
            for(i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    //application of the TWEAKEY permutation
                    pos=TWEAKEY_P[j+4*i];
                    keyCells_tmp[k][i][j]=keyCells[player][k][pos>>2][pos&0x3];
                }
            }
        }

        // update the subtweakey states with the LFSRs
        for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++) {
            for(i = 0; i <= 1; i++) {
                for(j = 0; j < 4; j++) {
                    //application of LFSRs for TK updates
                    if (k==1) {
                        if (versions[ver][0]==64)
                            keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xE)^((keyCells_tmp[k][i][j]>>3)&0x1)^((keyCells_tmp[k][i][j]>>2)&0x1);
                        else
                            keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xFE)^((keyCells_tmp[k][i][j]>>7)&0x01)^((keyCells_tmp[k][i][j]>>5)&0x01);

                    } else if (k==2) {
                        if (versions[ver][0]==64)
                            keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7)^((keyCells_tmp[k][i][j])&0x8)^((keyCells_tmp[k][i][j]<<3)&0x8);
                        else
                            keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7F)^((keyCells_tmp[k][i][j]<<7)&0x80)^((keyCells_tmp[k][i][j]<<1)&0x80);
                    }
                }
            }
        }

        for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++) {
            for(i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    keyCells[player][k][i][j]=keyCells_tmp[k][i][j];
                }
            }
        }
    }
}

// Apply the constants: using a LFSR counter on 6 bits, we XOR the 6 bits to the first 6 bits of the internal state
void mpc_AddConstants_verify(uint8_t state[2][4][4], int r) {
    for(int player=0;player<2;player++){
        state[player][0][0] ^= (RC[r] & 0xf);
        state[player][1][0] ^= ((RC[r]>>4) & 0x3);
        state[player][2][0] ^= 0x2;
    }
}

// apply the 4-bit Sbox
static void mpc_SubCell4_verify(uint8_t state[2][4][4]) {
    int i,j;
    for(int player=0;player<2;player++){
        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                state[player][i][j] = sbox_4[state[player][i][j]];
            }
        }
    }
}

void SKINNY_AND_verify(uint8_t in1[2], uint8_t in2[2], uint8_t out[2],
                    randomTape_t* rand, view_t views[2])
{
    uint8_t r[2] = { getBit(rand->tape[0], rand->pos), getBit(rand->tape[1], rand->pos) };

    
    out[0] = (in1[0] & in2[1]) ^ (in1[1] & in2[0]) ^ (in1[0] & in2[0]) ^ r[0] ^ r[1];
    setBit(views[0].communicatedBits, rand->pos, out[0]);

    out[1] = getBit(views[1].communicatedBits, rand->pos); 

    (rand->pos)++;
}

static void skinny_bytes_update_verify(uint8_t x[2], int index, int players, randomTape_t* rand, view_t views[2]){

    (void) index;
    uint8_t x_0[2],x_1[2],x_2[2],x_3[2],x_4[2],x_5[2],x_6[2],x_7[2];
    uint8_t a[2],b[2];
    uint8_t ab[2];

    /* Two S-boxes of 4 bits are applyed to the uint8_t */

    for(int i=0; i<players;i++){

        /* S-box 1 */

        x_1[i] = (x[i] & 2);
        x_2[i] = (x[i] & 4);
        x_3[i] = (x[i] & 8);

        /* S-box 2 */

        x_5[i] = (x[i] & 32);
        x_6[i] = (x[i] & 64);
        x_7[i] = (x[i] & 128);
    }

    /* S-box 1 */

    for(int i=0;i<players;i++){
        a[i] = (x_2[i] >> 2);
        b[i] = (x_3[i] >> 3);
    }

    
    SKINNY_AND_verify(a,b,ab,rand,views);
    

    for(int i=0;i<players;i++){
        x_0[i] = (x_3[i] >> 3) ^ (x_2[i] >> 2) ^ (x_1[i] >> 1) ^ ab[i];
    }

    /* S-box 2 */

    for(int i=0;i<players;i++){
        a[i] = (x_6[i] >> 6);
        b[i] = (x_7[i] >> 7);
    }

    SKINNY_AND_verify(a,b,ab,rand,views);


    for(int i=0;i<players;i++){
        x_4[i] = (x_7[i] >> 3) ^ (x_6[i] >> 2) ^ (x_5[i] >> 1) ^ (ab[i] << 4);
    }

    /* Bit permutation */

    for(int i=0;i<players;i++){
        x[i] = (x_2[i] << 5) ^ (x_1[i] << 5) ^ (x_7[i] >> 2) ^ (x_6[i] >> 2) ^ (x_4[i] >> 1) ^ (x_0[i] << 2) ^ (x_3[i] >> 2) ^ (x_5[i] >> 5);
    }
}

// apply the 8-bit Sbox
static void mpc_SubCell8_verify(uint8_t state[2][4][4],int index, randomTape_t* rand, view_t views[2]) {
    int i,j;
    uint8_t aux[2];
    for(i = 0; i < 4; i++) {
        for(j = 0; j <  4; j++) {
            aux[0] = state[0][i][j];
            aux[1] = state[1][i][j];
            skinny_bytes_update_verify(aux,index,2,rand,views);
            state[0][i][j] = aux[0];
            state[1][i][j] = aux[1];
        }
    }
}

// Apply the ShiftRows function
static void mpc_ShiftRows_verify(uint8_t state[2][4][4]) {
    int i, j, pos;

    uint8_t state_tmp[4][4];
    for(int player=0;player<2;player++){
        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                //application of the ShiftRows permutation
                pos=P[j+4*i];
                state_tmp[i][j]=state[player][pos>>2][pos&0x3];
            }
        }

        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                state[player][i][j]=state_tmp[i][j];
            }
        }
    }
}

// Apply the linear diffusion matrix
//M =
//1 0 1 1
//1 0 0 0
//0 1 1 0
//1 0 1 0
static void mpc_MixColumn_verify(uint8_t state[2][4][4]) {
    int j;
    uint8_t temp;
    for(int player=0;player<2;player++){
        for(j = 0; j < 4; j++) {
            state[player][1][j]^=state[player][2][j];
            state[player][2][j]^=state[player][0][j];
            state[player][3][j]^=state[player][2][j];

            temp=state[player][3][j];
            state[player][3][j]=state[player][2][j];
            state[player][2][j]=state[player][1][j];
            state[player][1][j]=state[player][0][j];
            state[player][0][j]=temp;
        }
    }
}


// encryption function of Skinny
void mpc_enc_verify(const uint8_t* input, const uint8_t tweakeys[2][48], uint8_t* output[2], const int ver, randomTape_t* rand, view_t views[2]) {

    uint8_t state[2][4][4];
    uint8_t keyCells[2][3][4][4];
    int i;

    /* Set state and keyCells */
    for(int player=0;player<2;player++){
        memset(keyCells[player], 0, 48);
        for(i = 0; i < 16; i++) {
            if (versions[ver][0]==64) {
                if(i&1) {
                    state[player][i>>2][i&0x3] = input[i>>1]&0xF;

                    keyCells[player][0][i>>2][i&0x3] = tweakeys[player][i>>1]&0xF;
                    if (versions[ver][1]>=128) keyCells[player][1][i>>2][i&0x3] = tweakeys[player][(i+16)>>1]&0xF;
                    if (versions[ver][1]>=192) keyCells[player][2][i>>2][i&0x3] = tweakeys[player][(i+32)>>1]&0xF;
                } else {
                    state[player][i>>2][i&0x3] = (input[i>>1]>>4)&0xF;

                    keyCells[player][0][i>>2][i&0x3] = (tweakeys[player][i>>1]>>4)&0xF;
                    if (versions[ver][1]>=128) keyCells[player][1][i>>2][i&0x3] = (tweakeys[player][(i+16)>>1]>>4)&0xF;
                    if (versions[ver][1]>=192) keyCells[player][2][i>>2][i&0x3] = (tweakeys[player][(i+32)>>1]>>4)&0xF;
                }
            } else if (versions[ver][0]==128) {
                state[player][i>>2][i&0x3] = input[i]&0xFF;

                keyCells[player][0][i>>2][i&0x3] = tweakeys[player][i]&0xFF;
                if (versions[ver][1]>=256) keyCells[player][1][i>>2][i&0x3] = tweakeys[player][i+16]&0xFF;
                if (versions[ver][1]>=384) keyCells[player][2][i>>2][i&0x3] = tweakeys[player][i+32]&0xFF;
            }
        }
    }
    #ifdef DEBUG
        fprintf(fic,"ENC - initial state:                 ");display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
    #endif
    
    for(i = 0; i < 24; i++) {
        
        if (versions[ver][0]==64)
            mpc_SubCell4_verify(state);
        else
            mpc_SubCell8_verify(state, i, rand, views);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after SubCell:      ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_AddConstants_verify(state, i);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after AddConstants: ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_AddKey_verify(state, keyCells, ver);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after AddKey:       ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_ShiftRows_verify(state);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after ShiftRows:    ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_MixColumn_verify(state);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after MixColumn:    ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
    }  //The last subtweakey should not be added
    fflush(stdout);
    #ifdef DEBUG
        fprintf(fic,"ENC - final state:                   ");display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
    #endif
    if (versions[ver][0]==64) {
        for(int player=0;player<2;player++){
            for(i = 0; i < 8; i++) {
                output[player][i] = ((state[player][(2*i)>>2][(2*i)&0x3] & 0xF) << 4) | (state[player][(2*i+1)>>2][(2*i+1)&0x3] & 0xF);
            }
        }

    } else if (versions[ver][0]==128) {
        for(int player=0;player<2;player++){
            for(i = 0; i < 16; i++) {
                output[player][i] = state[player][i>>2][i&0x3] & 0xFF;
            }
        }
    }
}

/*
** Encryption call to the TBC primitive used in the mode
*/
static void mpc_skinny_enc_verify(const uint8_t* input, const uint8_t tweakey[2][48], uint8_t* output[2], randomTape_t* rand, view_t views[2]) {

    if(SKINNY_AEAD_MEMBER == 1)      mpc_enc_verify(input, tweakey, output, 5, rand, views); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 2) mpc_enc_verify(input, tweakey, output, 5, rand, views); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 3) mpc_enc_verify(input, tweakey, output, 5, rand, views); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 4) mpc_enc_verify(input, tweakey, output, 5, rand, views); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 5) mpc_enc_verify(input, tweakey, output, 4, rand, views); /* SKINNY-128-256 (48 rounds) */
    else if(SKINNY_AEAD_MEMBER == 6) mpc_enc_verify(input, tweakey, output, 4, rand, views); /* SKINNY-128-256 (48 rounds) */
}


/*
** SKINNY-AEAD encryption function
*
* - PICNIC INPUT      | - SKINNY INPUT
* --------------------|---------------
* - plaintext         | - message
* - viewX.inputShare  | - key
* - nonce             | - nonce
* - viewX.outputShare | - ciphertext
*
*/
void mpc_skinny_encrypt_verify(const uint8_t *plaintext,
                        randomTape_t* rand,
                        view_t* view1, view_t* view2,
                        const uint8_t *nonce,
                        paramset_t* params)
{

    uint64_t i;

    view_t views[2] = {*view1,*view2};
    uint64_t counter;
    uint8_t last_block[16];
    uint8_t zero_block[16];
    size_t m_len;

    if((sizeof(plaintext) % 16) == 0){
        m_len = sizeof(plaintext);
    }
    else {
        m_len = sizeof(plaintext) + (16-(sizeof(plaintext) % 16));
    }
    uint8_t tweakeys[2][TWEAKEY_STATE_SIZE/8];
    uint8_t* ciphertexts[2];
    //uint32_t* tmp_aux;
    /* 
    ** Initialization
    */
    for(int player=0;player<2;player++){
        /* Fill the tweakey state with zeros */
        memset(tweakeys[player], 0, sizeof(tweakeys[player]));

        /* Set the key in the tweakey state */
        set_key_in_tweakey(tweakeys[player], (uint8_t*)views[player].inputShare);
        
        /* Set the nonce in the tweakey state */
        set_nonce_in_tweakey(tweakeys[player], nonce);

        /* Specify that we are now handling the plaintext */
        set_stage_in_tweakey(tweakeys[player], CST_ENC_FULL);

        ciphertexts[player] = malloc(m_len*sizeof(uint8_t));
    }
    
    
    /*
    ** Now process the plaintext
    */
    i = 0;
    counter = 1;
    while (16*(i+1) <= m_len) {
        for(int player=0;player<2;player++){
            /* Update the tweakey state with the current block number */
            set_block_number_in_tweakey(tweakeys[player], counter);
        }
        
        /* Encrypt the current block and produce the ciphertext block */
        mpc_skinny_enc_verify(plaintext+16*i, tweakeys, ciphertexts, rand, views);

        /* Update the counter */
        i++;
        counter = lfsr(counter);
    }
    
    /* Process incomplete block */
    if (m_len > 16*i) {

        /* Prepare the last padded block */
        memset(last_block, 0, 16);
        memcpy(last_block, plaintext+16*i, m_len-16*i);
        last_block[m_len-16*i] = 0x80;

        /* Create the zero block for encryption */
        memset(zero_block, 0, 16);

        for(int player=0;player<3;player++){

            set_stage_in_tweakey(tweakeys[player], CST_ENC_PARTIAL);
            set_block_number_in_tweakey(tweakeys[player], counter);

        }

        /* Encrypt it */
        mpc_skinny_enc_verify(zero_block, tweakeys, ciphertexts, rand, views);
    }

    for(int player=0;player < 2;player++){
        memcpy(views[player].outputShare, ciphertexts[player], params->stateSizeBytes);
    }
}

void mpc_LowMC_verify(view_t* view1, view_t* view2,
                      randomTape_t* tapes, uint32_t* tmp,
                      const uint32_t* plaintext, paramset_t* params, uint8_t challenge)
{
    uint32_t* state[2];
    uint32_t* keyShares[2];
    uint32_t* roundKey[2];

    memset(tmp, 0, 4 * params->stateSizeWords * sizeof(uint32_t));
    roundKey[0] = tmp;
    roundKey[1] = roundKey[0] + params->stateSizeWords;
    state[0] = roundKey[1] + params->stateSizeWords;
    state[1] = state[0] + params->stateSizeWords;

    mpc_xor_constant_verify(state, plaintext, params->stateSizeWords, challenge);

    keyShares[0] = view1->inputShare;
    keyShares[1] = view2->inputShare;

    mpc_matrix_mul(roundKey, keyShares, KMatrix(0, params), params, 2);
    mpc_xor(state, roundKey, params->stateSizeWords, 2);

    for (uint32_t r = 1; r <= params->numRounds; ++r) {
        mpc_matrix_mul(roundKey, keyShares, KMatrix(r, params), params, 2);
        mpc_substitution_verify(state, tapes, view1, view2, params);
        mpc_matrix_mul(state, state, LMatrix(r - 1, params), params, 2);
        mpc_xor_constant_verify(state, RConstant(r - 1, params), params->stateSizeWords, challenge);
        mpc_xor(state, roundKey, params->stateSizeWords, 2);
    }

    memcpy(view1->outputShare, state[0], params->stateSizeBytes);
    memcpy(view2->outputShare, state[1], params->stateSizeBytes);
}

void verifyProof(const proof_t* proof, view_t* view1, view_t* view2,
                 uint8_t challenge, uint8_t* salt, uint16_t roundNumber, uint8_t* tmp,
                 const uint32_t* plaintext, randomTape_t* tape, paramset_t* params, unsigned char* wots_signature)
{
    memcpy(view2->communicatedBits, proof->communicatedBits, params->andSizeBytes);
    tape->pos = 0;

    bool status = false;
    switch (challenge) {
    case 0:
        // in this case, both views' inputs are derivable from the input share
        status = createRandomTape(proof->seed1, salt, roundNumber, 0, tmp, params->stateSizeBytes + params->andSizeBytes, params);
        memcpy(view1->inputShare, tmp, params->stateSizeBytes);
        memcpy(tape->tape[0], tmp + params->stateSizeBytes, params->andSizeBytes);
        status = status && createRandomTape(proof->seed2, salt, roundNumber, 1, tmp, params->stateSizeBytes + params->andSizeBytes, params);
        if (!status) {
            break;
        }
        memcpy(view2->inputShare, tmp, params->stateSizeBytes);

        memcpy(tape->tape[1], tmp + params->stateSizeBytes, params->andSizeBytes);
        break;

    case 1:
        // in this case view2's input share was already given to us explicitly as
        // it is not computable from the seed. We just need to compute view1's input from
        // its seed
        status = createRandomTape(proof->seed1, salt, roundNumber, 1, tmp, params->stateSizeBytes + params->andSizeBytes, params);
        memcpy(view1->inputShare, tmp, params->stateSizeBytes);
        memcpy(tape->tape[0], tmp + params->stateSizeBytes, params->andSizeBytes);
        status = status && createRandomTape(proof->seed2, salt, roundNumber, 2, tape->tape[1], params->andSizeBytes, params);
        if (!status) {
            break;
        }
        memcpy(view2->inputShare, proof->inputShare, params->stateSizeBytes);
        break;

    case 2:
        // in this case view1's input share was already given to us explicitly as
        // it is not computable from the seed. We just need to compute view2's input from
        // its seed
        status = createRandomTape(proof->seed1, salt, roundNumber, 2, tape->tape[0], params->andSizeBytes, params);
        memcpy(view1->inputShare, proof->inputShare, params->stateSizeBytes);
        status = status && createRandomTape(proof->seed2, salt, roundNumber, 0, tmp, params->stateSizeBytes + params->andSizeBytes, params);
        if (!status) {
            break;
        }
        memcpy(view2->inputShare, tmp, params->stateSizeBytes);
        memcpy(tape->tape[1], tmp + params->stateSizeBytes, params->andSizeBytes);
        break;

    default:
        PRINT_DEBUG(("Invalid Challenge"));
        break;
    }
    memcpy(wots_signature,proof->wotsSignature,HASH_SIZE);

    if (!status) {
        PRINT_DEBUG(("Failed to generate random tapes, signature verification will fail (but signature may actually be valid)\n"));
    }

    /* When input shares are read from the tapes, and the length is not a whole number of bytes, the trailing bits must be zero */
    zeroTrailingBits((uint8_t*)view1->inputShare, params->stateSizeBits);
    zeroTrailingBits((uint8_t*)view2->inputShare, params->stateSizeBits);

    uint8_t nonce[] = "000102030405060708090A0B";

    mpc_skinny_encrypt_verify((uint8_t*) plaintext, tape,view1,view2,nonce,params);
    //mpc_LowMC_verify(view1, view2, tape, (uint32_t*)tmp, plaintext, params, challenge);
}

int verify(signature_t* sig, const uint32_t* pubKey, const uint32_t* plaintext,
           const uint8_t* message, size_t messageByteLength, paramset_t* params)
{
    commitments_t* as = allocateCommitments(params, 0);
    g_commitments_t* gs = allocateGCommitments(params);


    unsigned char** wots_sig = allocate_wots_signatures(params);
    unsigned char** wots_sig_pk = allocate_wots_signatures_pk(params);
    unsigned char* sk = malloc(HASH_SIZE);
    uint32_t lengths[5];

    unsigned char* aux_views[5][3];
    allocateAuxiliarViews(aux_views,params);


    uint32_t** viewOutputs = malloc(params->numMPCRounds * 3 * sizeof(uint32_t*));
    const proof_t* proofs = sig->proofs;

    const uint8_t* received_challengebits = sig->challengeBits;
    int status = EXIT_SUCCESS;
    uint8_t* computed_challengebits = NULL;
    uint32_t* view3Slab = NULL;

    uint8_t* tmp = malloc(MAX(6 * params->stateSizeBytes, params->stateSizeBytes + params->andSizeBytes));

    randomTape_t* tape = (randomTape_t*)malloc(sizeof(randomTape_t));

    allocateRandomTape(tape, params);

    view_t* view1s = malloc(params->numMPCRounds * sizeof(view_t));
    view_t* view2s = malloc(params->numMPCRounds * sizeof(view_t));

    /* Allocate a slab of memory for the 3rd view's output in each round */
    view3Slab = calloc(params->stateSizeBytes, params->numMPCRounds);
    uint32_t* view3Output = view3Slab;     /* pointer into the slab to the current 3rd view */

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        
        allocateView(&view1s[i], params);
        allocateView(&view2s[i], params);

        verifyProof(&proofs[i], &view1s[i], &view2s[i],
                    getChallenge(received_challengebits, i), sig->salt, i,
                    tmp, plaintext, tape, params,wots_sig[i]);

        // create ordered array of commitments with order computed based on the challenge
        // check commitments of the two opened views
        uint8_t challenge = getChallenge(received_challengebits, i);
        

        VIEW_OUTPUTS(i, challenge) = view1s[i].outputShare;
        VIEW_OUTPUTS(i, (challenge + 1) % 3) = view2s[i].outputShare;
        xor_three(view3Output, view1s[i].outputShare,  view2s[i].outputShare, pubKey, params->stateSizeBytes); 
        VIEW_OUTPUTS(i, (challenge + 2) % 3) = view3Output;

        memcpy(sk,wots_sig[i],HASH_SIZE);

        if(challenge == 0) {
            memcpy(aux_views[i % 5][0], view1s[i].outputShare, params->stateSizeBytes);
            memcpy(aux_views[i % 5][1], view2s[i].outputShare, params->stateSizeBytes);
            memcpy(aux_views[i % 5][2], view3Output, params->stateSizeBytes);
        }
        if(challenge == 1) {
            memcpy(aux_views[i % 5][0], view3Output, params->stateSizeBytes);
            memcpy(aux_views[i % 5][1], view1s[i].outputShare, params->stateSizeBytes);
            memcpy(aux_views[i % 5][2], view2s[i].outputShare, params->stateSizeBytes);
        }
        if(challenge == 2) {
            memcpy(aux_views[i % 5][0], view2s[i].outputShare, params->stateSizeBytes);
            memcpy(aux_views[i % 5][1], view3Output, params->stateSizeBytes);
            memcpy(aux_views[i % 5][2], view1s[i].outputShare, params->stateSizeBytes);
        }

        if((i % 5) == 4){
          get_lengths_verify(lengths, aux_views, params->stateSizeBytes);
        
          gen_wots_pk_from_sig(wots_sig_pk,wots_sig,lengths,i-4);

        }


        view3Output = (uint32_t*) ((uint8_t*)view3Output + params->stateSizeBytes);

    }

    computed_challengebits = malloc(numBytes(2 * params->numMPCRounds));

    H3(pubKey, plaintext, wots_sig_pk,
       computed_challengebits, sig->salt, message, messageByteLength, params);

    if (computed_challengebits != NULL &&
        memcmp(received_challengebits, computed_challengebits, numBytes(2 * params->numMPCRounds)) != 0) {
        PRINT_DEBUG(("Invalid signature. Did not verify\n"));
        status = EXIT_FAILURE;
    }

    free(computed_challengebits);
    free(view3Slab);

    freeCommitments(as);
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        freeView(&view1s[i]);
        freeView(&view2s[i]);
    }
    free(view1s);
    free(view2s);
    free(tmp);
    freeRandomTape(tape);
    free(tape);
    freeGCommitments(gs);
    free(viewOutputs);

    return status;
}

/*** Functions implementing Sign ***/

void mpc_AND(uint8_t in1[3], uint8_t in2[3], uint8_t out[3], randomTape_t* rand,
             view_t views[3])
{
    uint8_t r[3] = { getBit(rand->tape[0], rand->pos), getBit(rand->tape[1], rand->pos), getBit(rand->tape[2], rand->pos) };

    for (uint8_t i = 0; i < 3; i++) {
        out[i] = (in1[i] & in2[(i + 1) % 3]) ^ (in1[(i + 1) % 3] & in2[i])
                 ^ (in1[i] & in2[i]) ^ r[i] ^ r[(i + 1) % 3];

        setBit(views[i].communicatedBits, rand->pos, out[i]);
    }

    (rand->pos)++;
}

void mpc_substitution(uint32_t* state[3], randomTape_t* rand, view_t views[3],
                      paramset_t* params)
{
    uint8_t a[3];
    uint8_t b[3];
    uint8_t c[3];

    uint8_t ab[3];
    uint8_t bc[3];
    uint8_t ca[3];

    for (uint32_t i = 0; i < params->numSboxes * 3; i += 3) {

        for (uint8_t j = 0; j < 3; j++) {
            a[j] = getBitFromWordArray(state[j], i + 2);
            b[j] = getBitFromWordArray(state[j], i + 1);
            c[j] = getBitFromWordArray(state[j], i);
        }

        mpc_AND(a, b, ab, rand, views);
        mpc_AND(b, c, bc, rand, views);
        mpc_AND(c, a, ca, rand, views);

        for (uint8_t j = 0; j < 3; j++) {
            setBitInWordArray(state[j], i + 2, a[j] ^ (bc[j]));
            setBitInWordArray(state[j], i + 1, a[j] ^ b[j] ^ (ca[j]));
            setBitInWordArray(state[j], i, a[j] ^ b[j] ^ c[j] ^ (ab[j]));
        }
    }
}

#if 0   /* Debugging helper: reconstruct a secret shared value and print it */
void print_reconstruct(const char* label, uint32_t* s[3], size_t lengthBytes)
{
    uint32_t temp[LOWMC_MAX_WORDS] = {0};
    xor_three(temp, s[0], s[1], s[2], lengthBytes);
#if 0
    printf("\n");
    printHex("s0", (uint8_t*)s[0], lengthBytes); 
    printHex("s1", (uint8_t*)s[1], lengthBytes); 
    printHex("s2", (uint8_t*)s[2], lengthBytes); 
#endif
    printHex(label, (uint8_t*)temp, lengthBytes);
}
#endif


/**********************************
*                                 *
*                                 *
*          SKINNY FUNTIONS        *
*                                 *
*                                 *
***********************************/


// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state
static void mpc_AddKey(uint8_t state[3][4][4], uint8_t keyCells[3][3][4][4], int ver) {
    int i, j, k;
    uint8_t pos;
    uint8_t keyCells_tmp[3][4][4];
    //uint8_t aux;

    for(int player=0;player<3;player++){
        // apply the subtweakey to the internal state
        for(i = 0; i <= 1; i++) {
            for(j = 0; j < 4; j++) {
                state[player][i][j] ^= keyCells[player][0][i][j];
                if (2*versions[ver][0]==versions[ver][1]) state[player][i][j] ^= keyCells[player][1][i][j];
                else if (3*versions[ver][0]==versions[ver][1]) state[player][i][j] ^= keyCells[player][1][i][j] ^ keyCells[player][2][i][j];
            }
        }

        // update the subtweakey states with the permutation
        for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++) {
            for(i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    //application of the TWEAKEY permutation
                    pos=TWEAKEY_P[j+4*i];
                    keyCells_tmp[k][i][j]=keyCells[player][k][pos>>2][pos&0x3];
                }
            }
        }

        // update the subtweakey states with the LFSRs
        for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++) {
            for(i = 0; i <= 1; i++) {
                for(j = 0; j < 4; j++) {
                    //application of LFSRs for TK updates
                    if (k==1) {
                        if (versions[ver][0]==64)
                            keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xE)^((keyCells_tmp[k][i][j]>>3)&0x1)^((keyCells_tmp[k][i][j]>>2)&0x1);
                        else
                            keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xFE)^((keyCells_tmp[k][i][j]>>7)&0x01)^((keyCells_tmp[k][i][j]>>5)&0x01);

                    } else if (k==2) {
                        if (versions[ver][0]==64)
                            keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7)^((keyCells_tmp[k][i][j])&0x8)^((keyCells_tmp[k][i][j]<<3)&0x8);
                        else
                            keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7F)^((keyCells_tmp[k][i][j]<<7)&0x80)^((keyCells_tmp[k][i][j]<<1)&0x80);
                    }
                }
            }
        }

        for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++) {
            for(i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    keyCells[player][k][i][j]=keyCells_tmp[k][i][j];
                }
            }
        }
    }
}

// Apply the constants: using a LFSR counter on 6 bits, we XOR the 6 bits to the first 6 bits of the internal state
void mpc_AddConstants(uint8_t state[3][4][4], int r) {
    for(int player=0;player<3;player++){
        state[player][0][0] ^= (RC[r] & 0xf);
        state[player][1][0] ^= ((RC[r]>>4) & 0x3);
        state[player][2][0] ^= 0x2;
    }
}

// apply the 4-bit Sbox
static void mpc_SubCell4(uint8_t state[3][4][4]) {
    int i,j;
    for(int player=0;player<3;player++){
        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                state[player][i][j] = sbox_4[state[player][i][j]];
            }
        }
    }
}

static void SKINNY_AND(uint8_t in1[3], uint8_t in2[3], uint8_t out[3], randomTape_t* rand,
             view_t views[3])
{
    uint8_t r[3] = { getBit(rand->tape[0], rand->pos), getBit(rand->tape[1], rand->pos), getBit(rand->tape[2], rand->pos) };

    for (uint8_t i = 0; i < 3; i++) {
        out[i] = (in1[i] & in2[(i + 1) % 3]) ^ (in1[(i + 1) % 3] & in2[i])
                 ^ (in1[i] & in2[i]) ^ r[i] ^ r[(i + 1) % 3];

        setBit(views[i].communicatedBits, rand->pos, out[i]);
    }
    if(Debug == 0) nrAND += 1;

    (rand->pos)++;
}

static void skinny_bytes_update(uint8_t x[3], int index, int players, randomTape_t* rand, view_t views[3]){

    (void) index;
    uint8_t x_0[3],x_1[3],x_2[3],x_3[3],x_4[3],x_5[3],x_6[3],x_7[3];
    uint8_t a[3],b[3];
    uint8_t ab[3];

    /* Two S-boxes of 4 bits are applyed to the uint8_t */

    for(int i=0; i<players;i++){

        /* S-box 1 */

        x_1[i] = (x[i] & 2);
        x_2[i] = (x[i] & 4);
        x_3[i] = (x[i] & 8);

        /* S-box 2 */

        x_5[i] = (x[i] & 32);
        x_6[i] = (x[i] & 64);
        x_7[i] = (x[i] & 128);
    }

    /* S-box 1 */

    for(int i=0;i<players;i++){
        a[i] = (x_2[i] >> 2);
        b[i] = (x_3[i] >> 3);
    }
    
    SKINNY_AND(a,b,ab,rand,views);
    

    for(int i=0;i<players;i++){
        x_0[i] = (x_3[i] >> 3) ^ (x_2[i] >> 2) ^ (x_1[i] >> 1) ^ ab[i];
    }

    /* S-box 2 */

    for(int i=0;i<players;i++){
        a[i] = (x_6[i] >> 6);
        b[i] = (x_7[i] >> 7);
    }

    SKINNY_AND(a,b,ab,rand,views);

    for(int i=0;i<players;i++){
        x_4[i] = (x_7[i] >> 3) ^ (x_6[i] >> 2) ^ (x_5[i] >> 1) ^ (ab[i] << 4);
    }

    /* Bit permutation */

    for(int i=0;i<players;i++){
        x[i] = (x_2[i] << 5) ^ (x_1[i] << 5) ^ (x_7[i] >> 2) ^ (x_6[i] >> 2) ^ (x_4[i] >> 1) ^ (x_0[i] << 2) ^ (x_3[i] >> 2) ^ (x_5[i] >> 5);
    }
}

// apply the 8-bit Sbox
static void mpc_SubCell8(uint8_t state[3][4][4],int index, randomTape_t* rand, view_t views[3]) {
    (void) index;
    int i,j;
    uint8_t aux[3];
    for(i = 0; i < 4; i++) {
        for(j = 0; j <  4; j++) {
            aux[0] = state[0][i][j];
            aux[1] = state[1][i][j];
            aux[2] = state[2][i][j]; 
            skinny_bytes_update(aux,index,3,rand,views);
            state[0][i][j] = aux[0];
            state[1][i][j] = aux[1];
            state[2][i][j] = aux[2];
        }
    }
}

// Apply the ShiftRows function
static void mpc_ShiftRows(uint8_t state[3][4][4]) {
    int i, j, pos;

    uint8_t state_tmp[4][4];
    for(int player=0;player<3;player++){
        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                //application of the ShiftRows permutation
                pos=P[j+4*i];
                state_tmp[i][j]=state[player][pos>>2][pos&0x3];
            }
        }

        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                state[player][i][j]=state_tmp[i][j];
            }
        }
    }
}

// Apply the linear diffusion matrix
//M =
//1 0 1 1
//1 0 0 0
//0 1 1 0
//1 0 1 0
static void mpc_MixColumn(uint8_t state[3][4][4]) {
    int j;
    uint8_t temp;
    for(int player=0;player<3;player++){
        for(j = 0; j < 4; j++) {
            state[player][1][j]^=state[player][2][j];
            state[player][2][j]^=state[player][0][j];
            state[player][3][j]^=state[player][2][j];

            temp=state[player][3][j];
            state[player][3][j]=state[player][2][j];
            state[player][2][j]=state[player][1][j];
            state[player][1][j]=state[player][0][j];
            state[player][0][j]=temp;
        }
    }
}

/*static void mpc_XOR_STATE_TK(uint8_t state[3][4][4], uint8_t keyCells[3][3][4][4]){
    for(int player=0; player < 3; player++){
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                state[player][i][j] ^= keyCells[player][2][i][j];
            }
        }
    }
}*/

// encryption function of Skinny
void mpc_enc(const uint8_t* input, const uint8_t tweakeys[3][48], uint8_t* output[3], const int ver, randomTape_t* rand, view_t views[3]) {

    uint8_t state[3][4][4];
    uint8_t keyCells[3][3][4][4];
    int i;
    nrEnc += 1;

    /* Set state and keyCells */
    for(int player=0;player<3;player++){
        memset(keyCells[player], 0, 48);
        for(i = 0; i < 16; i++) {
            if (versions[ver][0]==64) {
                if(i&1) {
                    state[player][i>>2][i&0x3] = input[i>>1]&0xF;

                    keyCells[player][0][i>>2][i&0x3] = tweakeys[player][i>>1]&0xF;
                    if (versions[ver][1]>=128) keyCells[player][1][i>>2][i&0x3] = tweakeys[player][(i+16)>>1]&0xF;
                    if (versions[ver][1]>=192) keyCells[player][2][i>>2][i&0x3] = tweakeys[player][(i+32)>>1]&0xF;
                } else {
                    state[player][i>>2][i&0x3] = (input[i>>1]>>4)&0xF;

                    keyCells[player][0][i>>2][i&0x3] = (tweakeys[player][i>>1]>>4)&0xF;
                    if (versions[ver][1]>=128) keyCells[player][1][i>>2][i&0x3] = (tweakeys[player][(i+16)>>1]>>4)&0xF;
                    if (versions[ver][1]>=192) keyCells[player][2][i>>2][i&0x3] = (tweakeys[player][(i+32)>>1]>>4)&0xF;
                }
            } else if (versions[ver][0]==128) {
                state[player][i>>2][i&0x3] = input[i]&0xFF;

                keyCells[player][0][i>>2][i&0x3] = tweakeys[player][i]&0xFF;
                if (versions[ver][1]>=256) keyCells[player][1][i>>2][i&0x3] = tweakeys[player][i+16]&0xFF;
                if (versions[ver][1]>=384) keyCells[player][2][i>>2][i&0x3] = tweakeys[player][i+32]&0xFF;
            }
        }
    }
    #ifdef DEBUG
        fprintf(fic,"ENC - initial state:                 ");display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
    #endif

    for(i = 0; i < 24; i++) {
        
        if (versions[ver][0]==64)
            mpc_SubCell4(state);
        else 
            mpc_SubCell8(state,i,rand,views);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after SubCell:      ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_AddConstants(state, i);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after AddConstants: ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_AddKey(state, keyCells, ver);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after AddKey:       ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_ShiftRows(state);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after ShiftRows:    ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_MixColumn(state);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after MixColumn:    ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
    }  //The last subtweakey should not be added
    #ifdef DEBUG
        fprintf(fic,"ENC - final state:                   ");display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
    #endif
    if (versions[ver][0]==64) {
        for(int player=0;player<3;player++){
            for(i = 0; i < 8; i++) {
                output[player][i] = ((state[player][(2*i)>>2][(2*i)&0x3] & 0xF) << 4) | (state[player][(2*i+1)>>2][(2*i+1)&0x3] & 0xF);
            }
        }

    } else if (versions[ver][0]==128) {
        for(int player=0;player<3;player++){
            for(i = 0; i < 16; i++) {
                output[player][i] = state[player][i>>2][i&0x3] & 0xFF;
            }
        }
    }
}

/*
** Encryption call to the TBC primitive used in the mode
*/
static void mpc_skinny_enc(const uint8_t* input, const uint8_t tweakey[3][48], uint8_t* output[3], randomTape_t* rand, view_t views[3]) {

    if(SKINNY_AEAD_MEMBER == 1)      mpc_enc(input, tweakey, output, 5, rand, views); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 2) mpc_enc(input, tweakey, output, 5, rand, views); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 3) mpc_enc(input, tweakey, output, 5, rand, views); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 4) mpc_enc(input, tweakey, output, 5, rand, views); /* SKINNY-128-384 (56 rounds) */
    else if(SKINNY_AEAD_MEMBER == 5) mpc_enc(input, tweakey, output, 4, rand, views); /* SKINNY-128-256 (48 rounds) */
    else if(SKINNY_AEAD_MEMBER == 6) mpc_enc(input, tweakey, output, 4, rand, views); /* SKINNY-128-256 (48 rounds) */
}


/*
** SKINNY-AEAD encryption function
*
* - PICNIC INPUT      | - SKINNY INPUT
* --------------------|---------------
* - plaintext         | - message
* - viewX.inputShare  | - key
* - nonce             | - nonce
* - viewX.outputShare | - ciphertext
*
*/
void mpc_skinny_encrypt(const uint8_t *plaintext,
                        randomTape_t* rand,
                        view_t views[3],
                        const uint8_t *nonce,
                        paramset_t* params)
{

    uint64_t i;
    uint64_t counter;
    uint8_t last_block[16];
    uint8_t zero_block[16];
    size_t m_len;
    nrSKINNY +=1;

    if((sizeof(plaintext) % 16) == 0){
        m_len = sizeof(plaintext);
    }
    else {
        m_len = sizeof(plaintext) + (16-(sizeof(plaintext) % 16));
    }
    uint8_t tweakeys[3][TWEAKEY_STATE_SIZE/8];
    uint8_t* ciphertexts[3];
    //uint32_t* tmp_aux;
    /* 
    ** Initialization
    */
    for(int player=0;player<3;player++){
        /* Fill the tweakey state with zeros */
        memset(tweakeys[player], 0, sizeof(tweakeys[player]));

        /* Set the key in the tweakey state */
        set_key_in_tweakey(tweakeys[player], (uint8_t*)views[player].inputShare);
        
        /* Set the nonce in the tweakey state */
        set_nonce_in_tweakey(tweakeys[player], nonce);

        /* Specify that we are now handling the plaintext */
        set_stage_in_tweakey(tweakeys[player], CST_ENC_FULL);

        ciphertexts[player] = malloc(m_len*sizeof(uint8_t));
    }
    
    /*
    ** Now process the plaintext
    */

    i = 0;
    counter = 1;
    while (16*(i+1) <= m_len) {
        for(int player=0;player<3;player++){
            /* Update the tweakey state with the current block number */
            set_block_number_in_tweakey(tweakeys[player], counter);
        }
        
        /* Encrypt the current block and produce the ciphertext block */
        mpc_skinny_enc(plaintext+16*i, tweakeys, ciphertexts, rand, views);

        /* Update the counter */
        i++;
        counter = lfsr(counter);
    }

   /* Process incomplete block */
   if (m_len > 16*i) {

        /* Prepare the last padded block */
        memset(last_block, 0, 16);
        memcpy(last_block, plaintext+16*i, m_len-16*i);
        last_block[m_len-16*i] = 0x80;

        /* Create the zero block for encryption */
        memset(zero_block, 0, 16);

        for(int player=0;player<3;player++){

            set_stage_in_tweakey(tweakeys[player], CST_ENC_PARTIAL);
            set_block_number_in_tweakey(tweakeys[player], counter);

        }

        /* Encrypt it */
        mpc_skinny_enc(zero_block, tweakeys, ciphertexts, rand, views);
   }

   for(int player=0;player < 3;player++){
        memcpy(views[player].outputShare, ciphertexts[player], params->stateSizeBytes);
   }
}


void mpc_LowMC(randomTape_t* tapes, view_t views[3],
               const uint32_t* plaintext, uint32_t* slab, paramset_t* params)
{
    uint32_t* keyShares[3];
    uint32_t* state[3];
    uint32_t* roundKey[3];

    memset(slab, 0x00, 6 * params->stateSizeWords * sizeof(uint32_t));
    roundKey[0] = slab;
    roundKey[1] = slab + params->stateSizeWords;
    roundKey[2] = roundKey[1] + params->stateSizeWords;
    state[0] = roundKey[2] + params->stateSizeWords;
    state[1] = state[0] + params->stateSizeWords;
    state[2] = state[1] + params->stateSizeWords;

    for (int i = 0; i < 3; i++) {
        keyShares[i] = views[i].inputShare;
    }
    mpc_xor_constant(state, plaintext, params->stateSizeWords);
    mpc_matrix_mul(roundKey, keyShares, KMatrix(0, params), params, 3);
    mpc_xor(state, roundKey, params->stateSizeWords, 3);

    for (uint32_t r = 1; r <= params->numRounds; r++) {
        mpc_matrix_mul(roundKey, keyShares, KMatrix(r, params), params, 3);
        mpc_substitution(state, tapes, views, params);
        mpc_matrix_mul(state, state, LMatrix(r - 1, params), params, 3);
        mpc_xor_constant(state, RConstant(r - 1, params), params->stateSizeWords);
        mpc_xor(state, roundKey, params->stateSizeWords, 3);
    }

    for (int i = 0; i < 3; i++) {
        memcpy(views[i].outputShare, state[i], params->stateSizeBytes);
    }
}

#ifdef PICNIC_BUILD_DEFAULT_RNG
int random_bytes_default(uint8_t* buf, size_t len)
{

#if defined(__LINUX__)
    FILE* urandom = fopen("/dev/urandom", "r");
    if (urandom == NULL) {
        return -1;
    }

    if (fread(buf, sizeof(uint8_t), len, urandom) != len) {
        return -2;
    }
    fclose(urandom);

    return 0;

#elif defined(__WINDOWS__)
#ifndef ULONG_MAX
#define ULONG_MAX 0xFFFFFFFFULL
#endif
    if (len > ULONG_MAX) {
        return -3;
    }

    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return -4;
    }
    return 0;
#else
    #error "If neither __LINUX__ or __WINDOWS__ are defined, you'll have to implement the random number generator"
#endif

}
#endif /* PICNIC_BUILD_DEFAULT_RNG */

#ifdef SUPERCOP
#include "randombytes.h"
int random_bytes_supercop(uint8_t* buf, size_t len)
{
    randombytes(buf, len); /* returns void */
    return 0;
}
#endif /* SUPERCOP */

seeds_t* computeSeeds(uint32_t* privateKey, uint32_t*
                      publicKey, uint32_t* plaintext, const uint8_t* message, size_t messageByteLength, paramset_t* params)
{
    HashInstance ctx;
    seeds_t* allSeeds = allocateSeeds(params);


    HashInit(&ctx, params, HASH_PREFIX_NONE);
    HashUpdate(&ctx, (uint8_t*)privateKey, params->stateSizeBytes);
    HashUpdate(&ctx, message, messageByteLength);
    HashUpdate(&ctx, (uint8_t*)publicKey, params->stateSizeBytes);
    HashUpdate(&ctx, (uint8_t*)plaintext, params->stateSizeBytes);
    HashUpdateIntLE(&ctx, params->stateSizeBits);
    HashFinal(&ctx);

    // Derive the N*T seeds + 1 salt
    HashSqueeze(&ctx, allSeeds[0].seed[0], params->seedSizeBytes * (params->numMPCParties * params->numMPCRounds) + params->saltSizeBytes);

    return allSeeds;
}


int sign_picnic1(uint32_t* privateKey, uint32_t* pubKey, uint32_t* plaintext, const uint8_t* message,
                 size_t messageByteLength, signature_t* sig, paramset_t* params)
{
    bool status;

    /* Allocate views and commitments for all parallel iterations */
    view_t** views = allocateViews(params);
    commitments_t* as = allocateCommitments(params, 0);
    g_commitments_t* gs = allocateGCommitments(params);
    

    unsigned char** wots_sig = allocate_wots_signatures(params);
    unsigned char** wots_sig_pk = allocate_wots_signatures_pk(params);
    unsigned char** sks = allocateSks(params);
    unsigned char* sk = malloc(HASH_SIZE);
    uint32_t lengths[5];


    /* Compute seeds for all parallel iterations */
    seeds_t* seeds = computeSeeds(privateKey, pubKey, plaintext, message, messageByteLength, params);
    memcpy(sig->salt, seeds[params->numMPCRounds].iSeed, params->saltSizeBytes);

    //Allocate a random tape (re-used per parallel iteration), and a temporary buffer
    randomTape_t tape;

    allocateRandomTape(&tape, params);
    uint8_t* tmp = malloc( MAX(9 * params->stateSizeBytes, params->stateSizeBytes + params->andSizeBytes));

    for (uint32_t k = 0; k < params->numMPCRounds; k++) {
        Debug = k;
        // for first two players get all tape INCLUDING INPUT SHARE from seed
        for (int j = 0; j < 2; j++) {
            status = createRandomTape(seeds[k].seed[j], sig->salt, k, j, tmp, params->stateSizeBytes + params->andSizeBytes, params);

            if (!status) {
                fflush(stdout);
                PRINT_DEBUG(("createRandomTape failed \n"));
                return EXIT_FAILURE;
            }

            memcpy(views[k][j].inputShare, tmp, params->stateSizeBytes);
            zeroTrailingBits((uint8_t*)views[k][j].inputShare, params->stateSizeBits);
            memcpy(tape.tape[j], tmp + params->stateSizeBytes, params->andSizeBytes);
        }

        // Now set third party's wires. The random bits are from the seed, the input is
        // the XOR of other two inputs and the private key
        status = createRandomTape(seeds[k].seed[2], sig->salt, k, 2, tape.tape[2], params->andSizeBytes, params);
        if (!status) {
            PRINT_DEBUG(("createRandomTape failed \n"));
            return EXIT_FAILURE;
        }

        xor_three(views[k][2].inputShare, privateKey, views[k][0].inputShare, views[k][1].inputShare, params->stateSizeBytes);
        tape.pos = 0;

        uint8_t nonce[] = "000102030405060708090A0B";

        mpc_skinny_encrypt((uint8_t*)plaintext,&tape,views[k],nonce,params);

        uint32_t temp[LOWMC_MAX_WORDS] = {0};
        xor_three(temp, views[k][0].outputShare, views[k][1].outputShare, views[k][2].outputShare, params->stateSizeBytes);

        // compara 16 bytes!!

        if(memcmp(temp, pubKey, params->stateSizeBytes) != 0) {
            fflush(stdout);
            PRINT_DEBUG(("Simulation failed; output does not match public key (round = %u)\n", k));
            return EXIT_FAILURE;
        }

        //Committing
        Commit(seeds[k].seed[0], views[k][0], as[k].hashes[0], params);
        Commit(seeds[k].seed[1], views[k][1], as[k].hashes[1], params);
        Commit(seeds[k].seed[2], views[k][2], as[k].hashes[2], params);

        if (params->transform == TRANSFORM_UR) {
            G(0, seeds[k].seed[0], &views[k][0], gs[k].G[0], params);
            G(1, seeds[k].seed[1], &views[k][1], gs[k].G[1], params);
            G(2, seeds[k].seed[2], &views[k][2], gs[k].G[2], params);
            
            gen_ur_wots_sk(sk, as[k].hashes[0], as[k].hashes[1], as[k].hashes[2], gs[k].G[0], gs[k].G[1], gs[k].G[2], privateKey, params);
        }
        else{
            gen_fs_wots_sk(sk, as[k].hashes[0], as[k].hashes[1], as[k].hashes[2], privateKey, params);
        }

       /*Store secret key for round k */
        memcpy(sks[k],sk,HASH_SIZE);

        /* After we colllect 5 rounds we compute the WOTS+ signature. */
        if((k % 5) == 4){

          get_lengths(lengths, views, params->stateSizeBytes, k-4);

          gen_wots_sig(wots_sig, sks, lengths, k-4);
        
          gen_wots_pk_from_sig(wots_sig_pk,wots_sig,lengths,k-4);
        }

    }

    //Generating challenges
    uint32_t** viewOutputs = malloc(params->numMPCRounds * 3 * sizeof(uint32_t*));
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        for (size_t j = 0; j < 3; j++) {
            VIEW_OUTPUTS(i, j) = views[i][j].outputShare;
        }
    }

    H3(pubKey, plaintext, wots_sig_pk,
       sig->challengeBits, sig->salt, message, messageByteLength, params);

    //Packing Z
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        proof_t* proof = &sig->proofs[i];
        prove(proof, getChallenge(sig->challengeBits, i), &seeds[i],
              views[i], params, wots_sig[i]);
    }


#if 0   /* Self-test, verify the signature we just created */
    printf("\n-----------\n"); 
    int ret = verify(sig, pubKey, plaintext, message, messageByteLength, params);
    if(ret != EXIT_SUCCESS) {
        printf("Self-test of signature verification failed\n");
        exit(-1);
    }
    else {
        printf("Self-test succeeded\n");
    }
    printf("\n-----------\n"); 
#endif


    free(tmp);

    freeViews(views, params);
    freeCommitments(as);
    freeRandomTape(&tape);
    freeGCommitments(gs);
    free(viewOutputs);
    freeSeeds(seeds);

    return EXIT_SUCCESS;
}

/*** Serialization functions ***/

int serializeSignature(const signature_t* sig, uint8_t* sigBytes, size_t sigBytesLen, paramset_t* params)
{
    const proof_t* proofs = sig->proofs;
    const uint8_t* challengeBits = sig->challengeBits;

    /* Validate input buffer is large enough */
    size_t bytesRequired = numBytes(2 * params->numMPCRounds) + params->saltSizeBytes +
                           params->numMPCRounds * (2 * params->seedSizeBytes + params->stateSizeBytes + params->andSizeBytes + HASH_SIZE);

    if (sigBytesLen < bytesRequired) {
        return -1;
    }

    uint8_t* sigBytesBase = sigBytes;

    memcpy(sigBytes, challengeBits, numBytes(2 * params->numMPCRounds));
    sigBytes += numBytes(2 * params->numMPCRounds);

    memcpy(sigBytes, sig->salt, params->saltSizeBytes);
    sigBytes += params->saltSizeBytes;

    for (size_t i = 0; i < params->numMPCRounds; i++) {

        uint8_t challenge = getChallenge(challengeBits, i);

        memcpy(sigBytes, proofs[i].wotsSignature, HASH_SIZE);
        sigBytes += HASH_SIZE;

        memcpy(sigBytes, proofs[i].communicatedBits, params->andSizeBytes);
        sigBytes += params->andSizeBytes;

        memcpy(sigBytes, proofs[i].seed1, params->seedSizeBytes);
        sigBytes += params->seedSizeBytes;

        memcpy(sigBytes, proofs[i].seed2, params->seedSizeBytes);
        sigBytes += params->seedSizeBytes;

        if (challenge == 1 || challenge == 2) {
            memcpy(sigBytes, proofs[i].inputShare, params->stateSizeBytes);
            sigBytes += params->stateSizeBytes;
        }

    }

    return (int)(sigBytes - sigBytesBase);
}


static size_t computeInputShareSize(const uint8_t* challengeBits, size_t stateSizeBytes, paramset_t* params)
{
    /* When the FS transform is used, the input share is included in the proof
     * only when the challenge is 1 or 2.  When dersializing, to compute the
     * number of bytes expected, we must check how many challenge values are 1
     * or 2. The parameter stateSizeBytes is the size of an input share. */
    size_t inputShareSize = 0;

    for (size_t i = 0; i < params->numMPCRounds; i++) {
        uint8_t challenge = getChallenge(challengeBits, i);
        if (challenge == 1 || challenge == 2) {
            inputShareSize += stateSizeBytes;
        }
    }
    return inputShareSize;
}

static int isChallengeValid(uint8_t* challengeBits, paramset_t* params)
{
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        uint8_t challenge = getChallenge(challengeBits, i);
        if (challenge > 2) {
            return 0;
        }
    }
    return 1;
}

int arePaddingBitsZero(uint8_t* data, size_t bitLength)
{
    size_t byteLength = numBytes(bitLength); 
    for (size_t i = bitLength; i < byteLength * 8; i++) {
        uint8_t bit_i = getBit(data, i);
        if (bit_i != 0) {
            return 0;
        }
    }
    return 1;
}

int deserializeSignature(signature_t* sig, const uint8_t* sigBytes,
                         size_t sigBytesLen, paramset_t* params)
{
    proof_t* proofs = sig->proofs;
    uint8_t* challengeBits = sig->challengeBits;

    /* Validate input buffer is large enough */
    if (sigBytesLen < numBytes(2 * params->numMPCRounds)) {     /* ensure the input has at least the challenge */
        return EXIT_FAILURE;
    }

    size_t inputShareSize = computeInputShareSize(sigBytes, params->stateSizeBytes, params);
    size_t bytesExpected = numBytes(2 * params->numMPCRounds) + params->saltSizeBytes +
                           params->numMPCRounds * (2 * params->seedSizeBytes + params->andSizeBytes + HASH_SIZE) + inputShareSize;

    if (sigBytesLen < bytesExpected) {
        return EXIT_FAILURE;
    }

    memcpy(challengeBits, sigBytes, numBytes(2 * params->numMPCRounds));
    sigBytes += numBytes(2 * params->numMPCRounds);

    if (!isChallengeValid(challengeBits, params)) {
        return EXIT_FAILURE;
    }

    memcpy(sig->salt, sigBytes, params->saltSizeBytes);
    sigBytes += params->saltSizeBytes;

    for (size_t i = 0; i < params->numMPCRounds; i++) {

        uint8_t challenge = getChallenge(challengeBits, i);

        memcpy(proofs[i].wotsSignature, sigBytes, HASH_SIZE);
        sigBytes += HASH_SIZE;

        memcpy(proofs[i].communicatedBits, sigBytes, params->andSizeBytes);
        sigBytes += params->andSizeBytes;

        memcpy(proofs[i].seed1, sigBytes, params->seedSizeBytes);
        sigBytes += params->seedSizeBytes;

        memcpy(proofs[i].seed2, sigBytes, params->seedSizeBytes);
        sigBytes += params->seedSizeBytes;

        if (challenge == 1 || challenge == 2) {
            memcpy(proofs[i].inputShare, sigBytes, params->stateSizeBytes);
            sigBytes += params->stateSizeBytes;
            if(!arePaddingBitsZero((uint8_t*)proofs[i].inputShare, params->stateSizeBits)) {
                return EXIT_FAILURE;
            }
        }

    }

    return EXIT_SUCCESS;
}





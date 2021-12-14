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


#define MAX(a, b) ((a) > (b)) ? (a) : (b)

#define VIEW_OUTPUTS(i, j) viewOutputs[(i) * 3 + (j)]

#define TWEAKEY_STATE_SIZE 48 /* TK3                 */
#define DIGEST_SIZE        32 /* 256-bit outputs     */
#define RATE               16 /* 128-bit rate        */
#define CAPACITY           32 /* 256-bit capacity    */
#define SKINNY_F  skinny_F384 /* Underlying function */

int Debug=0;

// 8-bit Sbox
static const uint8_t sbox_8[256] = {0x65,0x4c,0x6a,0x42,0x4b,0x63,0x43,0x6b,0x55,0x75,0x5a,0x7a,0x53,0x73,0x5b,0x7b ,0x35,0x8c,0x3a,0x81,0x89,0x33,0x80,0x3b,0x95,0x25,0x98,0x2a,0x90,0x23,0x99,0x2b ,0xe5,0xcc,0xe8,0xc1,0xc9,0xe0,0xc0,0xe9,0xd5,0xf5,0xd8,0xf8,0xd0,0xf0,0xd9,0xf9 ,0xa5,0x1c,0xa8,0x12,0x1b,0xa0,0x13,0xa9,0x05,0xb5,0x0a,0xb8,0x03,0xb0,0x0b,0xb9 ,0x32,0x88,0x3c,0x85,0x8d,0x34,0x84,0x3d,0x91,0x22,0x9c,0x2c,0x94,0x24,0x9d,0x2d ,0x62,0x4a,0x6c,0x45,0x4d,0x64,0x44,0x6d,0x52,0x72,0x5c,0x7c,0x54,0x74,0x5d,0x7d ,0xa1,0x1a,0xac,0x15,0x1d,0xa4,0x14,0xad,0x02,0xb1,0x0c,0xbc,0x04,0xb4,0x0d,0xbd ,0xe1,0xc8,0xec,0xc5,0xcd,0xe4,0xc4,0xed,0xd1,0xf1,0xdc,0xfc,0xd4,0xf4,0xdd,0xfd ,0x36,0x8e,0x38,0x82,0x8b,0x30,0x83,0x39,0x96,0x26,0x9a,0x28,0x93,0x20,0x9b,0x29 ,0x66,0x4e,0x68,0x41,0x49,0x60,0x40,0x69,0x56,0x76,0x58,0x78,0x50,0x70,0x59,0x79 ,0xa6,0x1e,0xaa,0x11,0x19,0xa3,0x10,0xab,0x06,0xb6,0x08,0xba,0x00,0xb3,0x09,0xbb ,0xe6,0xce,0xea,0xc2,0xcb,0xe3,0xc3,0xeb,0xd6,0xf6,0xda,0xfa,0xd3,0xf3,0xdb,0xfb ,0x31,0x8a,0x3e,0x86,0x8f,0x37,0x87,0x3f,0x92,0x21,0x9e,0x2e,0x97,0x27,0x9f,0x2f ,0x61,0x48,0x6e,0x46,0x4f,0x67,0x47,0x6f,0x51,0x71,0x5e,0x7e,0x57,0x77,0x5f,0x7f ,0xa2,0x18,0xae,0x16,0x1f,0xa7,0x17,0xaf,0x01,0xb2,0x0e,0xbe,0x07,0xb7,0x0f,0xbf ,0xe2,0xca,0xee,0xc6,0xcf,0xe7,0xc7,0xef,0xd2,0xf2,0xde,0xfe,0xd7,0xf7,0xdf,0xff};
//static const uint8_t sbox_8_inv[256] = {0xac,0xe8,0x68,0x3c,0x6c,0x38,0xa8,0xec,0xaa,0xae,0x3a,0x3e,0x6a,0x6e,0xea,0xee ,0xa6,0xa3,0x33,0x36,0x66,0x63,0xe3,0xe6,0xe1,0xa4,0x61,0x34,0x31,0x64,0xa1,0xe4 ,0x8d,0xc9,0x49,0x1d,0x4d,0x19,0x89,0xcd,0x8b,0x8f,0x1b,0x1f,0x4b,0x4f,0xcb,0xcf ,0x85,0xc0,0x40,0x15,0x45,0x10,0x80,0xc5,0x82,0x87,0x12,0x17,0x42,0x47,0xc2,0xc7 ,0x96,0x93,0x03,0x06,0x56,0x53,0xd3,0xd6,0xd1,0x94,0x51,0x04,0x01,0x54,0x91,0xd4 ,0x9c,0xd8,0x58,0x0c,0x5c,0x08,0x98,0xdc,0x9a,0x9e,0x0a,0x0e,0x5a,0x5e,0xda,0xde ,0x95,0xd0,0x50,0x05,0x55,0x00,0x90,0xd5,0x92,0x97,0x02,0x07,0x52,0x57,0xd2,0xd7 ,0x9d,0xd9,0x59,0x0d,0x5d,0x09,0x99,0xdd,0x9b,0x9f,0x0b,0x0f,0x5b,0x5f,0xdb,0xdf ,0x16,0x13,0x83,0x86,0x46,0x43,0xc3,0xc6,0x41,0x14,0xc1,0x84,0x11,0x44,0x81,0xc4 ,0x1c,0x48,0xc8,0x8c,0x4c,0x18,0x88,0xcc,0x1a,0x1e,0x8a,0x8e,0x4a,0x4e,0xca,0xce ,0x35,0x60,0xe0,0xa5,0x65,0x30,0xa0,0xe5,0x32,0x37,0xa2,0xa7,0x62,0x67,0xe2,0xe7 ,0x3d,0x69,0xe9,0xad,0x6d,0x39,0xa9,0xed,0x3b,0x3f,0xab,0xaf,0x6b,0x6f,0xeb,0xef ,0x26,0x23,0xb3,0xb6,0x76,0x73,0xf3,0xf6,0x71,0x24,0xf1,0xb4,0x21,0x74,0xb1,0xf4 ,0x2c,0x78,0xf8,0xbc,0x7c,0x28,0xb8,0xfc,0x2a,0x2e,0xba,0xbe,0x7a,0x7e,0xfa,0xfe ,0x25,0x70,0xf0,0xb5,0x75,0x20,0xb0,0xf5,0x22,0x27,0xb2,0xb7,0x72,0x77,0xf2,0xf7 ,0x2d,0x79,0xf9,0xbd,0x7d,0x29,0xb9,0xfd,0x2b,0x2f,0xbb,0xbf,0x7b,0x7f,0xfb,0xff};

// ShiftAndSwitchRows permutation
static const uint8_t P[16] = {0,1,2,3,7,4,5,6,10,11,8,9,13,14,15,12};
//static const uint8_t P_inv[16] = {0,1,2,3,5,6,7,4,10,11,8,9,15,12,13,14};

// Tweakey permutation
static const uint8_t TWEAKEY_P[16] = {9,15,8,13,10,14,12,11,0,1,2,3,4,5,6,7};
//static const uint8_t TWEAKEY_P_inv[16] = {8,9,10,11,12,13,14,15,2,0,4,7,6,3,5,1};

// round constants
static const uint8_t RC[62] = {
        0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
        0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
        0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
        0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
        0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
        0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28,
        0x10, 0x20};


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

/*
** XOR an input block to another input block
*/
static void xor_values(uint8_t *v1, const uint8_t *v2, const int len) {
    for (int i=0; i<len; i++) {
        v1[i] ^= v2[i];
    }
}
/*
** XOR three input blocks
*/
static void mpc_xor_values(uint8_t *v1, const uint8_t *v2, const uint8_t *v3, const int len) {
    for (int i=0; i<len; i++) {
        v1[i] ^= v2[i] ^ v3[i];
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

// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state
static void AddKey(uint8_t state[4][4], uint8_t KeyCells[3][4][4]) {
    int i, j, k;
    uint8_t pos;

    uint8_t keyCells_tmp[3][4][4];

    // apply the subtweakey to the internal state
    for(i = 0; i <= 1; i++) {
        for(j = 0; j < 4; j++) {
            state[i][j] ^= KeyCells[0][i][j] ^ KeyCells[1][i][j] ^ KeyCells[2][i][j];
        }
    }

    // update the subtweakey states with the permutation
    for(k = 0; k < 3; k++) {
        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                //application of the TWEAKEY permutation
                pos=TWEAKEY_P[j+4*i];
                keyCells_tmp[k][i][j]=KeyCells[k][pos>>2][pos&0x3];
            }
        }
    }

    // update the subtweakey states with the LFSRs
    for(k = 0; k < 3; k++) {
        for(i = 0; i <= 1; i++) {
            for(j = 0; j < 4; j++) {
                //application of LFSRs for TK updates
                if (k==1) {
                    keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xFE)^((keyCells_tmp[k][i][j]>>7)&0x01)^((keyCells_tmp[k][i][j]>>5)&0x01);
                } else if (k==2) {
                    keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7F)^((keyCells_tmp[k][i][j]<<7)&0x80)^((keyCells_tmp[k][i][j]<<1)&0x80);
                }
            }
        }
    }

    for(k = 0; k < 3; k++) {
        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                KeyCells[k][i][j]=keyCells_tmp[k][i][j];
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


// apply the 8-bit Sbox
static void SubCell8(uint8_t state[4][4]) {
        int i,j;
        for(i = 0; i < 4; i++) {
            for(j = 0; j <  4; j++) {
                state[i][j] = sbox_8[state[i][j]];
            }
    }
}

// encryption function of Skinny
// {128,384, 56}; ver 5 -> SKINNY-128-384: 56 rounds 
void encript(const uint8_t* input, const uint8_t tweakey[48], uint8_t output[16]) {

    uint8_t state[4][4];
    uint8_t KeyCells[3][4][4];
    int i;

#ifdef DEBUG
    fic = fopen("SKINNY_TBC_detailed_TV.txt", "a");
#endif

    /* Set state and keyCells */

    memset(KeyCells, 0, 48);

    for(i = 0; i < 16; i++) {
        state[i>>2][i&0x3] = input[i]&0xFF;

        KeyCells[0][i>>2][i&0x3] = tweakey[i]&0xFF;
        KeyCells[2][i>>2][i&0x3] = tweakey[i+32]&0xFF;
    }

    #ifdef DEBUG
        fprintf(fic,"ENC - initial state:                 ");display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
    #endif

    for(i = 0; i < 56; i++) {

        SubCell8(state);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after SubCell:      ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        AddConstants(state, i);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after AddConstants: ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        AddKey(state, KeyCells);
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


        for(i = 0; i < 16; i++) {
            output[i] = state[i>>2][i&0x3] & 0xFF;
        }

#ifdef DEBUG
    fclose(fic);
#endif
}
static void F384(uint8_t state[48]) {

    uint8_t tweakey[48];
    uint8_t tmp_out[16];

    uint8_t tmp_in[16];
    memset(tmp_in, 0, sizeof(tmp_in));

    /* Initialization */

    memcpy(tweakey, state, 48);
    memset(tmp_out,0, 16);
    
    /*
        Call for the three players a enc() function with the initial input for each one 
    */

    /* First TBC call with input 0 */
    //tmp_ins[player][0] = 0; -> not needed as it is alredy 0
    encript(tmp_in, tweakey, tmp_out);
    memcpy(state, tmp_out, 16);
    
    /* Second TBC call with input 1 */
    tmp_in[0] = 1;
    encript(tmp_in, tweakey, tmp_out);
    memcpy(state+16, tmp_out, 16);
    

    /* Third TBC call with input 2 */
    tmp_in[0] = 2;
    encript(tmp_in, tweakey, tmp_out);
    memcpy(state+32, tmp_out, 16);
}

void SKINNYEnc(const uint32_t* plaintext, uint32_t* output, uint32_t* key, paramset_t* params){
    
    if (plaintext != output) {
        /* output will hold the intermediate state */
        memcpy(output, plaintext, params->stateSizeWords*(sizeof(uint32_t)));
    }

    uint8_t state[TWEAKEY_STATE_SIZE];
    uint8_t last_block[RATE];
    uint8_t last_block_key[RATE];

    uint8_t* pt_aux = (uint8_t*) plaintext; 
    uint8_t* key_aux = (uint8_t*) key;

    // número de bytes de input
    unsigned long long m_len = sizeof(plaintext)*4;

    /* Initialization */
    memset(state, 0, TWEAKEY_STATE_SIZE);
    state[RATE] = 0x80;

    /* Absorbing */
    unsigned long long i = 0;

    while (RATE*(i+1) <= m_len) {
        
        /* Inject the message into the rate part of the internal state */
        mpc_xor_values(state, key_aux +RATE*i, pt_aux + RATE*i, RATE);

        /* Apply the sponge function */
        F384(state);

        /* Update the counter (number of blocks) */
        i++;
    }

   /* Process incomplete block */
   if (m_len > RATE*i) {

        /* Prepare the last padded blocks */
        memset(last_block, 0, RATE);
        memcpy(last_block, pt_aux + RATE*i, m_len-RATE*i);

        memset(last_block_key, 0, RATE);
        memcpy(last_block_key, key_aux + RATE*i, m_len-RATE*i);
        last_block_key[m_len-RATE*i] = 0x80;

        /* Inject the message into the rate part of the internal state */
        mpc_xor_values(state, last_block_key, last_block, RATE);

    } else {

        /* Prepare the last padded block */
        memset(last_block, 0, RATE);
        last_block[0] = 0x80;

        /* Inject padded block into the rate part */
        xor_values(state, last_block, RATE);

    }

    /* Apply the sponge function */
    F384(state);

    //uint8_t* outs[2];
    //uint32_t* aux_outs[2];
    memcpy(output,state,16);
}

/*
    ciphertext = encrypt (plaintext,key)

    //initial whitening
    state = plaintext + MultiplyWithGF2Matrix(KMatrix(0),key)

    for (i = 1 to r)

    //m computations of 3-bit sbox,
    //remaining n-3m bits remain the same
    state = Sboxlayer (state)

    //affine layer
    state = MultiplyWithGF2Matrix(LMatrix(i),state)
    state = state + Constants(i)

    //generate round key and add to the state
    state = state + MultiplyWithGF2Matrix(KMatrix(i),key)
    end
    ciphertext = state
*/
// plaintext, cipher (public key), secret key, parâmetros
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

void H3(const uint32_t* circuitOutput, const uint32_t* plaintext, uint32_t** viewOutputs,
        commitments_t* as, uint8_t* challengeBits, const uint8_t* salt,
        const uint8_t* message, size_t messageByteLength,
        g_commitments_t* gs, paramset_t* params)
{
    uint8_t* hash = malloc(params->digestSizeBytes);
    HashInstance ctx;

    /* Depending on the number of rounds, we might not set part of the last
     * byte, make sure it's always zero. */
    challengeBits[numBytes(params->numMPCRounds * 2) - 1] = 0;

    HashInit(&ctx, params, HASH_PREFIX_1);

    /* Hash the output share from each view */
    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        for (int j = 0; j < 3; j++) {
            HashUpdate(&ctx, (uint8_t*)VIEW_OUTPUTS(i, j), params->stateSizeBytes);
        }
    }

    /* Hash all the commitments C */
    for (uint32_t i = 0; i < params->numMPCRounds; i++) {
        for (int j = 0; j < 3; j++) {
            HashUpdate(&ctx, as[i].hashes[j], params->digestSizeBytes);
        }
    }

    /* Hash all the commitments G */
    if (params->transform == TRANSFORM_UR) {
        for (uint32_t i = 0; i < params->numMPCRounds; i++) {
            for (int j = 0; j < 3; j++) {
                size_t view3UnruhLength = (j == 2) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
                HashUpdate(&ctx, gs[i].G[j], view3UnruhLength);
            }
        }
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
           view_t views[3], commitments_t* commitments, g_commitments_t* gs, paramset_t* params)
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

    memcpy(proof->view3Commitment, commitments->hashes[(challenge + 2) % 3], params->digestSizeBytes);
    if (params->transform == TRANSFORM_UR) {
        size_t view3UnruhLength = (challenge == 0) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
        memcpy(proof->view3UnruhG, gs->G[(challenge + 2) % 3], view3UnruhLength);
    }
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



// Apply the linear diffusion matrix
//M =
//1 0 1 1
//1 0 0 0
//0 1 1 0
//1 0 1 0
static void MixColumn_verify(uint8_t states[2][4][4]) {
    int j;
    uint8_t temp;
    for(int player = 0; player < 2; player++){

        for(j = 0; j < 4; j++) {
            states[player][1][j]^=states[player][2][j];
            states[player][2][j]^=states[player][0][j];
            states[player][3][j]^=states[player][2][j];

            temp=states[player][3][j];
            states[player][3][j]=states[player][2][j];
            states[player][2][j]=states[player][1][j];
            states[player][1][j]=states[player][0][j];
            states[player][0][j]=temp;
        }
    }
}

// Apply the ShiftRows function
static void ShiftRows_verify(uint8_t states[2][4][4]) {
    int i, j, pos;

    for(int player = 0; player < 2; player++){

        uint8_t state_tmp[4][4];
        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                //application of the ShiftRows permutation
                pos=P[j+4*i];
                state_tmp[i][j]=states[player][pos>>2][pos&0x3];
            }
        }

        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                states[player][i][j]=state_tmp[i][j];
            }
        }
    }
}

// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state
static void AddKey_verify(uint8_t states[2][4][4], uint8_t playerKeyCells[2][3][4][4]) {
    int i, j, k;
    uint8_t pos;

    for(int player = 0; player < 2; player++){

        uint8_t keyCells_tmp[3][4][4];

        // apply the subtweakey to the internal state
        for(i = 0; i <= 1; i++) {
            for(j = 0; j < 4; j++) {
                states[player][i][j] ^= playerKeyCells[player][0][i][j] ^ playerKeyCells[player][1][i][j] ^ playerKeyCells[player][2][i][j];
            }
        }

        // update the subtweakey states with the permutation
        for(k = 0; k < 3; k++) {
            for(i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    //application of the TWEAKEY permutation
                    pos=TWEAKEY_P[j+4*i];
                    keyCells_tmp[k][i][j]=playerKeyCells[player][k][pos>>2][pos&0x3];
                }
            }
        }

        // update the subtweakey states with the LFSRs
        for(k = 0; k < 3; k++) {
            for(i = 0; i <= 1; i++) {
                for(j = 0; j < 4; j++) {
                    //application of LFSRs for TK updates
                    if (k==1) {
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xFE)^((keyCells_tmp[k][i][j]>>7)&0x01)^((keyCells_tmp[k][i][j]>>5)&0x01);
                    } else if (k==2) {
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7F)^((keyCells_tmp[k][i][j]<<7)&0x80)^((keyCells_tmp[k][i][j]<<1)&0x80);
                    }
                }
            }
        }

        for(k = 0; k < 3; k++) {
            for(i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    playerKeyCells[player][k][i][j]=keyCells_tmp[k][i][j];
                }
            }
        }
    }
}

// Apply the constants: using a LFSR counter on 6 bits, we XOR the 6 bits to the first 6 bits of the internal state
void AddConstants_verify(uint8_t states[2][4][4], int r) {
    for(int player=0;player<2;player++){
        states[player][0][0] ^= (RC[r] & 0xf);
        states[player][1][0] ^= ((RC[r]>>4) & 0x3);
        states[player][2][0] ^= 0x2;
    }
}

/*
// Operations performed:
// (x7,x6,x5,x4,x3,x2,x1,x0) -> (x7, x6, x5, x4 ^ (~x7 & ~x6), x3, x2, x1, x0 ^(~x3 & ~x2))
// (x7, x6, x5, x4, x3, x2, x1, x0) -> (x2, x1, x7, x6, x4, x0, x3, x5)
static uint8_t skinny_byte_update(uint8_t x){
    return ((x >> (2 % 8)) & 1) | ((x >> (1 % 8)) & 1) | ((x >> (7 % 8)) & 1) | ((x >> (6 % 8)) & 1) \
    | (((x >> (4 % 8)) & 1) ^ (~((x >> (7 % 8)) & 1) & ~((x >> (6 % 8)) & 1))) \
    | (((x >> (0 % 8)) & 1) ^ (~((x >> (3 % 8)) & 1) & ~((x >> (2 % 8)) & 1))) \
    | ((x >> (3 % 8)) & 1) | ((x >> (5 % 8)) & 1);
    
}

static void mpc_skinny_and_verify(uint8_t states[2][4][4], view_t views[3], randomTape_t* rand){

    uint8_t r[2] = { getBit(rand->tape[0], rand->pos), getBit(rand->tape[1], rand->pos) };

    uint8_t abc[3],out[2][16][3][2];
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j <  4; j++) {
            abc[0] = states[0][i][j];
            abc[1] = states[1][i][j];
            abc[2] = states[2][i][j];
            for(int reps=0;reps<3;reps++){ // transformações dentro da S-box
                // ~(x >> (7 % 8) & 1) & ~(x >> (6 % 8) & 1)
                // ~(x >> (3 % 8) & 1) & ~(x >> (2 % 8) & 1)
                for(uint8_t player = 0; player < 2; player++){ // itera por 3 jogadores
                    out[player][i*4+j][reps][0] = (~((abc[player] >> (7 % 8)) & 1) & ~((abc[(player+1) % 2] >> (6 % 8)) & 1)) ^ \
                        (~((abc[(player+1) % 2] >> (7 % 8)) & 1) & ~((abc[player] >> (6 % 8)) & 1)) ^ \
                        (~((abc[player] >> (7 % 8)) & 1) & ~((abc[player] >> (6 % 8)) & 1)) ^ \
                        r[player] ^ r[(player+1) % 2];
                    out[player][player*4+j][reps][1] = getBit(view2->communicatedBits, rand->pos);
                }
                abc[0] = skinny_byte_update(abc[0]);
                abc[1] = skinny_byte_update(abc[1]);
                abc[2] = skinny_byte_update(abc[2]);
            }
        }
    }
    for(uint8_t player =0; player<3; player++){
        for(uint8_t cell=0;cell < 16;cell++){
            for(uint8_t update=0;update<3;update++){
                setBit(views[player].communicatedBits, rand->pos, out[player][cell][update][0]);
            }
            rand->pos += 2;
        }
    }
}
*/

// apply the 8-bit Sbox
static void SubCell8_verify(uint8_t states[2][4][4], view_t views[3], randomTape_t* tapes) {
    (void) views;
    (void) tapes;
    //mpc_skinny_and_verify(states,views,tapes);
    for(int player=0;player<2;player++){
        int i,j;
        for(i = 0; i < 4; i++) {
            for(j = 0; j <  4; j++) {
                states[player][i][j] = sbox_8[states[player][i][j]];
            }
        }
    }
}

// encryption function of Skinny
// {128,384, 56}; ver 5 -> SKINNY-128-384: 56 rounds 
void enc_verify(const uint8_t* input, const uint8_t tweakeys[2][48], uint8_t outputs[2][16], view_t views[3], randomTape_t* tapes, paramset_t* params) {

    (void) params;
    uint8_t states[2][4][4];
    uint8_t playersKeyCells[2][3][4][4];
    int i,player;

#ifdef DEBUG
    fic = fopen("SKINNY_TBC_detailed_TV.txt", "a");
#endif

    /* Set state and keyCells for each player */
    for(player=0;player<2;player++){

        memset(playersKeyCells[player], 0, 48);

        for(i = 0; i < 16; i++) {
            states[player][i>>2][i&0x3] = input[i]&0xFF;

            playersKeyCells[player][0][i>>2][i&0x3] = tweakeys[player][i]&0xFF;
            playersKeyCells[player][2][i>>2][i&0x3] = tweakeys[player][i+32]&0xFF;
        }
    }

    #ifdef DEBUG
        fprintf(fic,"ENC - initial state:                 ");display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
    #endif

    for(i = 0; i < 56; i++) {

        SubCell8_verify(states,views,tapes);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after SubCell:      ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        AddConstants_verify(states, i);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after AddConstants: ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        AddKey_verify(states, playersKeyCells);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after AddKey:       ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        ShiftRows_verify(states);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after ShiftRows:    ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        MixColumn_verify(states);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after MixColumn:    ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
    }  //The last subtweakey should not be added

    #ifdef DEBUG
        fprintf(fic,"ENC - final state:                   ");display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
    #endif


    for(player=0;player<2;player++){
        for(i = 0; i < 16; i++) {
            outputs[player][i] = states[player][i>>2][i&0x3] & 0xFF;
        }
    }

#ifdef DEBUG
    fclose(fic);
#endif
}

static void skinny_F384_verify(uint8_t states[2][48], view_t views[2], randomTape_t* tapes, paramset_t* params) {

    uint8_t tweakeys[2][48];
    uint8_t tmp_outs[2][16];
    int player;

    uint8_t tmp_in[16];
    memset(tmp_in, 0, sizeof(tmp_in));

    /* Initialization */
    for(player=0;player<2;player++){
        memcpy(tweakeys[player], states[player], 48);
        memset(tmp_outs[player],0, 16);
    }
    /*
        Call for the three players a enc() function with the initial input for each one 
    */

    /* First TBC call with input 0 */
    //tmp_ins[player][0] = 0; -> not needed as it is alredy 0
    enc_verify(tmp_in, tweakeys, tmp_outs, views, tapes, params);
    for(player=0;player<2;player++){
        memcpy(states[player], tmp_outs[player], 16);
    }
    
    /* Second TBC call with input 1 */
    tmp_in[0] = 1;
    enc_verify(tmp_in, tweakeys, tmp_outs, views, tapes, params);
    for(player=0;player<2;player++){ 
        memcpy(states[player]+16, tmp_outs[player], 16);
    }

    /* Third TBC call with input 2 */
    tmp_in[0] = 2;
    enc_verify(tmp_in, tweakeys, tmp_outs, views, tapes, params);
    for(player=0;player<2;player++){
        memcpy(states[player]+32, tmp_outs[player], 16);
    }

}

/*
** SKINNY-HASH
*/
void mpc_SKINNY_verify(view_t* view1, view_t* view2,
                         randomTape_t* tapes,const uint32_t* plaintext, paramset_t* params, uint8_t challenge)
{
    // prevent errors
    (void) challenge;

    uint8_t states[2][TWEAKEY_STATE_SIZE];
    uint8_t last_blocks[2][RATE];
    uint8_t* in[2];
    uint8_t* pt = (uint8_t*) plaintext;
    uint8_t last_pt[RATE];
    view_t views[2] = {*view1,*view2};
    // número de bytes de input
    unsigned long long m_len = sizeof(view1->inputShare)*4;
    int player;
    /* Initialization */
    for(player=0;player<2;player++){

        /* Initialize each internal state */
        memset(states[player], 0, TWEAKEY_STATE_SIZE);
        states[player][RATE] = 0x80;
    }

    //store player's input
    in[0] = (uint8_t*)view1->inputShare;
    in[1] = (uint8_t*)view2->inputShare;

    /* Absorbing */
    
    unsigned long long i = 0;
    while (RATE*(i+1) <= m_len) {
        for(player=0;player<2;player++){

            /* Inject the message into the rate part of the internal state */
            mpc_xor_values(states[player], in[player] + RATE*i, pt + RATE*i, RATE);

        }

        /* Apply the sponge function */
        skinny_F384_verify(states,views,tapes,params);

        /* Update the counter (number of blocks) */
        i++;
    }
    
   /* Process incomplete block */
   if (m_len > RATE*i) {
        memset(last_pt, 0, RATE);
        memcpy(last_pt, pt+RATE*i, m_len-RATE*i);
        for(player=0;player<2;player++){

            /* Prepare the last padded block */
            memset(last_blocks[player], 0, RATE);
            memcpy(last_blocks[player], in[player]+RATE*i, m_len-RATE*i);
            last_blocks[player][m_len-RATE*i] = 0x80;

            /* Inject the message into the rate part of the internal state */
            mpc_xor_values(states[player], last_blocks[player], last_pt, RATE);

        }
    } else {
        for(player=0;player<2;player++){
            /* Prepare the last padded block */
            memset(last_blocks[player], 0, RATE);
            last_blocks[player][0] = 0x80;

            /* Inject padded block into the rate part */
            xor_values(states[player], last_blocks[player], RATE);

        }
    }

    /* Apply the sponge function */
    skinny_F384_verify(states,views,tapes,params);

    uint8_t* outs[2];
    uint32_t* aux_outs[2];


    for(player=0;player<2;player++){
        outs[player] = calloc(1,sizeof(uint8_t)*64);
        memcpy(outs[player], states[player], 16);
        aux_outs[player] = (uint32_t*) outs[player];
    }

    /*if(Debug ==0){
        fprintf(stdout, "\nDEBUG PRE:\n\naux_outs[0] ==> { ");
        for(uint32_t aux = 0; aux < params->stateSizeBytes/4; aux++ ){
            fprintf(stdout, "%u",aux_outs[0][aux]);
            if(aux != 3 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\naux_outs[1] ==> {");
        for(uint32_t aux = 0; aux < params->stateSizeBytes/4; aux++ ){
            fprintf(stdout, "%u",aux_outs[1][aux]);
            if(aux != 3 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\n# ---------- #\n");
        fflush(stdout);
    }*/
    
    // params->stateSizeBytes == 16
    memcpy(views[0].outputShare,aux_outs[0],params->stateSizeBytes);
    memcpy(views[1].outputShare,aux_outs[1],params->stateSizeBytes);

    /*if(Debug == 0){
        fprintf(stdout, "\nDEBUG POS:\n\nview1->outputShare ==> {");
        for(uint32_t aux = 0; aux < params->stateSizeBytes/4; aux++ ){
            fprintf(stdout, "%u",views[0].outputShare[aux]);
            if(aux != 3 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\nview2->outputShare ==> {");
        for(uint32_t aux = 0; aux < params->stateSizeBytes/4; aux++ ){
            fprintf(stdout, "%u",views[1].outputShare[aux]);
            if(aux != 3 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\n# ---------- #\n");
        fflush(stdout);
    }*/
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

    for (uint32_t r = 1; r <= 4; ++r) {
        mpc_matrix_mul(roundKey, keyShares, KMatrix(r, params), params, 2);
        mpc_substitution_verify(state, tapes, view1, view2, params);
        mpc_matrix_mul(state, state, LMatrix(r - 1, params), params, 2);
        mpc_xor_constant_verify(state, RConstant(r - 1, params), params->stateSizeWords, challenge);
        mpc_xor(state, roundKey, params->stateSizeWords, 2);
    }

    if(Debug == 0){
        fprintf(stdout, "\nDEBUG PRÉ:\n Size of the output views: %lu; Size of the state to be copyed: %u\n\nView1 ==> {",sizeof(view1->outputShare),params->stateSizeBytes);
        for(uint32_t aux = 0; aux < params->stateSizeBytes; aux++ ){
            fprintf(stdout, "%u",state[0][aux]);
            if(aux != 15 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\nView2 ==> {");
        for(uint32_t aux = 0; aux < params->stateSizeBytes; aux++ ){
            fprintf(stdout, "%u",state[1][aux]);
            if(aux != 15 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\n# ---------- #\n");
        fflush(stdout);
    }

    memcpy(view1->outputShare, state[0], params->stateSizeBytes);
    memcpy(view2->outputShare, state[1], params->stateSizeBytes);

    if(Debug == 0){
        fprintf(stdout, "\nDEBUG PÓS:\n Size of the output views: %lu; Size of the state to be copyed: %lu\n\nView1 ==> {",sizeof(view1->outputShare),sizeof(state[0]));
        for(uint32_t aux = 0; aux < params->stateSizeBytes; aux++ ){
            fprintf(stdout, "%u",view1->outputShare[aux]);
            if(aux != 15 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\nView2 ==> {");
        for(uint32_t aux = 0; aux < params->stateSizeBytes; aux++ ){
            fprintf(stdout, "%u",view2->outputShare[aux]);
            if(aux != 15 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\n# ---------- #\n");
        fflush(stdout);
    }
}

void verifyProof(const proof_t* proof, view_t* view1, view_t* view2,
                 uint8_t challenge, uint8_t* salt, uint16_t roundNumber, uint8_t* tmp,
                 const uint32_t* plaintext, randomTape_t* tape, paramset_t* params)
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

    if (!status) {
        PRINT_DEBUG(("Failed to generate random tapes, signature verification will fail (but signature may actually be valid)\n"));
    }

    /* When input shares are read from the tapes, and the length is not a whole number of bytes, the trailing bits must be zero */
    zeroTrailingBits((uint8_t*)view1->inputShare, params->stateSizeBits);
    zeroTrailingBits((uint8_t*)view2->inputShare, params->stateSizeBits);

    mpc_SKINNY_verify(view1, view2, tape, plaintext, params, challenge);
    //mpc_LowMC_verify(view1, view2, tape, (uint32_t*)tmp, plaintext, params, challenge);
}

int verify(signature_t* sig, const uint32_t* pubKey, const uint32_t* plaintext,
           const uint8_t* message, size_t messageByteLength, paramset_t* params)
{
    commitments_t* as = allocateCommitments(params, 0);
    g_commitments_t* gs = allocateGCommitments(params);

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
        Debug=i;
        allocateView(&view1s[i], params);
        allocateView(&view2s[i], params);

        verifyProof(&proofs[i], &view1s[i], &view2s[i],
                    getChallenge(received_challengebits, i), sig->salt, i,
                    tmp, plaintext, tape, params);
    
        // create ordered array of commitments with order computed based on the challenge
        // check commitments of the two opened views
        uint8_t challenge = getChallenge(received_challengebits, i);
        Commit(proofs[i].seed1, view1s[i], as[i].hashes[challenge], params);
        Commit(proofs[i].seed2, view2s[i], as[i].hashes[(challenge + 1) % 3], params);
        memcpy(as[i].hashes[(challenge + 2) % 3], proofs[i].view3Commitment, params->digestSizeBytes);

        if (params->transform == TRANSFORM_UR) {
            G(challenge, proofs[i].seed1, &view1s[i], gs[i].G[challenge], params);
            G((challenge + 1) % 3, proofs[i].seed2, &view2s[i], gs[i].G[(challenge + 1) % 3], params);
            size_t view3UnruhLength = (challenge == 0) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
            memcpy(gs[i].G[(challenge + 2) % 3], proofs[i].view3UnruhG, view3UnruhLength);
        }

        VIEW_OUTPUTS(i, challenge) = view1s[i].outputShare;
        VIEW_OUTPUTS(i, (challenge + 1) % 3) = view2s[i].outputShare;
        xor_three(view3Output, view1s[i].outputShare,  view2s[i].outputShare, pubKey, params->stateSizeBytes);
        
        if(Debug==0){
            fprintf(stdout,"\n\nparams->stateSizeBytes: %u\n\n",params->stateSizeBytes);
            fprintf(stdout, "\nView1 => {");
            for(uint32_t aux=0; aux < params->stateSizeBytes/4;aux++){
                fprintf(stdout, "%u",view1s[i].outputShare[aux]);
                if(aux != 3) fprintf(stdout, ",");
            }
            fprintf(stdout, "}\nView2 => {");
            for(uint32_t aux=0; aux < params->stateSizeBytes/4;aux++){
                fprintf(stdout, "%u",view2s[i].outputShare[aux]);
                if(aux != 3) fprintf(stdout, ",");
            }
            fprintf(stdout, "}\npubKey => {");
            for(uint32_t aux=0; aux < params->stateSizeBytes/4;aux++){
                fprintf(stdout, "%u",pubKey[aux]);
                if(aux != 3) fprintf(stdout, ",");
            }
            size_t wholeWords = params->stateSizeBytes/sizeof(uint32_t);
            uint32_t output[wholeWords];
            uint32_t* in1 = (uint32_t*)view1s[i].outputShare;
            uint32_t* in2 = (uint32_t*)view2s[i].outputShare;
            uint32_t* in3 = (uint32_t*)pubKey;
            fprintf(stdout, "}\n\n# -- First xor -- #\n\n");
            for(size_t aux = 0; aux < wholeWords; aux++) {
                output[aux] = in1[aux] ^ in2[aux] ^ in3[aux];
                fprintf(stdout,"{%u = %u ^ %u ^ %u}\n",output[aux],in1[aux],in2[aux],in3[aux]);
                fprintf(stdout,"{%u = %u ^ %u ^ %u}\n",in3[aux],in3[aux] ^ in2[aux] ^ in1[aux],in2[aux],in1[aux]);
            }
            fprintf(stdout, "\nView3 => {");
            for(uint32_t aux=0; aux < params->stateSizeBytes/4;aux++){
                fprintf(stdout, "%u",view3Output[aux]);
                if(aux != 3) fprintf(stdout, ",");
            } 
            fprintf(stdout, "}\n");
            fflush(stdout);  
        }
        VIEW_OUTPUTS(i, (challenge + 2) % 3) = view3Output;
        view3Output = (uint32_t*) ((uint8_t*)view3Output + params->stateSizeBytes);
    }

    computed_challengebits = malloc(numBytes(2 * params->numMPCRounds));

    H3(pubKey, plaintext, viewOutputs, as,
       computed_challengebits, sig->salt, message, messageByteLength, gs, params);

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
    //fprintf(stdout,"Byte: %u, bit: %u\n",rand->pos/8, rand->pos%8);
    //fflush(stdout);

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

// Apply the linear diffusion matrix
//M =
//1 0 1 1
//1 0 0 0
//0 1 1 0
//1 0 1 0
static void mpc_MixColumn(uint8_t states[3][4][4]) {
    int j;
    uint8_t temp;
    for(int player = 0; player < 3; player++){

        for(j = 0; j < 4; j++) {
            states[player][1][j]^=states[player][2][j];
            states[player][2][j]^=states[player][0][j];
            states[player][3][j]^=states[player][2][j];

            temp=states[player][3][j];
            states[player][3][j]=states[player][2][j];
            states[player][2][j]=states[player][1][j];
            states[player][1][j]=states[player][0][j];
            states[player][0][j]=temp;
        }
    }
}

// Apply the ShiftRows function
static void mpc_ShiftRows(uint8_t states[3][4][4]) {
    int i, j, pos;

    for(int player = 0; player < 3; player++){

        uint8_t state_tmp[4][4];
        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                //application of the ShiftRows permutation
                pos=P[j+4*i];
                state_tmp[i][j]=states[player][pos>>2][pos&0x3];
            }
        }

        for(i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                states[player][i][j]=state_tmp[i][j];
            }
        }
    }
}

// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state
static void mpc_AddKey(uint8_t states[3][4][4], uint8_t playerKeyCells[3][3][4][4]) {
    int i, j, k;
    uint8_t pos;

    for(int player = 0; player < 3; player++){

        uint8_t keyCells_tmp[3][4][4];

        // apply the subtweakey to the internal state
        for(i = 0; i <= 1; i++) {
            for(j = 0; j < 4; j++) {
                states[player][i][j] ^= playerKeyCells[player][0][i][j] ^ playerKeyCells[player][1][i][j] ^ playerKeyCells[player][2][i][j];
            }
        }

        // update the subtweakey states with the permutation
        for(k = 0; k < 3; k++) {
            for(i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    //application of the TWEAKEY permutation
                    pos=TWEAKEY_P[j+4*i];
                    keyCells_tmp[k][i][j]=playerKeyCells[player][k][pos>>2][pos&0x3];
                }
            }
        }

        // update the subtweakey states with the LFSRs
        for(k = 0; k < 3; k++) {
            for(i = 0; i <= 1; i++) {
                for(j = 0; j < 4; j++) {
                    //application of LFSRs for TK updates
                    if (k==1) {
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xFE)^((keyCells_tmp[k][i][j]>>7)&0x01)^((keyCells_tmp[k][i][j]>>5)&0x01);
                    } else if (k==2) {
                        keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7F)^((keyCells_tmp[k][i][j]<<7)&0x80)^((keyCells_tmp[k][i][j]<<1)&0x80);
                    }
                }
            }
        }

        for(k = 0; k < 3; k++) {
            for(i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    playerKeyCells[player][k][i][j]=keyCells_tmp[k][i][j];
                }
            }
        }
    }
}

// Apply the constants: using a LFSR counter on 6 bits, we XOR the 6 bits to the first 6 bits of the internal state
void mpc_AddConstants(uint8_t states[3][4][4], int r) {
    for(int player=0;player<3;player++){
        states[player][0][0] ^= (RC[r] & 0xf);
        states[player][1][0] ^= ((RC[r]>>4) & 0x3);
        states[player][2][0] ^= 0x2;
    }
}

/*

// ~(x >> (7 % 8) & 1) & ~(x >> (6 % 8) & 1)
// ~(x >> (3 % 8) & 1) & ~(x >> (2 % 8) & 1)

static void mpc_skinny_and(uint8_t states[3][4][4], view_t views[3], randomTape_t* rand){

    uint8_t r[3] = { getBit(rand->tape[0], rand->pos), getBit(rand->tape[1], rand->pos), getBit(rand->tape[2], rand->pos) };

    uint8_t abc[3],out[3][16][3][2];
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j <  4; j++) {
            abc[0] = states[0][i][j];
            abc[1] = states[1][i][j];
            abc[2] = states[2][i][j];
            for(int reps=0;reps<3;reps++){ // transformações dentro da S-box
                for(uint8_t player = 0; player < 3; player++){ // itera por 3 jogadores
                    out[player][i*4+j][reps][0] = (~((abc[player] >> (7 % 8)) & 1) & ~((abc[(player+1) % 3] >> (6 % 8)) & 1)) ^ \
                        (~((abc[(player+1) % 3] >> (7 % 8)) & 1) & ~((abc[player] >> (6 % 8)) & 1)) ^ \
                        (~((abc[player] >> (7 % 8)) & 1) & ~((abc[player] >> (6 % 8)) & 1)) ^ \
                        r[player] ^ r[(player+1) % 3];
                    out[player][player*4+j][reps][1] = (~((abc[player] >> (3 % 8)) & 1) & ~((abc[(player+1) % 3] >> (2 % 8)) & 1)) ^ \
                        (~((abc[(player+1) % 3] >> (3 % 8)) & 1) & ~((abc[player] >> (2 % 8)) & 1)) ^ \
                        (~((abc[player] >> (3 % 8)) & 1) & ~((abc[player] >> (2 % 8)) & 1)) ^ \
                        r[player] ^ r[(player+1) % 3];
                }
                abc[0] = skinny_byte_update(abc[0]);
                abc[1] = skinny_byte_update(abc[1]);
                abc[2] = skinny_byte_update(abc[2]);
            }
        }
    }
    for(uint8_t player =0; player<3; player++){
        for(uint8_t cell=0;cell < 16;cell++){
            for(uint8_t update=0;update<3;update++){
                setBit(views[player].communicatedBits, rand->pos, out[player][cell][update][0]);
                setBit(views[player].communicatedBits, rand->pos+1, out[player][cell][update][0]);
            }
            rand->pos += 2;
        }
    }
}
*/


// apply the 8-bit Sbox
static void mpc_SubCell8(uint8_t states[3][4][4], view_t views[3], randomTape_t* tapes) {
    (void) tapes;
    (void) views;
    //mpc_skinny_and(states,views,tapes);
    for(int player=0;player<3;player++){
        int i,j;
        for(i = 0; i < 4; i++) {
            for(j = 0; j <  4; j++) {
                states[player][i][j] = sbox_8[states[player][i][j]];
            }
        }
    }
}

// encryption function of Skinny
// {128,384, 56}; ver 5 -> SKINNY-128-384: 56 rounds 
void enc(const uint8_t* input, const uint8_t tweakeys[3][48], uint8_t outputs[3][16], view_t views[3], paramset_t* params, randomTape_t* tapes) {

    (void) params;
    uint8_t states[3][4][4];
    uint8_t playersKeyCells[3][3][4][4];
    int i,player;

#ifdef DEBUG
    fic = fopen("SKINNY_TBC_detailed_TV.txt", "a");
#endif

    /* Set state and keyCells for each player */
    for(player=0;player<3;player++){

        memset(playersKeyCells[player], 0, 48);

        for(i = 0; i < 16; i++) {
            states[player][i>>2][i&0x3] = input[i]&0xFF;

            playersKeyCells[player][0][i>>2][i&0x3] = tweakeys[player][i]&0xFF;
            playersKeyCells[player][2][i>>2][i&0x3] = tweakeys[player][i+32]&0xFF;
        }
    }

    #ifdef DEBUG
        fprintf(fic,"ENC - initial state:                 ");display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
    #endif

    for(i = 0; i < 56; i++) {

        mpc_SubCell8(states,views,tapes);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after SubCell:      ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_AddConstants(states, i);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after AddConstants: ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_AddKey(states, playersKeyCells);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after AddKey:       ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_ShiftRows(states);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after ShiftRows:    ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
        mpc_MixColumn(states);
            #ifdef DEBUG
            fprintf(fic,"ENC - round %.2i - after MixColumn:    ",i);display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
            #endif
    }  //The last subtweakey should not be added

    #ifdef DEBUG
        fprintf(fic,"ENC - final state:                   ");display_cipher_state(state,keyCells,ver);fprintf(fic,"\n");
    #endif

    for(player=0;player<3;player++){
        for(i = 0; i < 16; i++) {
            outputs[player][i] = states[player][i>>2][i&0x3] & 0xFF;
        }
    }

#ifdef DEBUG
    fclose(fic);
#endif
}

static void skinny_F384(uint8_t states[3][48], view_t views[3], randomTape_t* tapes, paramset_t* params) {

    uint8_t tweakeys[3][48];
    uint8_t tmp_outs[3][16];
    int player;

    uint8_t tmp_in[16];
    memset(tmp_in, 0, sizeof(tmp_in));

    /* Initialization */
    for(player=0;player<3;player++){
        memcpy(tweakeys[player], states[player], 48);
        memset(tmp_outs[player],0,16);
    }
    /*
        Call for the three players a enc() function with the initial input for each one 
    */

    /* First TBC call with input 0 */
    //tmp_ins[player][0] = 0; -> not needed as it is alredy 0
    enc(tmp_in, tweakeys, tmp_outs,views,params,tapes);
    for(player=0;player<3;player++){
        memcpy(states[player], tmp_outs[player], 16);
    }

    /* Second TBC call with input 1 */
    tmp_in[0] = 1;
    enc(tmp_in, tweakeys, tmp_outs,views,params,tapes);
    for(player=0;player<3;player++){ 
        memcpy(states[player]+16, tmp_outs[player], 16);
    }

    /* Third TBC call with input 2 */
    tmp_in[0] = 2;
    enc(tmp_in, tweakeys, tmp_outs,views,params,tapes);
    for(player=0;player<3;player++){
        memcpy(states[player]+32, tmp_outs[player], 16);
    }
}

/*
** SKINNY-HASH
*/
void mpc_SKINNY(randomTape_t* tapes,const uint32_t* plaintext, view_t views[3], paramset_t* params)
{

    uint8_t states[3][TWEAKEY_STATE_SIZE];
    uint8_t last_blocks[3][RATE];
    uint8_t last_pt[RATE];
    uint8_t* in[3];
    uint8_t* pt = (uint8_t*) plaintext;
    // número de bytes de input - 32 bytes (2 absorções + 1 F384 para o padding)
    unsigned long long m_len = sizeof(views[0].inputShare)*4;
    fflush(stdout);
    int player;

    /* Initialization */
    for(player=0;player<3;player++){

        /* Initialize each internal state */
        memset(states[player], 0, TWEAKEY_STATE_SIZE);
        states[player][RATE] = 0x80;

        //store player's input
        in[player] = (uint8_t*)views[player].inputShare;
    }
    /* Absorbing */
    unsigned long long i = 0;

    //RATE*(i+1) => 16
    //m_len => 8
    
    while (RATE*(i+1) <= m_len) {
        for(player=0;player<3;player++){

            /* Inject the message into the rate part of the internal state */
            mpc_xor_values(states[player], in[player] + RATE*i, pt + RATE*i, RATE);

        }
        /* Apply the sponge function */
        skinny_F384(states,views,tapes,params);

        /* Update the counter (number of blocks) */
        i++;
    }
   /* Process incomplete block */
   if (m_len > RATE*i) {
        memset(last_pt, 0, RATE);
        memcpy(last_pt, pt+RATE*i, m_len-RATE*i);
        for(player=0;player<3;player++){

            /* Prepare the last padded block */
            memset(last_blocks[player], 0, RATE);
            memcpy(last_blocks[player], in[player]+RATE*i, m_len-RATE*i);
            last_blocks[player][m_len-RATE*i] = 0x80;

            /* Inject the message into the rate part of the internal state */
            mpc_xor_values(states[player], last_blocks[player], last_pt, RATE);
        }
    } else {
        for(player=0;player<3;player++){

            /* Prepare the last padded block */
            memset(last_blocks[player], 0, RATE);
            last_blocks[player][0] = 0x80;

            /* Inject padded block into the rate part */
            xor_values(states[player], last_blocks[player], RATE);
        }
    }

    /* Apply the sponge function */
    skinny_F384(states,views,tapes,params);

    uint8_t* outs[3];
    uint32_t* aux_outs[3];

    for(player=0;player<3;player++){
        outs[player] = malloc(sizeof(uint8_t)*16);
        memcpy(outs[player], states[player], 16);
        aux_outs[player] = (uint32_t*) outs[player];
    }


    /*if(Debug == 0){
        fprintf(stdout, "\nOutputs:\n\naux_outs[0] ==> {");
        for(uint32_t aux = 0; aux < params->stateSizeBytes/4; aux++ ){
            fprintf(stdout, "%u",aux_outs[0][aux]);
            if(aux != 3 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\naux_outs[1] ==> {");
        for(uint32_t aux = 0; aux < params->stateSizeBytes/4; aux++ ){
            fprintf(stdout, "%u",aux_outs[1][aux]);
            if(aux != 3 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\naux_outs[2] ==> {");
        for(uint32_t aux = 0; aux < params->stateSizeBytes/4; aux++ ){
            fprintf(stdout, "%u",aux_outs[2][aux]);
            if(aux != 3 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\n# ---------- #\n");
        fflush(stdout);
    }*/

    for(player=0;player<3;player++){
        memcpy(views[player].outputShare, aux_outs[player], params->stateSizeBytes);
    }

    /*if(Debug ==0){
        fprintf(stdout, "\n Stored Outputs (size: %lu):\n\nView1 ==> { ",sizeof(views[0].outputShare));
        for(uint32_t aux = 0; aux < params->stateSizeBytes/4; aux++ ){
            fprintf(stdout, "%u",views[0].outputShare[aux]);
            if(aux != 3 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\nView2 ==> {");
        for(uint32_t aux = 0; aux < params->stateSizeBytes/4; aux++ ){
            fprintf(stdout, "%u",views[1].outputShare[aux]);
            if(aux != 3 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\nView3 ==> {");
        for(uint32_t aux = 0; aux < params->stateSizeBytes/4; aux++ ){
            fprintf(stdout, "%u",views[2].outputShare[aux]);
            if(aux != 3 ) fprintf(stdout, ", ");
        }
        fprintf(stdout, "}\n# ---------- #\n");
        fflush(stdout);
    }*/
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

    /* Compute seeds for all parallel iterations */
    seeds_t* seeds = computeSeeds(privateKey, pubKey, plaintext, message, messageByteLength, params);

    memcpy(sig->salt, seeds[params->numMPCRounds].iSeed, params->saltSizeBytes);

    //Allocate a random tape (re-used per parallel iteration), and a temporary buffer
    randomTape_t tape;

    allocateRandomTape(&tape, params);
    uint8_t* tmp = malloc( MAX(9 * params->stateSizeBytes, params->stateSizeBytes + params->andSizeBytes));

    for (uint32_t k = 0; k < params->numMPCRounds; k++) {
        Debug=k;
        // for first two players get all tape INCLUDING INPUT SHARE from seed

        for (int j = 0; j < 2; j++) {
            status = createRandomTape(seeds[k].seed[j], sig->salt, k, j, tmp, params->stateSizeBytes + params->andSizeBytes, params);
            if (!status) {
                PRINT_DEBUG(("createRandomTape failed \n"));
                return EXIT_FAILURE;
            }
            /* Se copiar 16 bytes 2 vezes para o output falha aqui!! */
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

        mpc_SKINNY(&tape, plaintext, views[k], params);
        //mpc_LowMC(&tape, views[k], plaintext, (uint32_t*)tmp, params);

        uint32_t temp[LOWMC_MAX_WORDS] = {0};
        xor_three(temp, views[k][0].outputShare, views[k][1].outputShare, views[k][2].outputShare, params->stateSizeBytes);
        
        if(Debug==0){
            fprintf(stdout,"Input Views:\n");
            fprintf(stdout, "\nView0 => {");
            for(uint32_t aux=0; aux < params->stateSizeBytes/4;aux++){
                fprintf(stdout, "%u",views[k][0].inputShare[aux]);
                if(aux != 3) fprintf(stdout, ",");
            }
            fprintf(stdout, "}\nView1 => {");
            for(uint32_t aux=0; aux < params->stateSizeBytes/4;aux++){
                fprintf(stdout, "%u",views[k][1].inputShare[aux]);
                if(aux != 3) fprintf(stdout, ",");
            }
            fprintf(stdout, "}\nView2 => {");
            for(uint32_t aux=0; aux < params->stateSizeBytes/4;aux++){
                fprintf(stdout, "%u",views[k][2].inputShare[aux]);
                if(aux != 3) fprintf(stdout, ",");
            } 
            fprintf(stdout,"}\n\nplaintext ==> {%u,%u,%u,%u}\n",plaintext[0],plaintext[1],plaintext[2],plaintext[3]); 
            fprintf(stdout,"\n\nOutput Views:\n");
            fprintf(stdout, "\nView0 => {");
            for(uint32_t aux=0; aux < params->stateSizeBytes/4;aux++){
                fprintf(stdout, "%u",views[k][0].outputShare[aux]);
                if(aux != 3) fprintf(stdout, ",");
            }
            fprintf(stdout, "}\nView1 => {");
            for(uint32_t aux=0; aux < params->stateSizeBytes/4;aux++){
                fprintf(stdout, "%u",views[k][1].outputShare[aux]);
                if(aux != 3) fprintf(stdout, ",");
            }
            fprintf(stdout, "}\nView2 => {");
            for(uint32_t aux=0; aux < params->stateSizeBytes/4;aux++){
                fprintf(stdout, "%u",views[k][2].outputShare[aux]);
                if(aux != 3) fprintf(stdout, ",");
            } 
            fprintf(stdout, "}\n\ncipher => {");
            for(uint32_t aux=0; aux < params->stateSizeBytes/4;aux++){
                fprintf(stdout, "%u",pubKey[aux]);
                if(aux != 3) fprintf(stdout, ",");
            } 
            size_t wholeWords = params->stateSizeBytes/sizeof(uint32_t);
            uint32_t output[wholeWords];
            uint32_t* in0 = (uint32_t*)views[k][0].outputShare;
            uint32_t* in1 = (uint32_t*)views[k][1].outputShare;
            uint32_t* in2 = (uint32_t*)views[k][2].outputShare;
            uint32_t* in3 = (uint32_t*)pubKey;

            fprintf(stdout, "}\n\n# -- Verificação -- #\n\n");
            for(size_t aux = 0; aux < wholeWords; aux++) {
                output[aux] = in0[aux] ^ in1[aux] ^ in2[aux];
                fprintf(stdout,"Obtido:   {%u = %u ^ %u ^ %u}\n",output[aux],in0[aux],in1[aux],in2[aux]);
                fprintf(stdout,"Objetivo: {%u = %u ^ %u ^ %u}\n\n",in3[aux],in0[aux],in1[aux],in2[aux]);
            }
            fprintf(stdout, "\n\n");
            fflush(stdout);  
        }

        if(memcmp(temp, pubKey, params->stateSizeBytes) != 0) {
            fprintf(stdout, "ERROU!!\n");
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
        }
        
    }

    //Generating challenges
    uint32_t** viewOutputs = malloc(params->numMPCRounds * 3 * sizeof(uint32_t*));
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        for (size_t j = 0; j < 3; j++) {
            VIEW_OUTPUTS(i, j) = views[i][j].outputShare;
        }
    }


    H3(pubKey, plaintext, viewOutputs, as,
       sig->challengeBits, sig->salt, message, messageByteLength, gs, params);

    //Packing Z
    for (size_t i = 0; i < params->numMPCRounds; i++) {
        proof_t* proof = &sig->proofs[i];
        prove(proof, getChallenge(sig->challengeBits, i), &seeds[i],
              views[i], &as[i], (gs == NULL) ? NULL : &gs[i], params);
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
                           params->numMPCRounds * (2 * params->seedSizeBytes + params->stateSizeBytes + params->andSizeBytes + params->digestSizeBytes);

    if (params->transform == TRANSFORM_UR) {
        bytesRequired += params->UnruhGWithoutInputBytes * params->numMPCRounds;
    }

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

        memcpy(sigBytes, proofs[i].view3Commitment, params->digestSizeBytes);
        sigBytes += params->digestSizeBytes;

        if (params->transform == TRANSFORM_UR) {
            size_t view3UnruhLength = (challenge == 0) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
            memcpy(sigBytes, proofs[i].view3UnruhG, view3UnruhLength);
            sigBytes += view3UnruhLength;
        }

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
                           params->numMPCRounds * (2 * params->seedSizeBytes + params->andSizeBytes + params->digestSizeBytes) + inputShareSize;

    if (params->transform == TRANSFORM_UR) {
        bytesExpected += params->UnruhGWithoutInputBytes * params->numMPCRounds;
    }
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

        memcpy(proofs[i].view3Commitment, sigBytes, params->digestSizeBytes);
        sigBytes += params->digestSizeBytes;

        if (params->transform == TRANSFORM_UR) {
            size_t view3UnruhLength = (challenge == 0) ? params->UnruhGWithInputBytes : params->UnruhGWithoutInputBytes;
            memcpy(proofs[i].view3UnruhG, sigBytes, view3UnruhLength);
            sigBytes += view3UnruhLength;
        }

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





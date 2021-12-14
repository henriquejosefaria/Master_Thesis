#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "utils.h"
//#include "hash.h"
//#include "thash.h"
#include "wots.h"
//#include "address.h"
//#include "params.h"
#include "picnic_types.h"

#define WOTS_W 16
#define WOTS_LOGW 4
#define HASH_SIZE 34

void gen_ur_wots_sk(unsigned char *sk, uint8_t* as1, uint8_t* as2, uint8_t* as3, uint8_t* gs1, uint8_t* gs2, uint8_t* gs3, unsigned char* previous_chain_value, uint32_t* privateKey, paramset_t* params){


    size_t inlen = params->digestSizeBytes * 7;

    if(previous_chain_value) inlen += HASH_SIZE;

    unsigned char *buf = malloc(inlen);
    memcpy(buf, privateKey, params->digestSizeBytes);
    memcpy(buf + params->digestSizeBytes, as1, params->digestSizeBytes);
    memcpy(buf + params->digestSizeBytes * 2, as2, params->digestSizeBytes);
    memcpy(buf + params->digestSizeBytes * 3, as3, params->digestSizeBytes);
    memcpy(buf + params->digestSizeBytes * 4, gs1, params->digestSizeBytes);
    memcpy(buf + params->digestSizeBytes * 5, gs2, params->digestSizeBytes);
    memcpy(buf + params->digestSizeBytes * 6, gs3, params->digestSizeBytes);

    if(previous_chain_value) memcpy(buf + params->digestSizeBytes * 7, previous_chain_value, HASH_SIZE);

    ascon_hash(sk, buf, inlen);
}

void gen_fs_wots_sk(unsigned char *sk, uint8_t* as1, uint8_t* as2, uint8_t* as3, unsigned char* previous_chain_value, uint32_t* privateKey, paramset_t* params){

    size_t inlen = params->digestSizeBytes * 4;

    if(previous_chain_value) inlen += HASH_SIZE;

    unsigned char *buf = malloc(inlen);
    memcpy(buf, privateKey, params->digestSizeBytes);
    memcpy(buf + params->digestSizeBytes, as1, params->digestSizeBytes);
    memcpy(buf + params->digestSizeBytes * 2, as2, params->digestSizeBytes);
    memcpy(buf + params->digestSizeBytes * 3, as3, params->digestSizeBytes);

    if(previous_chain_value) memcpy(buf + params->digestSizeBytes * 4, previous_chain_value, HASH_SIZE);

    ascon_hash(sk, buf, inlen);
}

void gen_chain(unsigned char* out, unsigned char* in, uint32_t start, uint32_t steps, uint32_t round)
{
    uint32_t i;
    size_t size_value = sizeof(uint32_t);
    unsigned char *buf = malloc(size_value * 2 + HASH_SIZE);

    memcpy(out,in,HASH_SIZE);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start+steps) && i < WOTS_W; i++) {
        
        memcpy(buf,out,HASH_SIZE);
        memcpy(buf + HASH_SIZE, &round, size_value);
        memcpy(buf + HASH_SIZE + size_value, &i, size_value);

        ascon_hash((unsigned char *)out, buf, size_value * 2 + HASH_SIZE);
    }
}

void gen_wots_pk_from_sig(unsigned char** wots_sig_pk, unsigned char** sig, uint32_t lengths[5], uint32_t round)
{
    for (int i = 0; i < 5; i++)
    {
        gen_chain(wots_sig_pk[round+i], sig[round+i], lengths[i], WOTS_W - lengths[i], round);
    }
}

void gen_wots_sig(unsigned char** wots_sig, unsigned char** sig, uint32_t lengths[5], uint32_t round)
{
    for (int i = 0; i < 5; i++)
    {
        gen_chain(wots_sig[round+i], sig[round+i], 0, lengths[i], round);
    }
}

void single_base_w(unsigned int *output, const unsigned char *input)
{

    unsigned char total;
    int bits = 0;

    total = input[0];
    bits += 8;

    bits -= WOTS_LOGW;
    (*output) = (total >> bits) & (WOTS_W - 1);
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(unsigned int *output, const int out_len,
                   const unsigned char *input)
{
    int in = 0;
    int out = 0;
    unsigned char total;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= WOTS_LOGW;
        output[out] = (total >> bits) & (WOTS_W - 1);
        out++;
    }
}


void get_lengths_verify(uint32_t lengths[5], unsigned char* views[5][3], size_t lenBytes){

    /*The buffer holds 3 views outputs per round after 5 rounds */
    unsigned char *buf = malloc(lenBytes * 15);
    unsigned char *secretValue = malloc(HASH_SIZE);


    for (int i = 0; i < 5; i++)
    {
        //printf("for round: %d\n",i );
        memcpy(buf + lenBytes * (i * 3)    , views[i][0], lenBytes);
        memcpy(buf + lenBytes * (i * 3 + 1), views[i][1], lenBytes);
        memcpy(buf + lenBytes * (i * 3 + 2), views[i][2], lenBytes);
    }
    //printf("did for\n");
    ascon_hash(secretValue, buf, lenBytes * 15);

    base_w(lengths,5,secretValue);

    lengths[3] = WOTS_W - lengths[3]; // checksum
    lengths[4] = WOTS_W - lengths[4]; // checksum
}


void get_lengths(uint32_t lengths[5], view_t** views, size_t lenBytes, uint32_t k){

    /*The buffer holds 3 views outputs per round after 5 rounds */
    unsigned char *buf = malloc(lenBytes * 15);
    unsigned char *secretValue = malloc(HASH_SIZE);


    for (int i = 0; i < 5; i++)
    {
        memcpy(buf + lenBytes * (i * 3)    , views[k+i][0].outputShare, lenBytes);
        memcpy(buf + lenBytes * (i * 3 + 1), views[k+i][1].outputShare, lenBytes);
        memcpy(buf + lenBytes * (i * 3 + 2), views[k+i][2].outputShare, lenBytes);
    }

    ascon_hash(secretValue, buf, lenBytes * 15);

    base_w(lengths,5,secretValue);

    lengths[3] = WOTS_W - lengths[3]; // checksum
    lengths[4] = WOTS_W - lengths[4]; // checksum
}

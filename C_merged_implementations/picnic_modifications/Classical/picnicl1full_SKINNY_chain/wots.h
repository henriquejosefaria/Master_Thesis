#ifndef SPX_WOTS_H
#define SPX_WOTS_H

#include <stdint.h>
#include "picnic_types.h"
//#include "params.h"

void gen_wots_pk_from_sig(unsigned char** wots_sig_pk, unsigned char** sig, uint32_t lengths[5], uint32_t round);

void gen_wots_sig(unsigned char** wots_sig, unsigned char** sig, uint32_t lengths[5], uint32_t round);

void get_lengths_verify(uint32_t lengths[5], unsigned char* views[5][3], size_t lenBytes);

void get_lengths(uint32_t lengths[5], view_t** views, size_t lenBytes, uint32_t k);

void gen_fs_wots_sk(unsigned char *sk, uint8_t* as1, uint8_t* as2, uint8_t* as3, unsigned char* previous_chain_value, uint32_t* privateKey, paramset_t* params);

void gen_ur_wots_sk(unsigned char *sk, uint8_t* as1, uint8_t* as2, uint8_t* as3, uint8_t* gs1, uint8_t* gs2, uint8_t* gs3, unsigned char* previous_chain_value, uint32_t* privateKey, paramset_t* params);


#endif

#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

#include "api.h"
#include "permutations.h"
#include "picnic_types.h"

//#define DEBUG
#define RATE (64 / 8)
#define PA_ROUNDS 12
//#define CRYPTO_BYTES 32
#define IV                                            \
  ((u64)(8 * (RATE)) << 48 | (u64)(PA_ROUNDS) << 40 | \
   (u64)(8 * (CRYPTO_BYTES)) << 0)


uint64_t getByte(const uint32_t* array, uint32_t bitNumber)
{   
    uint64_t byte;
    memcpy(&byte,&array[bitNumber],sizeof(byte));
    return byte;  // (array[bitNumber / 8] >> (7 - (bitNumber % 8))) & 0x01;
}

uint64_t getRandByte(const uint8_t* array, uint32_t bitNumber)
{  
    uint64_t byte;
    memcpy(&byte,&array[bitNumber],sizeof(byte));
    return byte;  // (array[bitNumber / 8] >> (7 - (bitNumber % 8))) & 0x01;
}

/* Set a specific bit in a byte array to a given value */
void setASCONBit(uint8_t* bytes, uint32_t bitNumber, uint64_t val)
{ 
  uint8_t *p = (uint8_t *)&val;
  /*
  for(uint8_t i = 0; i < 8; i++){
    bytes[bitNumber+i] = p[i];
  }*/
  bytes[bitNumber / 8] = (bytes[bitNumber >> 3] & ~(1 << (7 - (bitNumber % 8)))) | (p[0] << (7 - (bitNumber % 8)));
  //bytes[bitNumber / 8] = (bytes[bitNumber >> 3] & ~(1 << (7 - (bitNumber % 8)))) | (val << (7 - (bitNumber % 8)));
}

/*

  MPC_ASCON VERIFY HASH FUNCTIONS
*/

static inline void permutationAND_verify(state* t[2], state* states[2], randomTape_t* rand, view_t views[2]){
  /* AND CALCULATIONS
    t.x0 &= s.x1;
    t.x1 &= s.x2;
    t.x2 &= s.x3;
    t.x3 &= s.x4;
    t.x4 &= s.x0;
  */
  uint64_t r[2] = { getRandByte(rand->tape[0], rand->pos), getRandByte(rand->tape[1], rand->pos) };

  for (uint8_t i = 0; i < 2; i++) {

      t[i]->x0 = (t[i]->x0 & states[(i + 1) % 3]->x1) ^ (t[(i + 1) % 3]->x0 & states[i]->x1) ^ (t[i]->x0 & states[i]->x1) ^ r[i] ^ r[(i + 1) % 3];
      t[i]->x1 = (t[i]->x1 & states[(i + 1) % 3]->x2) ^ (t[(i + 1) % 3]->x1 & states[i]->x2) ^ (t[i]->x1 & states[i]->x2) ^ r[i] ^ r[(i + 1) % 3];
      t[i]->x2 = (t[i]->x2 & states[(i + 1) % 3]->x3) ^ (t[(i + 1) % 3]->x2 & states[i]->x3) ^ (t[i]->x2 & states[i]->x3) ^ r[i] ^ r[(i + 1) % 3];
      t[i]->x3 = (t[i]->x3 & states[(i + 1) % 3]->x4) ^ (t[(i + 1) % 3]->x3 & states[i]->x4) ^ (t[i]->x3 & states[i]->x4) ^ r[i] ^ r[(i + 1) % 3];
      t[i]->x4 = (t[i]->x4 & states[(i + 1) % 3]->x0) ^ (t[(i + 1) % 3]->x4 & states[i]->x0) ^ (t[i]->x4 & states[i]->x0) ^ r[i] ^ r[(i + 1) % 3];

      setASCONBit(views[i].communicatedBits, rand->pos, t[i]->x0);
  }

  (rand->pos)++;

}


// REPLACE p for states

static inline void ROUND_verify(u8 C, state* states[2], randomTape_t* tapes, view_t* views[2]) {
  //state s = *p;
  state* t[2];
  // addition of round constant
  for(uint8_t i = 0; i < 2 ; i++){

    states[i]->x2 ^= C;
    //printstates(" addition of round constant:", states);
    // substitution layer
    states[i]->x0 ^= states[i]->x4;
    states[i]->x4 ^= states[i]->x3;
    states[i]->x2 ^= states[i]->x1;
    // start of keccak s-box
    t[i]->x0 = ~states[i]->x0;
    t[i]->x1 = ~states[i]->x1;
    t[i]->x2 = ~states[i]->x2;
    t[i]->x3 = ~states[i]->x3;
    t[i]->x4 = ~states[i]->x4;

    permutationAND_verify(t,states,tapes,*views);

    states[i]->x0 ^= t[i]->x1;
    states[i]->x1 ^= t[i]->x2;
    states[i]->x2 ^= t[i]->x3;
    states[i]->x3 ^= t[i]->x4;
    states[i]->x4 ^= t[i]->x0;
    // end of keccak s-box
    states[i]->x1 ^= states[i]->x0;
    states[i]->x0 ^= states[i]->x4;
    states[i]->x3 ^= states[i]->x2;
    states[i]->x2 = ~states[i]->x2;
    //printstates(" substitution layer:", states);
    // linear diffusion layer
    states[i]->x0 ^= ROTR64(states[i]->x0, 19) ^ ROTR64(states[i]->x0, 28);
    states[i]->x1 ^= ROTR64(states[i]->x1, 61) ^ ROTR64(states[i]->x1, 39);
    states[i]->x2 ^= ROTR64(states[i]->x2, 1) ^ ROTR64(states[i]->x2, 6);
    states[i]->x3 ^= ROTR64(states[i]->x3, 10) ^ ROTR64(states[i]->x3, 17);
    states[i]->x4 ^= ROTR64(states[i]->x4, 7) ^ ROTR64(states[i]->x4, 41);
    //printstates(" linear diffusion layer:", states);

  }

}

static inline void P12_verify(state* states[2], randomTape_t* tapes, view_t* views[2]) {
  //printstates(" permutation input:", states);
  for(int i=0; i<2;i++){
    ROUND_verify(0xf0, states, tapes, views);
    ROUND_verify(0xe1, states, tapes, views);
    ROUND_verify(0xd2, states, tapes, views);
    ROUND_verify(0xc3, states, tapes, views);
    ROUND_verify(0xb4, states, tapes, views);
    ROUND_verify(0xa5, states, tapes, views);
    ROUND_verify(0x96, states, tapes, views);
    ROUND_verify(0x87, states, tapes, views);
    ROUND_verify(0x78, states, tapes, views);
    ROUND_verify(0x69, states, tapes, views);
    ROUND_verify(0x5a, states, tapes, views);
    ROUND_verify(0x4b, states, tapes, views);
  }
}


/* 
  out   => views.outputShare
  in    => views.inputShare
  inlen => sizeof(views.inputShare) * 4 -> porque estamos a trabalhar com uint32_t (4 bytes por posição)
  rand => tapes
  views => views
*/
void mpc_ASCON_verify(view_t* view1, view_t* view2, randomTape_t* tapes){
  
  u64 outlen;
  view_t *in[2] = { view1, view2 };
  int inlen = sizeof(view1->inputShare)/2;
  // 1 uint32_t são 4 u8 (u8 <=> uint8_t)

  // initialization
  state *states[2];
  for(int i=0;i<2;i++){
    states[i]->x0 = IV;
    states[i]->x1 = 0;
    states[i]->x2 = 0;
    states[i]->x3 = 0;
    states[i]->x4 = 0;
    //printstates("initial value:", states);
  }
  P12_verify(states, tapes, in);
  //printstates("initialization:", states);
  
  
  // absorb plaintext
  
  while (inlen >= RATE) {
      for(int i=0;i<2;i++){
        states[i]->x0 ^= BYTES_TO_U64((uint8_t *)in[i]->inputShare, 8);
        (in[i]->inputShare)+=2;  //in += RATE;
      }
      P12_verify(states, tapes, in);
      inlen--;  //inlen -= RATE;
  }
  for(int i=0;i<2;i++){
    states[i]->x0 ^= BYTES_TO_U64((uint8_t *)in[i]->inputShare, inlen);
    states[i]->x0 ^= 0x80ull << (56 - 8 * inlen);
    //printstate("absorb plaintext:", states[i]);
  }
  P12_verify(states, tapes, in);
  //printstates("finalization:", states);

  // set hash output
  outlen = CRYPTO_BYTES;
  uint64_t *out[2] = { (uint64_t *) view1->outputShare, (uint64_t *) view2->outputShare };
  while (outlen > RATE) {
    for(int i=0;i<2;i++){
      memcpy(out[i], &states[i]->x0, 8);
      (*out[i])++; //out += RATE;
    }
    P12_verify(states, tapes, in);
    outlen -= RATE; //outlen -=RATE;
  }
  for(int i=0;i<2;i++){
    memcpy(out[i], &states[i]->x0, 8);
  }
}

/*

  MPC_ASCON HASH FUNCTIONS
*/

static inline void permutationAND(state* t[3], state* states[3], randomTape_t* rand, view_t views[3]){
  /* AND CALCULATIONS
    t.x0 &= s.x1;
    t.x1 &= s.x2;
    t.x2 &= s.x3;
    t.x3 &= s.x4;
    t.x4 &= s.x0;
  */
  uint64_t r[3] = { getRandByte(rand->tape[0], rand->pos), getRandByte(rand->tape[1], rand->pos), getRandByte(rand->tape[2], rand->pos) };

  for (uint8_t i = 0; i < 3; i++) {

      t[i]->x0 = (t[i]->x0 & states[(i + 1) % 3]->x1) ^ (t[(i + 1) % 3]->x0 & states[i]->x1) ^ (t[i]->x0 & states[i]->x1) ^ r[i] ^ r[(i + 1) % 3];
      t[i]->x1 = (t[i]->x1 & states[(i + 1) % 3]->x2) ^ (t[(i + 1) % 3]->x1 & states[i]->x2) ^ (t[i]->x1 & states[i]->x2) ^ r[i] ^ r[(i + 1) % 3];
      t[i]->x2 = (t[i]->x2 & states[(i + 1) % 3]->x3) ^ (t[(i + 1) % 3]->x2 & states[i]->x3) ^ (t[i]->x2 & states[i]->x3) ^ r[i] ^ r[(i + 1) % 3];
      t[i]->x3 = (t[i]->x3 & states[(i + 1) % 3]->x4) ^ (t[(i + 1) % 3]->x3 & states[i]->x4) ^ (t[i]->x3 & states[i]->x4) ^ r[i] ^ r[(i + 1) % 3];
      t[i]->x4 = (t[i]->x4 & states[(i + 1) % 3]->x0) ^ (t[(i + 1) % 3]->x4 & states[i]->x0) ^ (t[i]->x4 & states[i]->x0) ^ r[i] ^ r[(i + 1) % 3];

      setASCONBit(views[i].communicatedBits, rand->pos, t[i]->x0);
  }

  (rand->pos)++;

}


// REPLACE p for states

static inline void ROUND(u8 C, state* states[3], randomTape_t* tapes, view_t views[3]) {
  //state s = *p;
  state* t[3];
  // addition of round constant
  for(uint8_t i = 0; i < 3 ; i++){

    states[i]->x2 ^= C;
    //printstate(" addition of round constant:", states[i]);
    // substitution layer
    states[i]->x0 ^= states[i]->x4;
    states[i]->x4 ^= states[i]->x3;
    states[i]->x2 ^= states[i]->x1;
    // start of keccak s-box
    t[i]->x0 = ~states[i]->x0;
    t[i]->x1 = ~states[i]->x1;
    t[i]->x2 = ~states[i]->x2;
    t[i]->x3 = ~states[i]->x3;
    t[i]->x4 = ~states[i]->x4;

    permutationAND(t,states,tapes,views);

    states[i]->x0 ^= t[i]->x1;
    states[i]->x1 ^= t[i]->x2;
    states[i]->x2 ^= t[i]->x3;
    states[i]->x3 ^= t[i]->x4;
    states[i]->x4 ^= t[i]->x0;
    // end of keccak s-box
    states[i]->x1 ^= states[i]->x0;
    states[i]->x0 ^= states[i]->x4;
    states[i]->x3 ^= states[i]->x2;
    states[i]->x2 = ~states[i]->x2;
    //printstate(" substitution layer:", states[i]);
    // linear diffusion layer
    states[i]->x0 ^= ROTR64(states[i]->x0, 19) ^ ROTR64(states[i]->x0, 28);
    states[i]->x1 ^= ROTR64(states[i]->x1, 61) ^ ROTR64(states[i]->x1, 39);
    states[i]->x2 ^= ROTR64(states[i]->x2, 1) ^ ROTR64(states[i]->x2, 6);
    states[i]->x3 ^= ROTR64(states[i]->x3, 10) ^ ROTR64(states[i]->x3, 17);
    states[i]->x4 ^= ROTR64(states[i]->x4, 7) ^ ROTR64(states[i]->x4, 41);
    //printstate(" linear diffusion layer:", states[i]);

  }
}

static inline void P12(state* states[3], randomTape_t* tapes, view_t views[3]) {
  //printstate(" permutation input:", states);
  ROUND(0xf0, states, tapes, views);
  ROUND(0xe1, states, tapes, views);
  ROUND(0xd2, states, tapes, views);
  ROUND(0xc3, states, tapes, views);
  ROUND(0xb4, states, tapes, views);
  ROUND(0xa5, states, tapes, views);
  ROUND(0x96, states, tapes, views);
  ROUND(0x87, states, tapes, views);
  ROUND(0x78, states, tapes, views);
  ROUND(0x69, states, tapes, views);
  ROUND(0x5a, states, tapes, views);
  ROUND(0x4b, states, tapes, views);
}


/* 
  out   => views.outputShare
  in    => views.inputShare
  inlen => sizeof(views.inputShare) * 4 -> porque estamos a trabalhar com uint32_t (4 bytes por posição)
  rand => tapes
  views => views
*/
void mpc_ASCON(randomTape_t* tapes, view_t views[3]){
  printf("Entered ASCON!!");
  u64 outlen;
  printf("Starting states!!");
  // initialization
  state *states[3];
  for(int i=0;i<3;i++){
    states[i]->x0 = IV;
    states[i]->x1 = 0;
    states[i]->x2 = 0;
    states[i]->x3 = 0;
    states[i]->x4 = 0;
    //printstate("initial value:", states[i]);
    //printstate("initialization:", states[i]);
  }
  printf("Starting Permutation 1!!");
  P12(states, tapes, views);
  
  
  printf("Starting Absortion!!");
  // absorb plaintext
  int inlen = sizeof(views[0].inputShare)/2;
  // 1 uint32_t são 4 u8 (u8 <=> uint8_t)
  view_t *in[3] = { &views[0], &views[1], &views[2] };
  
  while (inlen >= RATE) {
      printf("Absorbing....");
      for(int i=0;i<3;i++){
        states[i]->x0 ^= BYTES_TO_U64((uint8_t *)in[i]->inputShare, 8);
        (in[i]->inputShare)+=2;;  //in += RATE;
      }
      P12(states, tapes, views);
      inlen--;  //inlen -= RATE;
  }
  printf("Absorbing last block of the message....");
  for(int i=0;i<3;i++){
    states[i]->x0 ^= BYTES_TO_U64((uint8_t *)in[i]->inputShare, inlen);
    states[i]->x0 ^= 0x80ull << (56 - 8 * inlen);
    //printstate("absorb plaintext:", states[i]);
  }
  printf("Permutating the last block of the message....");
  P12(states, tapes, views);
  //printstate("finalization:", states[i]);

  // set hash output
  outlen = CRYPTO_BYTES;
  uint32_t *out[3] = { views[0].outputShare, views[1].outputShare, views[2].outputShare };
  while (outlen > RATE) {
    for(int i=0;i<3;i++){
      memcpy(out[i], &states[i]->x0, 8);
      (*out[i]) += 2; //out += RATE;
    }
    P12(states, tapes, views);
    outlen -= RATE; //outlen -=RATE;
  }
  for(int i=0;i<3;i++){
    memcpy(out[i], &states[i]->x0, 8);
  }
}

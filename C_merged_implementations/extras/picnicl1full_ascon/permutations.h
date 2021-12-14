#ifndef PERMUTATIONS_H_
#define PERMUTATIONS_H_

#ifdef DEBUG
#include <stdio.h>
#endif

typedef unsigned char u8;
typedef unsigned long long u64;

typedef struct {
  u64 x0, x1, x2, x3, x4;
} state;

#define RATE (64 / 8)

#define PA_ROUNDS 12

#define IV                                            \
  ((u64)(8 * (RATE)) << 48 | (u64)(PA_ROUNDS) << 40 | \
   (u64)(8 * (CRYPTO_BYTES)) << 0)

static inline void printstates(const char* text, const state* s[2]) {
#ifdef DEBUG
  for(int i =0; i<3; i++){
    printf("%s\n", text);
    printf("  x0=%016llx\n", s[i].x0);
    printf("  x1=%016llx\n", s[i].x1);
    printf("  x2=%016llx\n", s[i].x2);
    printf("  x3=%016llx\n", s[i].x3);
    printf("  x4=%016llx\n", s[i].x4);

  }
  
#else
  // disable warning about unused parameters
  (void)text;
  (void)s;
#endif
}

static inline u64 BYTES_TO_U64(const u8* bytes, int n) {
  int i;
  u64 x = 0;
  for (i = 0; i < n; i++) x |= ((u64)bytes[i]) << (56 - 8 * i);
  return x;
}

static inline void U64_TO_BYTES(u8* bytes, const u64 x, int n) {
  int i;
  for (i = 0; i < n; i++) bytes[i] = (u8)(x >> (56 - 8 * i));
}

static inline u64 BYTE_MASK(int n) {
  int i;
  u64 x = 0;
  for (i = 0; i < n; i++) x |= 0xffull << (56 - 8 * i);
  return x;
}

static inline u64 ROTR64(u64 x, int n) { return (x << (64 - n)) | (x >> n); }
/*
static inline void ROUND(u8 C, state* s[3]) {
  //state s[3] = *p;
  state* t[3];
  uint8_t r[3] = { getBit(rand->tape[0], rand->pos), getBit(rand->tape[1], rand->pos), getBit(rand->tape[2], rand->pos) };
  for(int i=0; i<3; i++){
    // addition of round constant
    s[i].x2 ^= C;
    printstates(" addition of round constant:", s);
    // substitution layer
    s[i].x0 ^= s[i].x4;
    s[i].x4 ^= s[i].x3;
    s[i].x2 ^= s[i].x1;
    // start of keccak s-box
    t[i].x0 = ~s[i].x0;
    t[i].x1 = ~s[i].x1;
    t[i].x2 = ~s[i].x2;
    t[i].x3 = ~s[i].x3;
    t[i].x4 = ~s[i].x4;
  }


  // AND GATES

  t.x0 &= s.x1;
  t.x1 &= s.x2;
  t.x2 &= s.x3;
  t.x3 &= s.x4;
  t.x4 &= s.x0; 




  (rand->pos)++;


  for(int i=0; i<3; i++){
    s[i].x0 ^= t[i].x1;
    s[i].x1 ^= t[i].x2;
    s[i].x2 ^= t[i].x3;
    s[i].x3 ^= t[i].x4;
    s[i].x4 ^= t[i].x0;
    // end of keccak s-box
    s[i].x1 ^= s[i].x0;
    s[i].x0 ^= s[i].x4;
    s[i].x3 ^= s[i].x2;
    s[i].x2 = ~s[i].x2;
    printstate(" substitution layer:", s);
    // linear diffusion layer
    s[i].x0 ^= ROTR64(s[i].x0, 19) ^ ROTR64(s[i].x0, 28);
    s[i].x1 ^= ROTR64(s[i].x1, 61) ^ ROTR64(s[i].x1, 39);
    s[i].x2 ^= ROTR64(s[i].x2, 1 ) ^ ROTR64(s[i].x2, 6);
    s[i].x3 ^= ROTR64(s[i].x3, 10) ^ ROTR64(s[i].x3, 17);
    s[i].x4 ^= ROTR64(s[i].x4, 7 ) ^ ROTR64(s[i].x4, 41);
    printstate(" linear diffusion layer:", s);
    *p = s;
  }
}

static inline void P12(state* s[3], view_t views[3], randomTape_t* tapes) {
  printstate(" permutation input:", *s);
  ROUND(0xf0, s);
  ROUND(0xe1, s);
  ROUND(0xd2, s);
  ROUND(0xc3, s);
  ROUND(0xb4, s);
  ROUND(0xa5, s);
  ROUND(0x96, s);
  ROUND(0x87, s);
  ROUND(0x78, s);
  ROUND(0x69, s);
  ROUND(0x5a, s);
  ROUND(0x4b, s);
}

static inline void P8(state* s) {
  printstate(" permutation input:", *s);
  ROUND(0xb4, s);
  ROUND(0xa5, s);
  ROUND(0x96, s);
  ROUND(0x87, s);
  ROUND(0x78, s);
  ROUND(0x69, s);
  ROUND(0x5a, s);
  ROUND(0x4b, s);
}

static inline void P6(state* s) {
  printstate(" permutation input:", *s);
  ROUND(0x96, s);
  ROUND(0x87, s);
  ROUND(0x78, s);
  ROUND(0x69, s);
  ROUND(0x5a, s);
  ROUND(0x4b, s);
}
*/
#endif  // PERMUTATIONS_H_


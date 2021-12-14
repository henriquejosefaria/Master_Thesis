#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "api.h"
#include "params.h"
#include "wots.h"
#include "fors.h"
#include "hash.h"
#include "thash.h"
#include "address.h"
#include "rng.h"
#include "utils.h"

#define SPX_MLEN 32

/**
 * Computes the leaf at a given address. First generates the WOTS key pair,
 * then computes leaf by hashing horizontally.
 */
static void wots_gen_leaf(unsigned char *leaf, const unsigned char *sk_seed,
                          const unsigned char *pub_seed,
                          uint32_t addr_idx, const uint32_t tree_addr[8])
{
    unsigned char pk[SPX_WOTS_BYTES];
    uint32_t wots_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, addr_idx);
    wots_gen_pk(pk, sk_seed, pub_seed, wots_addr);

    copy_keypair_addr(wots_pk_addr, wots_addr);
    thash(leaf, pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);
}

/*
 * Returns the length of a secret key, in bytes
 */
unsigned long long crypto_sign_secretkeybytes(void)
{
    return CRYPTO_SECRETKEYBYTES;
}

/*
 * Returns the length of a public key, in bytes
 */
unsigned long long crypto_sign_publickeybytes(void)
{
    return CRYPTO_PUBLICKEYBYTES;
}

/*
 * Returns the length of a signature, in bytes
 */
unsigned long long crypto_sign_bytes(void)
{
    return CRYPTO_BYTES;
}

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
unsigned long long crypto_sign_seedbytes(void)
{
    return CRYPTO_SEEDBYTES;
}

/*
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed)
{
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT * SPX_N];
    uint32_t top_tree_addr[8] = {0};

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_type(top_tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES);

    memcpy(pk, sk + 2*SPX_N, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pk, sk);

    /* Compute root node of the top-most subtree. */
    treehash(sk + 3*SPX_N, auth_path, sk, sk + 2*SPX_N, 0, 0, SPX_TREE_HEIGHT,
             wots_gen_leaf, top_tree_addr);

    memcpy(pk + SPX_N, sk + 3*SPX_N, SPX_N);

    return 0;
}

/*
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
  unsigned char seed[CRYPTO_SEEDBYTES];
  randombytes(seed, CRYPTO_SEEDBYTES);
  crypto_sign_seed_keypair(pk, sk, seed);

  return 0;
}


/******************** ADDED FUNCTIONS ********************/


bool check_message_indices(bool *unchecked_indices, uint32_t *target_leaves, uint32_t *self_leaves, const unsigned char *m)
{
    unsigned int i, j;
    unsigned int offset = 0;
    bool ret = false;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        self_leaves[i] = 0; 
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            self_leaves[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
            offset++;
        }
        if(self_leaves[i] == target_leaves[i] && unchecked_indices[i]){
            ret = true;
        }
    }
    return ret;
}

/**
 * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 * Assumes indices has space for SPX_FORS_TREES integers.
 */
void my_message_to_indices(bool *unchecked_indices, uint32_t *indices, const unsigned char *m)
{
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        unchecked_indices[i] = true;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
            offset++;
        }
    }
}


/**
 * Returns an array containing a detached forged signature.
 */
int attack_function(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    /* GENERIC PREPARATIONS */

    const unsigned char *sk_seed = sk;
    const unsigned char *sk_prf = sk + SPX_N;
    const unsigned char *pk = sk + 2*SPX_N;
    const unsigned char *pub_seed = pk;


    unsigned char optrand[SPX_N];
    unsigned char mhash [SPX_FORS_MSG_BYTES];
    unsigned char root[SPX_N];
    unsigned long long i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pub_seed, sk_seed);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);


    /* GENERATING R and storing it in the signature sig */

    randombytes(optrand, SPX_N);
    memcpy(sig,optrand,SPX_N);

    /* -- */

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);


    /* Obtaining target leafs on each FORS's tree */

    uint32_t target_leaves[SPX_FORS_TREES];
    uint32_t self_leaves[SPX_FORS_TREES];
    bool unchecked_indexes[SPX_FORS_TREES];

    my_message_to_indices(unchecked_indexes,target_leaves, mhash);

    int counter = 0;

    /* Stores the R + the fors signature + hypertree signature */
    uint8_t *fors_sig = malloc(SPX_BYTES + SPX_MLEN);
    uint8_t *tree_signatures[SPX_FORS_TREES];


    unsigned char *m_fake = malloc(SPX_MLEN);
    uint64_t tree2;
    uint32_t idx_leaf2;

    while(counter < SPX_FORS_TREES){

        /*Generates collision message */
        randombytes(m_fake, SPX_MLEN);
        /* Generates random R */
        randombytes(optrand, SPX_N);

        /* Oracle computation on the sent message to be signed - Compute the digest randomization value. */
        gen_message_random(fors_sig, sk_prf, optrand, m_fake, SPX_MLEN);
        
        /* Obtaining collision digest */
        hash_message(mhash, &tree2, &idx_leaf2, fors_sig, pk, m_fake, mlen);

        if(tree == tree2 && idx_leaf == idx_leaf2){
            
            /* If it returned true, at least one index is part of the signature to be forged and is not yet owned */
            if(check_message_indices(unchecked_indexes, target_leaves, self_leaves, mhash)){
                
                /*oracle FORS signature generation */
                fors_sign(fors_sig, root, mhash, sk_seed, pub_seed, wots_addr);

                /* Pass the R value */
                fors_sig += SPX_N;

                /*Check for every tree if it has the index we are looking for */
                for(int index = 0; index < SPX_FORS_TREES; index++ ){
                    if(self_leaves[index] == target_leaves[index] && unchecked_indexes[index] == true){

                        unchecked_indexes[index] = false;

                        /* allocate tree signature size (SK + AUTH) */
                        tree_signatures[index] = malloc(SPX_N + SPX_N * SPX_FORS_HEIGHT);

                        /* copy tree signature to the allocated space */
                        memcpy(tree_signatures[index],fors_sig + index * (SPX_N + SPX_N * SPX_FORS_HEIGHT), SPX_N + SPX_N * SPX_FORS_HEIGHT);

                        counter += 1;
                    }
                }
            }
        } 
    }
    
    /* Copy the found signatures */
    for(int index = 0; index < SPX_FORS_TREES; index++ ){
        memcpy(sig,tree_signatures[index],SPX_N + SPX_N * SPX_FORS_HEIGHT);
        sig += SPX_N + SPX_N * SPX_FORS_HEIGHT;
    }

    /* retireve the Hypertree signature from the last message sent to the oracle (can be from any message
     sent ot the oracle) */

    fors_sig += SPX_FORS_BYTES;



    /* Oracle hypertree signature generation */

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        /* Compute a WOTS signature. */
        wots_sign(fors_sig, root, sk_seed, pub_seed, wots_addr);
        fors_sig += SPX_WOTS_BYTES;

        /* Compute the authentication path for the used WOTS leaf. */
        treehash(root, fors_sig, sk_seed, pub_seed, idx_leaf, 0,
                 SPX_TREE_HEIGHT, wots_gen_leaf, tree_addr);
        fors_sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    memcpy(sig,fors_sig,(SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N) * SPX_D);

    *siglen = SPX_BYTES;

    return 0;
}



/******************** ADDED FUNCTIONS ********************/



/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    const unsigned char *sk_seed = sk;
    const unsigned char *sk_prf = sk + SPX_N;
    const unsigned char *pk = sk + 2*SPX_N;
    const unsigned char *pub_seed = pk;

    unsigned char optrand[SPX_N];
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char root[SPX_N];
    unsigned long long i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pub_seed, sk_seed);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes(optrand, SPX_N);
    /* Compute the digest randomization value. */
    gen_message_random(sig, sk_prf, optrand, m, mlen);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign(sig, root, mhash, sk_seed, pub_seed, wots_addr);
    sig += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        /* Compute a WOTS signature. */
        wots_sign(sig, root, sk_seed, pub_seed, wots_addr);
        sig += SPX_WOTS_BYTES;

        /* Compute the authentication path for the used WOTS leaf. */
        treehash(root, sig, sk_seed, pub_seed, idx_leaf, 0,
                 SPX_TREE_HEIGHT, wots_gen_leaf, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    *siglen = SPX_BYTES;

    return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    const unsigned char *pub_seed = pk;
    const unsigned char *pub_root = pk + SPX_N;
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char wots_pk[SPX_WOTS_BYTES];
    unsigned char root[SPX_N];
    unsigned char leaf[SPX_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != SPX_BYTES) {
        return -1;
    }

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pub_seed, NULL);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen);
    sig += SPX_N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, pub_seed, wots_addr);
    sig += SPX_FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig(wots_pk, sig, root, pub_seed, wots_addr);
        sig += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     pub_seed, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N)) {
        return -1;
    }

    return 0;
}


/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk)
{
    size_t siglen;

    crypto_sign_signature(sm, &siglen, m, (size_t)mlen, sk);

    memmove(sm + SPX_BYTES, m, mlen);
    *smlen = siglen + mlen;

    return 0;
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if (smlen < SPX_BYTES) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - SPX_BYTES;

    if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, (size_t)*mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(m, sm + SPX_BYTES, *mlen);

    return 0;
}

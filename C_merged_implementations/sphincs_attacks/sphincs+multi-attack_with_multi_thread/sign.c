#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <math.h>

// Library - threads
#include <pthread.h>

#include "api.h"
#include "params.h"
#include "wots.h"
#include "fors.h"
#include "hash.h"
#include "thash.h"
#include "address.h"
#include "rng.h"
#include "utils.h"

#define THREAD_NUMBER 4

typedef struct {
    unsigned char *m_fake;
    unsigned char *r;
} forgery;

typedef struct {
    bool found_collision;
    uint32_t target_leaves[SPX_FORS_TREES];
    bool unchecked_indexes[SPX_FORS_TREES];
    uint8_t *tree_signatures[SPX_FORS_TREES];
} XMSS_LEAVES;


typedef struct {
    uint8_t *ht_sig;
} Hypersigs;

struct info {
    const unsigned char *sk_seed;
    const unsigned char *sk_prf;
    const unsigned char *pk;
    const unsigned char *pub_seed;
    uint64_t tree;
    uint32_t idx_leaf;
    size_t mlen;
};

pthread_mutex_t lock;

/* Stores the messages being forged and the respective R. */
forgery messages[collisions];

/* Stores all the FORS tree leaves used of all the WOTS+ key pairs chosen to be compromised. */
XMSS_LEAVES target_tree_leaves[collisions];

/* Stores the Hypertree signatures of the messages to be forged. */
Hypersigs hyper_storage[collisions];

/*The counter indicates the amount of messages to be forged besides the original one. 
After it reaches 0 it becomes the number of collisions found for all messages. */
int counter = collisions-1;


/* Is only used to check if we have alredy chosen the message to be forged for a specific WOTS+ key pair. */
bool message_found[collisions];

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
        unchecked_indices[i] = true;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
            offset++;
        }
    }
}

void *collisions_finder(void *data){

    struct info *info = data;

    const unsigned char *sk_seed;
    const unsigned char *sk_prf;
    const unsigned char *pk;
    const unsigned char *pub_seed;
    uint64_t tree;
    uint32_t idx_leaf;
    size_t mlen;

    sk_seed = info->sk_seed;
    sk_prf = info->sk_prf;
    pk = info->pk;
    pub_seed = info->pub_seed;
    tree = info->tree;
    idx_leaf = info->idx_leaf;
    mlen = info->mlen;

    unsigned char optrand[SPX_N];
    unsigned char mhash [SPX_FORS_MSG_BYTES];
    unsigned char root[SPX_N];
    uint32_t wots_addr[8] = {0};
    uint32_t wots_addr_aux[8] = {0};
    uint32_t tree_addr[8] = {0};

    int i;

    /* Stores each message generated */
    unsigned char *m_fake = malloc(SPX_MLEN);
    
    /* Stores the used leaves in the FORS's tree signatures of each message. */
    uint32_t self_leaves[SPX_FORS_TREES];

    /* Stores R + the FORS signatures + the Hypertree signature. */
    uint8_t *fors_sig = malloc(SPX_BYTES + SPX_MLEN);
    uint8_t *fors_sig2 = fors_sig;
    uint8_t *ht_sig;


    uint64_t tree2;
    uint32_t idx_leaf2;
    uint32_t idx_leaf_aux;

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);


    while(counter > 0){

        /*Generates tree collision message */
        randombytes(m_fake, SPX_MLEN);
        /* Generates random R  and store it in the signature */
        randombytes(optrand, SPX_N);
        memcpy(fors_sig,optrand,SPX_N);

        /* Obtaining collision digest */
        hash_message(mhash, &tree2, &idx_leaf2, fors_sig, pk, m_fake, SPX_MLEN);

        pthread_mutex_lock(&lock);
        if(tree == tree2 & message_found[idx_leaf2] == false){

            message_found[idx_leaf2] = true;
            pthread_mutex_unlock(&lock);

            /*Store the new message and R and check it as found */
            memcpy(messages[idx_leaf2].m_fake,m_fake,SPX_MLEN);
            memcpy(messages[idx_leaf2].r,optrand,SPX_N); 
            
            /* Storing the leaves each mesage uses on its FORS's tree signatures. */
            target_tree_leaves[idx_leaf2].found_collision = false;
            my_message_to_indices(target_tree_leaves[idx_leaf2].unchecked_indexes,target_tree_leaves[idx_leaf2].target_leaves, mhash);

            /*Updating the counter - we found another message we wanted to forge. */
            counter -= 1;

        }
        pthread_mutex_unlock(&lock);
    }
    

    /*needs to find 33 FORS tree collisions for X signatures */
    int total_collisions = SPX_FORS_TREES * collisions;

    /*
    Finding collisions for the chosen WOTS+ key pairs and querying the oracle about them. 
    The hypertree signature is simulated only for the first collision of each WOTS+ key pair as its the same for all.
    */
    while(counter < total_collisions){
        /*Generates collision message */
        randombytes(m_fake, SPX_MLEN);
        /* Generates random R and store it in the signature */
        randombytes(optrand, SPX_N);
        gen_message_random(fors_sig, sk_prf, optrand, m_fake, mlen);

        /* Obtaining collision digest */
        hash_message(mhash, &tree2, &idx_leaf2, fors_sig, pk, m_fake, mlen);

        if(tree == tree2){
            /* If it returned true, at least one of this FORS's tree signatures can be used on a forgery and is not yet owned. */
            if(check_message_indices(target_tree_leaves[idx_leaf2].unchecked_indexes, target_tree_leaves[idx_leaf2].target_leaves, self_leaves, mhash)){
                
                /* The Oracle simulation starts here. */

                /* Setting pointer beyond the R value */
                fors_sig += SPX_N;
                
                /* Setting the address to code the XMSS tree and WOTS+ key pair used */
                set_tree_addr(wots_addr, tree2);
                set_keypair_addr(wots_addr, idx_leaf2);

                /*oracle FORS signature generation */
                fors_sign(fors_sig, root, mhash, sk_seed, pub_seed, wots_addr);

                /*If this is the first collision found on a WOTS+ key pair we simulate the Hypertree signature and store it. */
                pthread_mutex_lock(&lock);
                if(target_tree_leaves[idx_leaf2].found_collision == false){
                    
                    target_tree_leaves[idx_leaf2].found_collision = true;
                    pthread_mutex_unlock(&lock);

                    /* Setting pointer beyond all FORS signatures */
                    fors_sig += SPX_FORS_BYTES;
                    /*
                        Saving pointer for latter copy of the Hypertree signature.
                        The same pointer can be obtained summing: original pointer's position + SPX_N + SPX_FORS_BYTES 
                    */
                    ht_sig = fors_sig;

                    /* 
                        Keeps the idx_leaf2 unchanged. Simulates the update of the idx_leaf used by the Oracle to
                        know which WOTS+ key pair is used in each of the Hypertree layers.
                        The adversary keeps the pointer position static.
                     */
                    idx_leaf_aux = idx_leaf2;

                    /*The adversary's address is saved in wots_addr_aux for latter use. */
                    copy_subtree_addr(wots_addr_aux, wots_addr);

                    /* Oracle's Hypertree signature simulation. */
                    for (i = 0; i < SPX_D; i++) {
                        set_layer_addr(tree_addr, i);
                        set_tree_addr(tree_addr, tree2);

                        copy_subtree_addr(wots_addr, tree_addr);
                        set_keypair_addr(wots_addr, idx_leaf_aux);

                        /* Compute a WOTS signature. */
                        wots_sign(fors_sig, root, sk_seed, pub_seed, wots_addr);
                         fors_sig += SPX_WOTS_BYTES;

                        /* Compute the authentication path for the used WOTS leaf. */
                        treehash(root, fors_sig, sk_seed, pub_seed, idx_leaf_aux, 0, SPX_TREE_HEIGHT, wots_gen_leaf, tree_addr);
                        fors_sig += SPX_TREE_HEIGHT * SPX_N;

                        /* Update the indices for the next layer. */
                        idx_leaf_aux = (tree2 & ((1 << SPX_TREE_HEIGHT)-1));
                        tree2 = tree2 >> SPX_TREE_HEIGHT;
                    }


                    copy_subtree_addr(wots_addr, wots_addr_aux);
                    set_keypair_addr(wots_addr, idx_leaf2);

                    /* 
                        Copy the full HYPERTREE Signature and signals this forgery alredy has its Hypertree signature.
                        - adversary code. 
                    */
                    
                    memcpy(hyper_storage[idx_leaf2].ht_sig, ht_sig, SPX_D * (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N));
                    

                    /* Sets the adversary's signature pointer to the beguining of the FORS signatures. */
                    fors_sig = fors_sig2 + SPX_N;
                }
                pthread_mutex_unlock(&lock);                

                /* 
                    The adversary checks, for each FORS's tree signature, if it is the signature our message to be forged
                    needs. It only collects and stores the tree signatures needed and not yet owned.
                */
                for(int index = 0; index < SPX_FORS_TREES; index++ ){

                    
                    if(self_leaves[index] == target_tree_leaves[idx_leaf2].target_leaves[index]){
                        pthread_mutex_lock(&lock);
                        if(target_tree_leaves[idx_leaf2].unchecked_indexes[index] == true){

                            /* 
                                Signals it found one FORS signature for message on WOTS+ key pair idx_leaf2
                                corresponding to tree index.
                            */
                            target_tree_leaves[idx_leaf2].unchecked_indexes[index] = false;
                            pthread_mutex_unlock(&lock);
                            /* Copy tree signature to a storage for latter assemble. */
                            memcpy(target_tree_leaves[idx_leaf2].tree_signatures[index],fors_sig + index * (SPX_N + SPX_N * SPX_FORS_HEIGHT), SPX_N + SPX_N * SPX_FORS_HEIGHT);

                            pthread_mutex_lock(&lock);
                            counter += 1;
                            pthread_mutex_unlock(&lock);
                            //printf("\rFound %d valid collisions!!",counter);
                        }
                        pthread_mutex_unlock(&lock);
                    }
                    
                }
                fors_sig -= SPX_N;
            }
        } 
    }

    return NULL;
}

/**
 * Returns an array containing several forged signatures.
 */
int attack_function(uint8_t *signatures[collisions], size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    /* GENERIC PREPARATIONS */

    const unsigned char *sk_seed = sk;
    const unsigned char *sk_prf = sk + SPX_N;
    const unsigned char *pk = sk + 2*SPX_N;
    const unsigned char *pub_seed = pk;

    struct info *info = malloc(sizeof(struct info));

    unsigned char optrand[SPX_N];
    unsigned char mhash [SPX_FORS_MSG_BYTES];
    unsigned char root[SPX_N];
    unsigned long long i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t wots_addr_aux[8] = {0};
    uint32_t tree_addr[8] = {0};

    // Multi-thread id
    pthread_t tid[THREAD_NUMBER];

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(pub_seed, NULL);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);


    /* GENERATING R. */
    randombytes(optrand, SPX_N);

    /* -- */

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idx_leaf, optrand, pk, m, mlen);
    
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);


    /* Stores each message generated */
    unsigned char *m_fake = malloc(SPX_MLEN);
    
    /* Stores the used leaves in the FORS's tree signatures of each message. */
    uint32_t self_leaves[SPX_FORS_TREES];

    /* Initializing all storage space needed in the attack. */
    for(int aux=0;aux < collisions;aux++){

        message_found[aux] = false;

        /* Initializing spaces for each message and respective R value to be forged. */
        messages[aux].m_fake = malloc(sizeof(unsigned char)*SPX_MLEN);
        messages[aux].r = malloc(sizeof(unsigned char)*SPX_N);

        /* Initializing Hypertree signatures storage space. */
        hyper_storage[aux].ht_sig = malloc(sizeof(uint8_t) *  SPX_D * (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N));

        for(int aux2=0;aux2<33;aux2++){

            /* Setting the initial value to 0 - will be midifyed depending on the message. */
            target_tree_leaves[aux].target_leaves[aux2] = 0;

            /* allocate FORS's tree signature size (SK + AUTH) */
            target_tree_leaves[aux].tree_signatures[aux2] = malloc(SPX_N + SPX_N * SPX_FORS_HEIGHT);
        }
    }

    pthread_mutex_init(&lock, NULL);

    /*Store the first message and R and check it as found. */
    memcpy(messages[idx_leaf].m_fake,m,SPX_MLEN); 
    memcpy(messages[idx_leaf].r,optrand,SPX_N);

    message_found[idx_leaf] = true;

    target_tree_leaves[idx_leaf].found_collision = false;
    my_message_to_indices(target_tree_leaves[idx_leaf].unchecked_indexes,target_tree_leaves[idx_leaf].target_leaves, mhash);

    info->sk_seed = sk_seed;
    info->sk_prf = sk_prf;
    info->pk = pk;
    info->pub_seed = pub_seed;
    info->tree = tree;
    info->idx_leaf = idx_leaf;
    info->mlen = mlen;

    for (i = 0; i < THREAD_NUMBER; i++)
        pthread_create(&tid[i], NULL, collisions_finder, info);

    for (i = 0; i < THREAD_NUMBER; i++)
        pthread_join(tid[i], NULL);


    pthread_mutex_destroy(&lock);

    /* Assembling signatures: R + FORS signatures + Hypertree Signature + Message signed. */
    for(int aux=0;aux < collisions;aux++){
        uint8_t *signature = signatures[aux];
        memcpy(signature,messages[aux].r,SPX_N);
        signature += SPX_N;

        /* Copy the FORS signatures */
        for(int index = 0; index < SPX_FORS_TREES; index++ ){
            memcpy(signature,target_tree_leaves[aux].tree_signatures[index],SPX_N + SPX_N * SPX_FORS_HEIGHT);
            signature += SPX_N + SPX_N * SPX_FORS_HEIGHT;
        }
        /* Copy the HT signature */
        memcpy(signature,hyper_storage[aux].ht_sig, SPX_D * (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N));
        signature += SPX_D * (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N);
        memcpy(signature,messages[aux].m_fake,SPX_MLEN);
    }

    /* DEBUG */
    //if(memcmp(signatures[0] + SPX_N,secure_fors_sig + SPX_N, SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N) == 0) printf("Forged signature successfully!\n");
   
    /* The signature length is the signature size plus the message size which is placed at the end of the signature. */
    *siglen = SPX_BYTES + SPX_MLEN; 


    return 0;
}



/**
 * Verifies given signature-message pairs under a given public key.
 */
int crypto_sign_open2(unsigned char *m, unsigned long long *mlen,
                     unsigned char *signatures[collisions], unsigned long long smlen,
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
    for(int aux=0;aux < collisions;aux++){

        unsigned char *sm = signatures[aux]; 

        if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, (size_t)*mlen, pk)) {
            printf("failed for signature %d!!",aux);
            memset(m, 0, smlen);
            *mlen = 0;
            return -1;
        }
        /* If verification was successful, move the message to the right place. */
        memmove(m, sm + SPX_BYTES, *mlen);
    }

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
        printf("failed!!\n");
        *mlen = 0;
        return -1;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(m, sm + SPX_BYTES, *mlen);

    return 0;
}

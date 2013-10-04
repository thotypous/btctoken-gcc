#include <stdio.h>
#include <string.h>
#include "types.h"
#include "sha2.h"
#include "ecdsa.h"

static const uint8_t my_scriptPubKey[] = { 0x19, 0x76, 0xa9, 0x14, 0xb0, 0x7e, 0x16, 0x3b, 0xe6, 0x3d, 0x63, 0x3a, 0xc3, 0xcc, 0x0c, 0x93, 0xeb, 0x85, 0x3b, 0x68, 0x4c, 0xd2, 0x79, 0xcd, 0x88, 0xac };

static const uint8_t null_script[] = { 0x00 };
static const uint8_t hashtype_seq[] = { 0x01, 0x00, 0x00, 0x00 };

static uint8_t readbuff[64], writebuff[64];
static uint8_t bigbuff[65536];

FILE *fp;
int HID_Read() {
    fread(readbuff, sizeof(readbuff), 1, fp);
    return 1;
}

static void HID_bRead() {
    while(!HID_Read());
}

static const uint8_t rawtx_hdr[] = "RAWTXlen";
static int tx_read() {
    uint16_t size, i;
    uint8_t *buffptr = bigbuff;

    HID_bRead();
    if(memcmp(readbuff, rawtx_hdr, 8) != 0)
        return 0;
    size = *(uint16_t *)&readbuff[8];

    if(size > sizeof(bigbuff)) // maximum raw transaction size
        return 0;

    for(i = 0; i < size; i += sizeof(readbuff)) {
        HID_bRead();
        memcpy(buffptr, readbuff, sizeof(readbuff));
        buffptr += sizeof(readbuff);
    }

    return size;
}

// NYI number of transactions represented by more than one byte
// REQUIRED: max_inputs < 0xfd
enum { max_inputs = 32 };

typedef union {
    uint8_t digest[SHA256_DIGEST_LENGTH];
} sha256_digest;

static uint8_t num_inputs;
static sha256_digest hash_to_sign[max_inputs];
static sha256_digest input_tx_ids[max_inputs];
static uint8_t input_tx_idxs[max_inputs];
static SHA256_CTX hash_ctxs[max_inputs];

typedef enum {
    TX_MAIN,
    TX_INPUT_SIGNED,
    TX_INPUT_NOTSIGNED
} tx_type;

static uint8_t input_tx_signed;   // for tx_type == TX_INPUT_SIGNED
static uint8_t curr_input;        // for tx_type != TX_MAIN
static uint64_t change_amount = 0, payment_amount = 0, input_amount = 0;
static char payment_addr[35];

static void double_hash(SHA256_CTX *ctx, sha256_digest *dig) {
    SHA256_Final(dig->digest, ctx);
    SHA256_Init(ctx);
    SHA256_Update(ctx, dig->digest, sizeof(sha256_digest));
    SHA256_Final(dig->digest, ctx);
}

static int tx_get(tx_type txtype) {
    SHA256_CTX ctx;
    uint8_t *buffptr = bigbuff, *buffend;
    int i, j, num_in, num_out, size, valid_amount = 0;

    size = tx_read();
    if(size < 5)
        return 0;
    buffend = &bigbuff[size];

    SHA256_Init(&ctx);

    if(txtype == TX_MAIN) {
        // other txtypes will be hashed all at the same time
        SHA256_Update(&ctx, buffptr, 5);
    }

    // check version
    if(*(uint32_t *)buffptr != 0x01)
        return 0;
    // NYI number of transactions represented by more than one byte
    num_in = buffptr[4];
    buffptr += 5;
    if(num_in >= 0xfd)
        return 0;

    if(txtype == TX_MAIN && num_in > max_inputs)
        return 0;

    if(txtype == TX_INPUT_SIGNED && num_in <= input_tx_signed)
        return 0;   // less inputs than expected for checking signature

    if(txtype == TX_MAIN)
        num_inputs = num_in;

    for(i = 0; i < num_in; i++) {
        int script_size;
        // read previous tx and index
        if((buffptr + sizeof(sha256_digest) + sizeof(uint32_t)) >= buffend)
            return 0;
        if(txtype == TX_MAIN) {
            SHA256_Update(&ctx, buffptr, sizeof(sha256_digest) + sizeof(uint32_t));
            for(j = 0; j < i; j++)
                SHA256_Update(&hash_ctxs[j], buffptr, sizeof(sha256_digest) + sizeof(uint32_t));
            uint32_t idx = *(uint32_t *)&buffptr[sizeof(sha256_digest)];
            if(idx >= 0xfd)
                return 0;
            memcpy(&input_tx_ids[i].digest, buffptr, sizeof(sha256_digest));
            input_tx_idxs[i] = idx;
        }
        buffptr += sizeof(sha256_digest) + sizeof(uint32_t);
        // read scriptSig
        script_size = buffptr[0];
        buffptr++;
        // an incomplete transaction must have null-size scriptSigs
        if(txtype == TX_MAIN && script_size != 0)
            return 0;
        if((buffptr + script_size) >= buffend)
            return 0;
        if(txtype == TX_INPUT_SIGNED && i == input_tx_signed) {
            // if we are checking a signed input, only need to compute the
            // signing hash for one of the inputs
            SHA256_Update(&ctx, bigbuff, buffptr - bigbuff - 1);
            SHA256_Update(&ctx, my_scriptPubKey, sizeof(my_scriptPubKey));
            buffptr += script_size;
            SHA256_Update(&ctx, buffptr, buffend - buffptr);
        }
        else {
            buffptr += script_size;
        }
        if(txtype == TX_MAIN) {
            // hash my_scriptPubKey for the current input, and the null script for others
            memcpy(&hash_ctxs[i], &ctx, sizeof(SHA256_CTX));
            SHA256_Update(&hash_ctxs[i], my_scriptPubKey, sizeof(my_scriptPubKey));
            SHA256_Update(&ctx, null_script, sizeof(null_script));
            for(j = 0; j < i; j++)
                SHA256_Update(&hash_ctxs[j], null_script, sizeof(null_script));
        }
        // check sequence
        if((buffptr + sizeof(uint32_t)) >= buffend)
            return 0;
        if(*(uint32_t *)buffptr != 0xffffffff)
            return 0;
        if(txtype == TX_MAIN) {
            SHA256_Update(&ctx, buffptr, sizeof(uint32_t));
            for(j = 0; j <= i; j++)
                SHA256_Update(&hash_ctxs[j], buffptr, sizeof(uint32_t));
        }
        buffptr += sizeof(uint32_t);
    }

    // compute remaining hash
    if(txtype == TX_MAIN) {
        for(j = 0; j < num_in; j++) {
            SHA256_Update(&hash_ctxs[j], buffptr, buffend - buffptr);
            SHA256_Update(&hash_ctxs[j], hashtype_seq, sizeof(hashtype_seq));
            double_hash(&hash_ctxs[j], &hash_to_sign[j]);
        }
    }

    // NYI number of transactions represented by more than one byte
    num_out = buffptr[0];
    if(num_out >= 0xfd)
        return 0;
    buffptr++;

    // the main transaction must have at most a payment and a change output
    if(txtype == TX_MAIN && num_out > 2)
        return 0;

    // check if we are verifying a output # which does not exist in current transaction
    if(txtype != TX_MAIN && input_tx_idxs[curr_input] >= num_out)
        return 0;

    // check bounds for a standard scriptPubKey for each output, and for the locktime
    if((buffptr + num_out*(sizeof(uint64_t)+sizeof(my_scriptPubKey)) + sizeof(uint32_t)) > buffend)
        return 0;

    for(i = 0; i < num_out; i++) {
        uint64_t amount = *(uint64_t *)buffptr;
        buffptr += sizeof(uint64_t);
        // check if this is a standard bitcoin address based scriptPubKey
        if(memcmp(buffptr, my_scriptPubKey, 4) || memcmp(&buffptr[24], &my_scriptPubKey[24], 2))
            return 0;
        if(txtype == TX_MAIN) {
            // check destination of this output
            if(!memcmp(buffptr, my_scriptPubKey, sizeof(my_scriptPubKey))) {
                // if the I am the destination myself, then it is a change
                if(valid_amount & 1)
                    return 0;  // repeated change output
                valid_amount |= 1;
                change_amount = amount;
            }
            else {
                // otherwise, it is a payment
                uint8_t ripemd[21];

                if(valid_amount & 2)
                    return 0;  // repeated payment output
                valid_amount |= 2;

                payment_amount = amount;
                ripemd[0] = 0;
                memcpy(&ripemd[1], &buffptr[4], 20);
                ecdsa_get_address_from_ripemd(ripemd, payment_addr);
            }
        }
        else if(i == input_tx_idxs[curr_input]) {
            // the destination of the output must be ourself, since we are using it as an input
            if(memcmp(buffptr, my_scriptPubKey, sizeof(my_scriptPubKey)))
                return 0;
            // sum the amount
            input_amount += amount;
        }
        buffptr += sizeof(my_scriptPubKey);
    }

    // check locktime
    if(*(uint32_t*)buffptr != 0x0)
        return 0;

    // assert there is no padding data at the end
    if((buffptr + sizeof(uint32_t)) != buffend)
        return 0;

    return 1;
}

int main() {
    fp = fopen("test.in", "rb");
    tx_get(TX_MAIN);
    return 0;
}

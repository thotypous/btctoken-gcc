#include <stdio.h>
#include <string.h>
#include "types.h"
#include "sha2.h"
#include "ecdsa.h"

static const uint8_t my_scriptPubKey[] = { 0x19, 0x76, 0xa9, 0x14, 0xb0, 0x7e, 0x16, 0x3b, 0xe6, 0x3d, 0x63, 0x3a, 0xc3, 0xcc, 0x0c, 0x93, 0xeb, 0x85, 0x3b, 0x68, 0x4c, 0xd2, 0x79, 0xcd, 0x88, 0xac };
static const uint8_t my_pubkey[] = { 0x04, 0x2d, 0x2a, 0x61, 0xff, 0x96, 0x4c, 0x56, 0x66, 0x05, 0xa4, 0xa4, 0xe6, 0x5d, 0xf7, 0x57, 0xb3, 0x13, 0x6b, 0x1c, 0xa5, 0xe3, 0x16, 0x6f, 0xa0, 0x8d, 0x8e, 0x03, 0x97, 0xa3, 0xa1, 0x96, 0xb7, 0x59, 0x97, 0x38, 0x71, 0x18, 0xc7, 0xdf, 0x30, 0x23, 0x5c, 0x4f, 0xa7, 0x6f, 0x61, 0x91, 0x68, 0xd2, 0x74, 0x03, 0x24, 0x70, 0xa2, 0x45, 0x82, 0x32, 0x06, 0x87, 0xb7, 0x20, 0x2b, 0x03, 0x2b };

static const uint8_t null_script[] = { 0x00 };
static const uint8_t hashtype_one[] = { 0x01, 0x00, 0x00, 0x00 };

static uint8_t readbuff[64];//, writebuff[64];
static uint8_t bigbuff[65536];

FILE *fp;
int HID_Read() {
    fread(readbuff, sizeof(readbuff), 1, fp);
    return 1;
}

static void HID_bRead() {
    while(!HID_Read());
}

static const uint8_t rawtx_hdr[] = {'R','A','W','T','X','l','e','n'};
static int tx_read() {
    uint16_t size, i;
    uint8_t *buffptr = bigbuff;

    HID_bRead();
    if(memcmp(readbuff, rawtx_hdr, sizeof(rawtx_hdr)) != 0)
        return 0;
    size = *(uint16_t *)&readbuff[sizeof(rawtx_hdr)];

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

static const uint8_t merkle_hdr[] = {'M','e','r','k','l','e','N','o','d','e'};
static int compute_merkle(sha256_digest *dig) {
    SHA256_CTX ctx;
    uint8_t pos;
    while(1) {
        HID_bRead();
        if(memcmp(readbuff, merkle_hdr, sizeof(merkle_hdr)))
            return 0;
        pos = readbuff[sizeof(merkle_hdr)];
        if(pos == 0xff)
            return 1;
        SHA256_Init(&ctx);
        if(pos == 0) {
            SHA256_Update(&ctx, dig->digest, sizeof(sha256_digest));
            SHA256_Update(&ctx, &readbuff[sizeof(merkle_hdr)+1], sizeof(sha256_digest));
        }
        else if(pos == 1) {
            SHA256_Update(&ctx, &readbuff[sizeof(merkle_hdr)+1], sizeof(sha256_digest));
            SHA256_Update(&ctx, dig->digest, sizeof(sha256_digest));
        }
        else return 0;
        double_hash(&ctx, dig);
    }
}

static int parse_scriptSig(const uint8_t *scriptSig, int script_size, uint8_t *sig) {
    int siglen, intlen;

    siglen = scriptSig[0];
    if(siglen >= 0x4c)
        return 0;  // NYI OP_PUSH 0x4c or more bytes
    if(siglen < 7) // 2 + 2*(2+0) + 1
        return 0;
    if((2 + siglen + (int)sizeof(my_pubkey)) > script_size)
        return 0;

    // check hashtype
    if(scriptSig[siglen] != 0x01)
        return 0;
    // check pubkey
    if(scriptSig[siglen+1] != sizeof(my_pubkey))
        return 0;  // different length from our pubkey
    if(memcmp(&scriptSig[siglen+2], my_pubkey, sizeof(my_pubkey)))
        return 0;  // different from our pubkey

    // check DER
    if(scriptSig[1] != 0x30)  // DER sequence
        return 0;
    if(scriptSig[2] != siglen - 3)
        return 0;
    if(scriptSig[3] != 0x02)  // DER integer
        return 0;
    intlen = scriptSig[4];
    if(intlen > 33)
        return 0;
    if(6 + intlen >= siglen)
        return 0;
    if(scriptSig[5+intlen] != 0x02) // DER integer
        return 0;
    if(7 + scriptSig[6+intlen] + intlen != siglen)
        return 0;
    if(intlen == 33) {
        memcpy(&sig[0], &scriptSig[6], 32);
    }
    else {
        memset(&sig[0], 0, 32);
        memcpy(&sig[32 - intlen], &scriptSig[5], intlen);
    }
    scriptSig += 6+intlen;
    intlen = scriptSig[0];
    if(intlen > 33)
        return 0;
    if(intlen == 33) {
        memcpy(&sig[32], &scriptSig[2], 32);
    }
    else {
        memset(&sig[32], 0, 32);
        memcpy(&sig[64 - intlen], &scriptSig[1], intlen);
    }

    return 1;
}

static int tx_get(tx_type txtype) {
    SHA256_CTX ctx;
    sha256_digest dig;
    uint8_t *buffptr = bigbuff, *buffend;
    uint8_t sig_to_verify[64];
    int i, j, num_in, num_out, size, valid_amount = 0;

    size = tx_read();
    if(size < 5)
        return 0;
    buffend = &bigbuff[size];

    SHA256_Init(&ctx);

    if(txtype != TX_INPUT_NOTSIGNED) {
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
        if(txtype != TX_INPUT_NOTSIGNED) {
            SHA256_Update(&ctx, buffptr, sizeof(sha256_digest) + sizeof(uint32_t));
        }
        if(txtype == TX_MAIN) {
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
        if(txtype == TX_INPUT_SIGNED) {
            // if we are checking a signed input, only need to compute the
            // signing hash for one of the inputs
            if(i == input_tx_signed) {
                SHA256_Update(&ctx, my_scriptPubKey, sizeof(my_scriptPubKey));
                if(!parse_scriptSig(buffptr, script_size, sig_to_verify))
                    return 0;
            }
            else {
                SHA256_Update(&ctx, null_script, sizeof(null_script));
            }
        }
        buffptr += script_size;
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
        if(txtype != TX_INPUT_NOTSIGNED)
            SHA256_Update(&ctx, buffptr, sizeof(uint32_t));
        if(txtype == TX_MAIN) {
            for(j = 0; j <= i; j++)
                SHA256_Update(&hash_ctxs[j], buffptr, sizeof(uint32_t));
        }
        buffptr += sizeof(uint32_t);
    }

    if(txtype == TX_MAIN) {
        // compute remaining hash
        for(j = 0; j < num_in; j++) {
            SHA256_Update(&hash_ctxs[j], buffptr, buffend - buffptr);
            SHA256_Update(&hash_ctxs[j], hashtype_one, sizeof(hashtype_one));
            SHA256_Final(hash_to_sign[j].digest, &hash_ctxs[j]);
        }
    }
    if(txtype == TX_INPUT_SIGNED) {
        // compute remaining hash and verify if signature matches
        SHA256_Update(&ctx, buffptr, buffend - buffptr);
        SHA256_Update(&ctx, hashtype_one, sizeof(hashtype_one));
        SHA256_Final(dig.digest, &ctx);
        if(ecdsa_verify(my_pubkey, sig_to_verify, dig.digest, sizeof(sha256_digest)) != 0)
            return 0;
    }
    if(txtype != TX_MAIN) {
        // compute hash and check if the transaction is the same as identified in the main one
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, bigbuff, size);
        double_hash(&ctx, &dig);
        if(memcmp(&dig, &input_tx_ids[curr_input], sizeof(sha256_digest)))
            return 0;
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
    input_tx_signed = 0;
    curr_input = 2;
    printf("tx_get=%d\n", tx_get(TX_MAIN));
    printf("tx_get=%d\n", tx_get(TX_INPUT_NOTSIGNED));
    printf("compute_merkle=%d\n", compute_merkle(&input_tx_ids[curr_input]));
    {
        int i;
        for(i = 31; i >= 0; i--)
            printf("%02x", input_tx_ids[curr_input].digest[i]);
        printf("\n");
    }
    return 0;
}

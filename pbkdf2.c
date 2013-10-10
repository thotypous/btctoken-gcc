/*-
 * Copyright 2005,2007,2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <string.h>

#include "pbkdf2.h"
#include "sha2.h"
#include "bignum.h"

/* Initialize an HMAC-scrypt_SHA256 operation with the given key. */
void
hmac_sha256_init(HMAC_SHA256_CTX * ctx, const void * _K, size_t Klen)
{
    unsigned char pad[64];
    unsigned char khash[32];
    const unsigned char * K = _K;
    size_t i;

    /* If Klen > 64, the key is really scrypt_SHA256(K). */
    if (Klen > 64) {
        SHA256_Init(&ctx->ictx);
        SHA256_Update(&ctx->ictx, K, Klen);
        SHA256_Final(khash, &ctx->ictx);
        K = khash;
        Klen = 32;
    }

    /* Inner scrypt_SHA256 operation is scrypt_SHA256(K xor [block of 0x36] || data). */
    SHA256_Init(&ctx->ictx);
    memset(pad, 0x36, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];
    SHA256_Update(&ctx->ictx, pad, 64);

    /* Outer scrypt_SHA256 operation is scrypt_SHA256(K xor [block of 0x5c] || hash). */
    SHA256_Init(&ctx->octx);
    memset(pad, 0x5c, 64);
    for (i = 0; i < Klen; i++)
        pad[i] ^= K[i];
    SHA256_Update(&ctx->octx, pad, 64);

    /* Clean the stack. */
    memset(khash, 0, 32);
}

/* Add bytes to the HMAC-scrypt_SHA256 operation. */
void
hmac_sha256_update(HMAC_SHA256_CTX * ctx, const void *in, size_t len)
{

    /* Feed data to the inner scrypt_SHA256 operation. */
    SHA256_Update(&ctx->ictx, in, len);
}

/* Finish an HMAC-scrypt_SHA256 operation. */
void
hmac_sha256_final(unsigned char digest[32], HMAC_SHA256_CTX * ctx)
{
    unsigned char ihash[32];

    /* Finish the inner scrypt_SHA256 operation. */
    SHA256_Final(ihash, &ctx->ictx);

    /* Feed the inner hash to the outer scrypt_SHA256 operation. */
    SHA256_Update(&ctx->octx, ihash, 32);

    /* Finish the outer scrypt_SHA256 operation. */
    SHA256_Final(digest, &ctx->octx);

    /* Clean the stack. */
    memset(ihash, 0, 32);
}

/**
 * pbkdf2_sha256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-scrypt_SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void
pbkdf2_sha256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
    size_t saltlen, uint32_t c, uint8_t * buf, size_t dkLen)
{
    HMAC_SHA256_CTX PShctx, hctx;
    size_t i;
    uint8_t ivec[4];
    uint8_t U[32];
    uint8_t T[32];
    uint32_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    hmac_sha256_init(&PShctx, passwd, passwdlen);
    hmac_sha256_update(&PShctx, salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * 32 < dkLen; i++) {
        /* Generate INT(i + 1). */
        write_be(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
        hmac_sha256_update(&hctx, ivec, 4);
        hmac_sha256_final(U, &hctx);

        /* T_i = U_1 ... */
        memcpy(T, U, 32);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            hmac_sha256_init(&hctx, passwd, passwdlen);
            hmac_sha256_update(&hctx, U, 32);
            hmac_sha256_final(U, &hctx);

            /* ... xor U_j ... */
            for (k = 0; k < 32; k++)
                T[k] ^= U[k];
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * 32;
        if (clen > 32)
            clen = 32;
        memcpy(&buf[i * 32], T, clen);
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset(&PShctx, 0, sizeof(HMAC_SHA256_CTX));
}

/* 
 * Test for wolfssl-4.4.0 used in
 * CDF – crypto differential fuzzing
 * (https://github.com/kudelskisecurity/cdf)
 * for finding an issue in the ECDSA
 * implementation.
 *
 * When using the ECDSA signing implementation of wolfssl-4.4.0 with
 * the curve secp256r1 it is possible to sign a message using (0, 0) as
 * public key and 0 as private key. The wc_ecc_import_raw function does
 * not validate if the points belong to the curve.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int rand_gen_seed(byte* output, word32 sz);
#define CUSTOM_RAND_GENERATE_SEED  rand_gen_seed
#define CUSTOM_RAND_GENERATE  rand_gen_seed

int rand_gen_seed(byte* output, word32 sz)
{
    int i;
    for (i = 0; i < sz; i++ ) {
        output[i] = '0xaa';
    }

    return 0;
}

#define MAX_BLOCK_SIZE 1024

// convert a char to its binary representation, from hex
static int toBin(unsigned char val)
{
    if (val >= '0' && val <= '9')
        return val - '0';
    else if (val >= 'a' && val <= 'f')
        return val - 'a' + 10;
    else if (val >= 'A' && val <= 'F')
        return val - 'A' + 10;
    else
        assert(0);
    return -1;
}

// unhexlify a given string
static int unhex(unsigned char* out, const char* in)
{
    unsigned char a, b;
    int len = strlen(in) / 2;
    assert(strlen(in) == 2 * len);

    while (*in != 0) {
        a = *in++;
        b = *in++;
        *out++ = (toBin(a) << 4) | toBin(b);
    }
    return len;
}

int main(int argc, char * argv[])
{
    // Parsing argument:
    int c;
    int blen_tested = 0;
    int hash_provided = 0;
    byte hash[WC_SHA256_DIGEST_SIZE];
    memset(hash, 0, sizeof(hash));
    extern char* optarg;
    extern int optind, optopt, opterr;
        wc_Sha256 sha;
        word32 inOutIdx;
        int pos, verify;
    ecc_key eccKey;

        const unsigned char *wx, *wy, *d, *r, *s, *msg_str;

    while ((c = getopt(argc, argv, ":h:")) != -1) {
        switch (c) {
        case 'h':
            unhex(hash, optarg); // unsafe for the memory, if optarg is bigger than hash!
            blen_tested = strlen(optarg) / 2;
            hash_provided = 1;
            break;
        case ':':
            // -h without hash length
            printf("-h without hash");
            break;
        case '?':
            printf("unknown arg %c\n", optopt);
            return -1;
        }
    }

    int ret = 1;
    int signing = 0;
    if (argc - optind == 4) {
        signing = 1;
    } else if (argc - optind == 5) {
        signing = 0;
    } else {
        printf("usage: \t%s X, Y, D, M\nor \t%s X, Y, R, S, M\n", argv[0], argv[0]);
        return -1;
    }

    ((void)argv);

    // we must unhexlify the data:
    const char* str = argv[argc - 1];
    unsigned char* msg = (unsigned char*)malloc(strlen(str) / 2 * sizeof(unsigned char));
    size_t mlen;
    mlen = unhex(msg, str);

    // Hashing the message:
    size_t hlen;
    hlen = WC_SHA256_DIGEST_SIZE;
    if (hash_provided != 1) { // then we must hash our message, flag -h not provided
   // msg, mlen -> hash     mbedtls_md(md_info, (const unsigned char*)msg, mlen, hash);


        ret = wc_InitSha256(&sha);
        if (ret != 0) {
            printf("Falla initsha256\n");
            return ret;
        }

        pos = 0;
        while (mlen > 0) {
            word32 len = mlen;

            if (len > MAX_BLOCK_SIZE)
                len = MAX_BLOCK_SIZE;

            ret = wc_Sha256Update(&sha, msg + pos, mlen);

            if (ret < 0) {
                printf("Falla sha256 update\n");
                goto exit;
            }

            pos += mlen;
            mlen -= len;
        }

        ret = wc_Sha256Final(&sha, hash);
        if (ret < 0) {
            printf("Falla sha256 final\n");
            goto exit;
        }
    
        inOutIdx = 0;



    } else { // then we have set blen_tested at the same time we setted the hash
        hlen = blen_tested;
    }


    if (signing) {

        wx = argv[1];
        wy = argv[2];
        d = argv[3];
        r = argv[4];
        s = argv[5];

        wc_ecc_init(&eccKey);
        ret = wc_ecc_import_raw(&eccKey, wx, wy, d, "SECP256R1");

        if (ret != 0) {
            printf("ERROR IMPORTANDO CLAVE PRIVADA\n");
            goto exit;
        }  
        
        byte* sig = NULL; // get rid of this magic number
        WC_RNG rng;
    
        word32 maxSigSz = ECC_MAX_SIG_SIZE;
        sig = (byte*) XMALLOC(maxSigSz * sizeof(byte), NULL,
                          DYNAMIC_TYPE_TMP_BUFFER);
                          


        if (sig == NULL) {
            printf("Failed to allocate sig buff\n");
            goto exit;
        }
        
        wolfCrypt_Init();

        ret = wc_InitRng(&rng);

        if (ret != 0) {
            printf("ERROR INIT RNG\n");
            goto exit;
        }  

        ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &maxSigSz, &rng, &eccKey);

        if (ret != 0) {
            printf("ERROR ECC SIGN\n");
            goto exit;
        }  
        
             int         keySz = 32;
    byte          r[keySz];
    byte          s[keySz];
    word32        rlen = (word32)sizeof(r);
    word32        slen = (word32)sizeof(s);

    XMEMSET(r, 0, keySz);
    XMEMSET(s, 0, keySz);

        ret = wc_ecc_sig_to_rs(sig, maxSigSz, r, &rlen, s, &slen);
        if (ret != 0) {
            printf("ERROR SIG TO RS\n");
            goto exit;
        }  

for (int i = 0; i < rlen; i++)
{
    //if (i > 0) printf(":");
    printf("%02X", r[i]);
}
printf("\n");

for (int i = 0; i < slen; i++)
{
    //if (i > 0) printf(":");
    printf("%02X", s[i]);
}
printf("\n");



    } else { // we are not signing, so we are verifying the signature

        wx = argv[1];
        wy = argv[2];
        r = argv[3];
        s = argv[4];
        msg_str = argv[5];

    byte          sig[ECC_MAX_SIG_SIZE];
    word32        siglen = (word32)sizeof(sig);

    int otro_ret = wc_ecc_rs_to_sig(r, s, sig, &siglen);

    wc_ecc_init(&eccKey);
    ret = wc_ecc_import_raw(&eccKey, wx, wy, NULL, "SECP256R1");

    if (ret < 0) {
        printf("Error public key decode\n");
        goto exit;
    }

    ret = wc_ecc_set_curve(&eccKey, 32, ECC_SECP256R1);
    if (ret < 0) {
        printf("Error ecc set curve\n");
        goto exit;
        }
    
    ret = wc_ecc_verify_hash(sig, siglen, hash, sizeof(hash), &verify, &eccKey);
        
    if (verify == 1)
        printf("true\n");
    else
        printf("false\n");
    
    if (ret < 0) {
        printf("Error wc ecc verify hash\n");
        goto exit;
    }

}

exit:
    wc_Sha256Free(&sha);
    return (ret);
}


/*
 * SLH-DSA Signing Server
 * 
 * This server generates SLH-DSA signatures for a fixed message.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* Configurable SLH-DSA parameter set - can be overridden at compile time */
#ifndef SLH_DSA_PARAM
#error "Must define SLH_DSA_PARAM"
#endif

#define RNODE_OFFSET 0x130
#define RNODE_SIZE 0x20

#define ALIGN_BUF_SIZE RNODE_OFFSET+RNODE_SIZE

int main(void) {
    // alignment buffer to push OpenSSL stack frames to desired alignment
    volatile char align_buf[ALIGN_BUF_SIZE] = {'A'};
    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Create parameter-specific key filename */
    char keyfilename[256];
    snprintf(keyfilename, sizeof(keyfilename), "sk_%s.key", SLH_DSA_PARAM);

    /* Load the private key from file or generate if not exists */
    FILE *keyfile = fopen(keyfilename, "r");
    EVP_PKEY *pkey = NULL;
    
    if (!keyfile) {
        fprintf(stderr, "Key file %s not found, generating new %s keypair...\n", 
                keyfilename, SLH_DSA_PARAM);
        
        /* Generate SLH-DSA keypair using the specific parameter set name */
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, SLH_DSA_PARAM);
        if (!pkey) {
            fprintf(stderr, "Failed to generate %s keypair.\n", SLH_DSA_PARAM);
            fprintf(stderr, "Make sure OpenSSL 3.5+ is built with SLH-DSA support.\n");
            ERR_print_errors_fp(stderr);
            return EXIT_FAILURE;
        }
        
        fprintf(stderr, "Successfully generated %s keypair.\n", SLH_DSA_PARAM);
        
        /* Save the private key to file */
        keyfile = fopen(keyfilename, "w");
        if (keyfile) {
            if (PEM_write_PrivateKey(keyfile, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
                fprintf(stderr, "Warning: Failed to save private key to file.\n");
                ERR_print_errors_fp(stderr);
            } else {
                fprintf(stderr, "Private key saved to %s\n", keyfilename);
            }
            fclose(keyfile);
        } else {
            fprintf(stderr, "Warning: Could not create key file for saving.\n");
        } 
        {
            char pubkeyfilename[256];
            snprintf(pubkeyfilename, sizeof(pubkeyfilename), "pk_%s.pub", SLH_DSA_PARAM);
            FILE *pubkeyfile = fopen(pubkeyfilename, "w");
            if (pubkeyfile) {
                if (PEM_write_PUBKEY(pubkeyfile, pkey) != 1) {
                    fprintf(stderr, "Warning: Failed to save public key to %s.\n", pubkeyfilename);
                    ERR_print_errors_fp(stderr);
                } else {
                    fprintf(stderr, "Public key saved to %s\n", pubkeyfilename);
                }
                fclose(pubkeyfile);
            } else {
                fprintf(stderr, "Warning: Could not create public key file for saving.\n");
            }
        }
    } else {
        pkey = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
        fclose(keyfile);
        if (!pkey) {
            fprintf(stderr, "Error reading private key.\n");
            ERR_print_errors_fp(stderr);
            return EXIT_FAILURE;
        }
        fprintf(stderr, "Loaded existing %s private key from %s\n", SLH_DSA_PARAM, keyfilename);
    }
    /* Use a fixed message */
    const unsigned char *message = (const unsigned char *)"This is a fixed message.";
    size_t total = strlen((const char *)message);

    /* Sign using SLH-DSA with the new message signing API */
    EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!sctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_pkey failed.\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        return EXIT_FAILURE;
    }

    /* Fetch the specific SLH-DSA signature algorithm */
    EVP_SIGNATURE *sig_alg = EVP_SIGNATURE_fetch(NULL, SLH_DSA_PARAM, NULL);
    if (!sig_alg) {
        fprintf(stderr, "EVP_SIGNATURE_fetch failed for %s.\n", SLH_DSA_PARAM);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(sctx);
        EVP_PKEY_free(pkey);
        return EXIT_FAILURE;
    }

    /* Initialize signing with deterministic mode and optional context string */
#ifdef SLH_DSA_DETERMINISTIC
    int deterministic_flag = 1;
#else
    int deterministic_flag = 0;
#endif
    const OSSL_PARAM sign_params[] = {
        OSSL_PARAM_octet_string("context-string", (unsigned char *)"SLH-DSA test context", 20),
        OSSL_PARAM_int("deterministic", &deterministic_flag),  /* Enable deterministic signing */
        OSSL_PARAM_END
    };

    if (EVP_PKEY_sign_message_init(sctx, sig_alg, sign_params) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign_message_init failed.\n");
        ERR_print_errors_fp(stderr);
        EVP_SIGNATURE_free(sig_alg);
        EVP_PKEY_CTX_free(sctx);
        EVP_PKEY_free(pkey);
        return EXIT_FAILURE;
    }

    /* Calculate the required size for the signature */
    size_t sig_len = 0;
    if (EVP_PKEY_sign(sctx, NULL, &sig_len, message, total) <= 0) {
        fprintf(stderr, "EVP_PKEY_sign (get length) failed.\n");
        ERR_print_errors_fp(stderr);
        EVP_SIGNATURE_free(sig_alg);
        EVP_PKEY_CTX_free(sctx);
        EVP_PKEY_free(pkey);
        return EXIT_FAILURE;
    }

    unsigned char *sig = malloc(sig_len);
    if (!sig) {
        fprintf(stderr, "Memory allocation error.\n");
        EVP_SIGNATURE_free(sig_alg);
        EVP_PKEY_CTX_free(sctx);
        EVP_PKEY_free(pkey);
        return EXIT_FAILURE;
    }

    while (1) {
        /* Perform the actual signing */
        if (EVP_PKEY_sign(sctx, sig, &sig_len, message, total) <= 0) {
            fprintf(stderr, "EVP_PKEY_sign failed.\n");
            ERR_print_errors_fp(stderr);
            free(sig);
            EVP_SIGNATURE_free(sig_alg);
            EVP_PKEY_CTX_free(sctx);
            EVP_PKEY_free(pkey);
            return EXIT_FAILURE;
        }

        //fprintf(stderr, "Successfully signed message with %s in deterministic mode (signature length: %zu bytes)\n", 
        //        SLH_DSA_PARAM, sig_len);

        /* Output the signature followed by the message in hexadecimal to stdout */
        /* First output the signature */
        for (size_t i = 0; i < sig_len; i++) {
            printf("%02x", sig[i]);
        }
        /* Then append the message */
        for (size_t i = 0; i < total; i++) {
            printf("%02x", message[i]);
        }
        printf("\n");
        
        /* Log the format to stderr for debugging */
        //fprintf(stderr, "Output format: signature (%zu bytes) + message (%zu bytes) = %zu bytes total\n",
        //        sig_len, total, sig_len + total);
    }
    /* Clean up */
    free(sig);
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_free(pkey);
    ERR_free_strings();


    return EXIT_SUCCESS;
}

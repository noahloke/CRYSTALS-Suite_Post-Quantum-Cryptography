#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h> // For RAND_bytes
#include <openssl/rsa.h>
#include <openssl/pem.h> // RSA
#include "kem.h"
#include "randombytes.h"
#include <ctype.h>

#define AES_KEY_SIZE 32 // 256 bits
#define AES_BLOCK_SIZE 16 // Block size in bytes

#define MAX_INPUT_SIZE 100

void handleErrors(void);

EVP_PKEY *generate_rsa_keypair(void);
int rsa_encrypt(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plaintext_len, unsigned char **encrypted);
int rsa_decrypt(EVP_PKEY *privkey, unsigned char *ciphertext, size_t ciphertext_len, unsigned char **decrypted);

EVP_PKEY *generate_rsa_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) handleErrors();

    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) handleErrors();

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int rsa_encrypt(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plaintext_len, unsigned char **encrypted) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx) handleErrors();

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, plaintext_len) <= 0) handleErrors();

    *encrypted = (unsigned char *)malloc(outlen);
    if (EVP_PKEY_encrypt(ctx, *encrypted, &outlen, plaintext, plaintext_len) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

int rsa_decrypt(EVP_PKEY *privkey, unsigned char *ciphertext, size_t ciphertext_len, unsigned char **decrypted) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) handleErrors();

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, ciphertext_len) <= 0) handleErrors();

    *decrypted = (unsigned char *)malloc(outlen);
    if (EVP_PKEY_decrypt(ctx, *decrypted, &outlen, ciphertext, ciphertext_len) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        return 1;
    }
    
    clock_t temp_start, temp_end;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int test_iterations = atoi(argv[1]);

    uint8_t test_aes_key[CRYPTO_BYTES];

    EVP_PKEY *rsa_keypair = NULL;
    unsigned char *rsa_encrypted_aes_key = NULL;
    int rsa_encrypted_aes_key_len;
    unsigned char *rsa_decrypted_aes_key = NULL;

    uint8_t kyber_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t kyber_sk[CRYPTO_SECRETKEYBYTES];
    uint8_t kyber_ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t kyber_dec_ct[CRYPTO_BYTES];

    double rsa_keypair_time = 0.0;
    double rsa_encrypt_time = 0.0;
    double rsa_decrypt_time = 0.0;

    double kyber_keypair_time = 0.0;
    double kyber_encrypt_time = 0.0;
    double kyber_decrypt_time = 0.0;
    
    printf("Running %d iterations to compare average execution time of RSA vs Kyber methods.\n\n", test_iterations);

    for (int i = 0; i < test_iterations; i++) {
        randombytes(test_aes_key, CRYPTO_BYTES);

        temp_start = clock();
        rsa_keypair = generate_rsa_keypair();
        temp_end = clock();
        rsa_keypair_time += ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;

        temp_start = clock();
        rsa_encrypted_aes_key_len = rsa_encrypt(rsa_keypair, test_aes_key, sizeof(test_aes_key), &rsa_encrypted_aes_key);
        temp_end = clock();
        rsa_encrypt_time += ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;

        temp_start = clock();
        rsa_decrypt(rsa_keypair, rsa_encrypted_aes_key, rsa_encrypted_aes_key_len, &rsa_decrypted_aes_key);
        temp_end = clock();
        rsa_decrypt_time += ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;

        if (memcmp(test_aes_key, rsa_decrypted_aes_key, CRYPTO_BYTES) != 0) {
            abort();
        }

        temp_start = clock();
        crypto_kem_keypair(kyber_pk, kyber_sk);
        temp_end = clock();
        kyber_keypair_time += ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;

        temp_start = clock();
        crypto_kem_enc(kyber_ct, test_aes_key, kyber_pk);
        temp_end = clock();
        kyber_encrypt_time += ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;

        temp_start = clock();
        crypto_kem_dec(kyber_dec_ct, kyber_ct, kyber_sk);
        temp_end = clock();
        kyber_decrypt_time += ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;

        if (memcmp(test_aes_key, kyber_dec_ct, CRYPTO_BYTES) != 0) {
            abort();
        }
    }

    rsa_keypair_time /= test_iterations;
    rsa_encrypt_time /= test_iterations;
    rsa_decrypt_time /= test_iterations;

    kyber_keypair_time /= test_iterations;
    kyber_encrypt_time /= test_iterations;
    kyber_decrypt_time /= test_iterations;

    printf("+----------------------+-----------------------+--------------------------+--------------------------+\n");
    printf("|                      | Keypair Avg. Time (s) | Encryption Avg. Time (s) | Decryption Avg. Time (s) |\n");
    printf("+----------------------+-----------------------+--------------------------+--------------------------+\n");
    printf("| Kyber                | %21f | %24f | %24f |\n", kyber_keypair_time, kyber_encrypt_time, kyber_decrypt_time);
    printf("| RSA                  | %21f | %24f | %24f |\n", rsa_keypair_time, rsa_encrypt_time, rsa_decrypt_time);
    printf("+----------------------+-----------------------+--------------------------+--------------------------+\n");

    return 0;
}

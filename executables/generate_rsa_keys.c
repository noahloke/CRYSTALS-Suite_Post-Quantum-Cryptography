#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h> // For RAND_bytes
#include <openssl/rsa.h>
#include <openssl/pem.h> // RSA
#include "randombytes.h"
#include <ctype.h>

#define AES_KEY_SIZE 32 // 256 bits
#define AES_BLOCK_SIZE 16 // Block size in bytes

#define MAX_INPUT_SIZE 100

void handleErrors(void);

EVP_PKEY *generate_rsa_keypair(void);
EVP_PKEY *extract_public_key(EVP_PKEY *pkey);
EVP_PKEY *extract_private_key(EVP_PKEY *pkey);

int rsa_encrypt(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plaintext_len, unsigned char **encrypted);
int rsa_decrypt(EVP_PKEY *privkey, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **decrypted);

void print_hex(const unsigned char *data, size_t length);

void print_public_key_hex(EVP_PKEY *pubkey);
void print_private_key_hex(EVP_PKEY *privkey);

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

EVP_PKEY *extract_public_key(EVP_PKEY *pkey) {
    BIO *pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub_bio, pkey);

    EVP_PKEY *pubkey = NULL;
    pubkey = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);

    BIO_free(pub_bio);

    return pubkey;
}

EVP_PKEY *extract_private_key(EVP_PKEY *pkey) {
    BIO *priv_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL);

    EVP_PKEY *privkey = NULL;
    privkey = PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL);

    BIO_free(priv_bio);

    return privkey;
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

int rsa_decrypt(EVP_PKEY *privkey, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **decrypted) {
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

void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void print_public_key_hex(EVP_PKEY *pubkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pubkey);

    size_t len = BIO_pending(bio);
    unsigned char *key_pem = (unsigned char *)malloc(len);
    BIO_read(bio, key_pem, len);

    printf("Public Key (Hexadecimal):\n");
    print_hex(key_pem, len);

    BIO_free(bio);
    free(key_pem);
}

void print_private_key_hex(EVP_PKEY *privkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, privkey, NULL, NULL, 0, NULL, NULL);

    size_t len = BIO_pending(bio);
    unsigned char *key_pem = (unsigned char *)malloc(len);
    BIO_read(bio, key_pem, len);

    printf("Private Key (Hexadecimal):\n");
    print_hex(key_pem, len);

    BIO_free(bio);
    free(key_pem);
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_PKEY *rsa_keypair = generate_rsa_keypair();
    EVP_PKEY *public_key = extract_public_key(rsa_keypair);
    EVP_PKEY *private_key = extract_private_key(rsa_keypair);
    
    print_public_key_hex(public_key);
    print_private_key_hex(private_key);

    unsigned char *rsa_encrypted_aes_key = NULL;
    unsigned char *rsa_decrypted_aes_key = NULL;

    uint8_t test_aes_key[AES_KEY_SIZE];
    randombytes(test_aes_key, AES_KEY_SIZE);

    int rsa_encrypted_aes_key_len = rsa_encrypt(public_key, test_aes_key, sizeof(test_aes_key), &rsa_encrypted_aes_key);

    int rsa_decrypted_aes_key_len = rsa_decrypt(private_key, rsa_encrypted_aes_key, rsa_encrypted_aes_key_len, &rsa_decrypted_aes_key);

    free(rsa_encrypted_aes_key);
    free(rsa_decrypted_aes_key);

    EVP_PKEY_free(rsa_keypair);
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);

    return 0;
}


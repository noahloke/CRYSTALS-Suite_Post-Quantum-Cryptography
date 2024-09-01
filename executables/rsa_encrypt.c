#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h> // For PEM handling
#include <openssl/rsa.h> // For RSA handling
#include <ctype.h>

#define AES_KEY_SIZE 32 // 256 bits (32 bytes)

void handleErrors(void);
void print_hex(const unsigned char *data, size_t length);
int rsa_encrypt(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plaintext_len, unsigned char **encrypted);
unsigned char* hex_to_bytes(const char *hex_str);

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

unsigned char* hex_to_bytes(const char *hex_str) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) {
        fprintf(stderr, "Hex string length should be even.\n");
        exit(EXIT_FAILURE);
    }

    size_t bytes_len = len / 2;
    unsigned char *bytes = (unsigned char *)malloc(bytes_len);

    for (size_t i = 0; i < len; i += 2) {
        sscanf(&hex_str[i], "%02hhx", &bytes[i / 2]); // Correct format specifier
    }

    return bytes;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <AES256 key in hex> <RSA public key in hex>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Convert AES key from hex to bytes
    const char *aes_hex = argv[1];
    unsigned char *aes_key = hex_to_bytes(aes_hex);

    // Convert RSA public key from hex to PEM
    const char *rsa_pub_hex = argv[2];
    unsigned char *pub_key_bytes = hex_to_bytes(rsa_pub_hex);

    BIO *bio = BIO_new_mem_buf(pub_key_bytes, -1);
    EVP_PKEY *public_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!public_key) {
        fprintf(stderr, "Error reading public key.\n");
        handleErrors();
    }

    // Encrypt the AES key using RSA public key
    unsigned char *encrypted_aes_key = NULL;
    int encrypted_len = rsa_encrypt(public_key, aes_key, AES_KEY_SIZE, &encrypted_aes_key);

    // Print encrypted AES key in hex
    printf("Encrypted AES key (Hexadecimal):\n");
    print_hex(encrypted_aes_key, encrypted_len);

    // Clean up
    BIO_free(bio);
    free(aes_key);
    free(pub_key_bytes);
    free(encrypted_aes_key);
    EVP_PKEY_free(public_key);

    return 0;
}


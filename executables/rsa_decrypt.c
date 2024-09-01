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

void handleErrors(void);
void print_hex(const unsigned char *data, size_t length);
unsigned char* hex_to_bytes(const char *hex_str);
int rsa_decrypt(EVP_PKEY *privkey, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **decrypted);

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

unsigned char* hex_to_bytes(const char *hex_str) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) {
        fprintf(stderr, "Hex string length should be even.\n");
        exit(EXIT_FAILURE);
    }

    size_t bytes_len = len / 2;
    unsigned char *bytes = (unsigned char *)malloc(bytes_len);

    for (size_t i = 0; i < len; i += 2) {
        sscanf(&hex_str[i], "%02hhx", &bytes[i / 2]); // Proper format specifier for unsigned char
    }

    return bytes;
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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <encrypted AES key in hex> <RSA private key in hex>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Convert encrypted AES key from hex to bytes
    const char *encrypted_aes_hex = argv[1];
    unsigned char *encrypted_aes = hex_to_bytes(encrypted_aes_hex);

    // Convert RSA private key from hex to PEM
    const char *rsa_priv_hex = argv[2];
    unsigned char *priv_key_bytes = hex_to_bytes(rsa_priv_hex);

    BIO *bio = BIO_new_mem_buf(priv_key_bytes, -1);
    EVP_PKEY *private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!private_key) {
        fprintf(stderr, "Error reading private key.\n");
        handleErrors();
    }

    // Decrypt the encrypted AES key using RSA private key
    unsigned char *decrypted_aes_key = NULL;
    int decrypted_len = rsa_decrypt(private_key, encrypted_aes, strlen(argv[1]) / 2, &decrypted_aes_key);

    // Print the decrypted AES key in hexadecimal
    printf("Decrypted AES key (Hexadecimal):\n");
    print_hex(decrypted_aes_key, decrypted_len);

    // Clean up
    BIO_free(bio);
    free(encrypted_aes);
    free(priv_key_bytes);
    free(decrypted_aes_key);
    EVP_PKEY_free(private_key);

    return 0;
}


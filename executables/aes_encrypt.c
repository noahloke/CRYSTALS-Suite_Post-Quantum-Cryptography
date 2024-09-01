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
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *iv, unsigned char *plaintext);
void hex_to_bytes(const char *hex_str, unsigned char *byte_array, size_t byte_array_len);

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void hex_to_bytes(const char *hex_str, unsigned char *byte_array, size_t byte_array_len) {
    for (size_t i = 0; i < byte_array_len; i++) {
        sscanf(&hex_str[i * 2], "%2hhx", &byte_array[i]);  // Convert each pair of hex digits into a byte
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        return 1;
    }

    char *hex_aes_key = argv[2];
    uint8_t aes_key[CRYPTO_BYTES];
    hex_to_bytes(hex_aes_key, aes_key, CRYPTO_BYTES);

    //randombytes(aes_key, CRYPTO_BYTES);
    //"f97b06ab10f76f6d79bb8c0fb55c522ff3f795d569295a6b2a17cc8898d8440f"

    // Generate a random IV
    const char *hex_iv = "81fe99c1cb4e33adc525b111774680da";
    unsigned char iv[AES_BLOCK_SIZE]  = {0};

    hex_to_bytes(hex_iv, iv, AES_BLOCK_SIZE);

    /*
    RAND_bytes(iv, sizeof(iv));
    printf("IV (Hexadecimal): ");
    for(size_t i = 0; i < sizeof(iv); i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");
    */

    // Allocate memory for ciphertext that might be larger than plaintext due to padding
    unsigned char *plaintext = (unsigned char *)argv[1];
    int plaintext_len = strlen((char *)plaintext);
    unsigned char ciphertext[1024];

    int ciphertext_len = aes_encrypt(plaintext, plaintext_len, aes_key, iv, ciphertext);
    

    printf("Ciphertext (Hexadecimal): ");
    for(int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}

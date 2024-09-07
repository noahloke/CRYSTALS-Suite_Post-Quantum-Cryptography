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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <message to encrypt>\n", argv[0]);
        return 1;
    }

    clock_t start, end;
    clock_t temp_start, temp_end;
    double seconds;
    start = clock();

    uint8_t personA_pk[CRYPTO_PUBLICKEYBYTES];
    printf("Allocating space for Person A's public key with %d bytes: Success\n", CRYPTO_PUBLICKEYBYTES);

    uint8_t personA_sk[CRYPTO_SECRETKEYBYTES];
    printf("Allocating space for Person A's secret key with %d bytes: Success\n", CRYPTO_SECRETKEYBYTES);

    static uint8_t shared_aes_key[CRYPTO_BYTES];
    printf("Allocating space for the original AES key with %d bytes: Success\n", CRYPTO_BYTES);

    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    printf("Allocating space for the ciphertext with %d bytes: Success\n", CRYPTO_CIPHERTEXTBYTES);

    uint8_t dec_ct[CRYPTO_BYTES];
    printf("Allocating space for the decapsulated ciphertext with %d bytes: Success\n\n", CRYPTO_BYTES);

    temp_start = clock();
    if (crypto_kem_keypair(personA_pk, personA_sk) == 0) {
        temp_end = clock();
        seconds = ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;
        printf("%-200sExecution Time: %f seconds\n", "Person A generates a public/private key pair: Success", seconds);
    } else {
        temp_end = clock();
        printf("%-200s", "Person A generates a public/private key pair: Failure");
        seconds = ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;
        printf("Execution Time: %f seconds\n", seconds);
    }
    
    printf("Public Key (Hexadecimal): ");
    for(int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        printf("%02x", personA_pk[i]);
    }
    printf("\n");
    
    printf("Private Key (Hexadecimal): ");
    for(int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
        printf("%02x", personA_sk[i]);
    }
    printf("\n\n");

    printf("Person A sends their KYBER public key to Person B over a possible insecure channel (not implemented)\n");

    temp_start = clock();
    randombytes(shared_aes_key, CRYPTO_BYTES);
    temp_end = clock();
    printf("%-200s", "Person B generates an AES-256 key to serve as a shared secret: Success");
    seconds = ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;
    printf("Execution Time: %f seconds\n", seconds);
    
    temp_start = clock();
    if (crypto_kem_enc(ct, shared_aes_key, personA_pk) == 0) {
        temp_end = clock();
        seconds = ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;
        printf("%-200sExecution Time: %f seconds\n", "Person B uses Person A's public key to encapsulate the shared AES key: Success", seconds);
    } else {
        temp_end = clock();
        printf("%-200s", "Person B uses Person A's public key to encapsulate the shared AES key: Failure");
        seconds = ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;
        printf("Execution Time: %f seconds\n", seconds);
    }
    
    printf("Encapsulated Key (Hexadecimal): ");
    for(int i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) {
        printf("%02x", ct[i]);
    }
    printf("\n\n");

    printf("Person B sends the encapsulated key to Person A over a possible insecure channel (not implemented)\n");

    temp_start = clock();
    if (crypto_kem_dec(dec_ct, ct, personA_sk) == 0) {
        temp_end = clock();
        seconds = ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;
        printf("%-200sExecution Time: %f seconds\n\n", "Person A uses their secret key to decapsulate the shared AES key: Success", seconds);
    } else {
        temp_end = clock();
        printf("%-200s", "Person A uses their secret key to decapsulate the shared AES key: Failure");
        seconds = ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;
        printf("Execution Time: %f seconds\n\n", seconds);
    }
	
    printf("Shared AES Key (Hexadecimal): ");
    for(int i = 0; i < CRYPTO_BYTES; i++) {
        printf("%02x", dec_ct[i]);
    }
    printf("\n");
    
    printf("Secure key exchange complete.\n\n");

    printf("Communication with Shared AES Key Test:\n\n");

    // Generate a random IV
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, sizeof(iv));

    // Allocate memory for ciphertext that might be larger than plaintext due to padding
    unsigned char *plaintext = (unsigned char *)argv[1];
    int plaintext_len = strlen((char *)plaintext);
    unsigned char ciphertext[1024];
    unsigned char decryptedtext[1024];

    // Input Sanitization
    size_t input_length = strlen((char *)plaintext);

    // Check input size
    if (input_length > MAX_INPUT_SIZE) {
        fprintf(stderr, "Invalid input. Max Input Size: %d characters\n", MAX_INPUT_SIZE);
        return 1;
    }

    // Validate input
    for (size_t i = 0; i < input_length; i++) {
        if (!isprint(plaintext[i])) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }
    }

    // Encrypt the plaintext
    temp_start = clock();
    int ciphertext_len = aes_encrypt(plaintext, plaintext_len, shared_aes_key, iv, ciphertext);
    temp_end = clock();
    seconds = ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;
    printf("%-200sExecution Time: %f seconds\n", "Person A encrypts the user input using the shared key: Success", seconds);

    printf("Ciphertext (Hexadecimal): ");
    for(int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    printf("Person A sends the encrypted user input to Person B over a possible insecure channel (not implemented)\n");

    // Decrypt the ciphertext
    temp_start = clock();
    int decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len, dec_ct, iv, decryptedtext);
    temp_end = clock();
    
    // Add a NULL terminator to the decrypted text
    decryptedtext[decryptedtext_len] = '\0';

    seconds = ((double) (temp_end - temp_start)) / CLOCKS_PER_SEC;
    printf("%-200sExecution Time: %f seconds\n", "Person B decrypts the encrypted user input using the shared key: Success", seconds);

    printf("The decrypted output is: \"%s\"\n\n", decryptedtext);

    end = clock();
    seconds = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Total execution time: %f seconds\n\n", seconds);

    return 0;
}

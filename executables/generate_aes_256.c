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

int main() {
    uint8_t shared_aes_key[CRYPTO_BYTES];

    randombytes(shared_aes_key, CRYPTO_BYTES);

    printf("Shared AES Key (Hexadecimal): ");
    for(int i = 0; i < CRYPTO_BYTES; i++) {
        printf("%02x", shared_aes_key[i]);
    }
    printf("\n");
    
    return 0;
}

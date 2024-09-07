#include <stdio.h>
#include <stdint.h>
#include "../randombytes.h"
#include "../sign.h"

#define MLEN 59 // (bytes)

int main(void) {
    size_t mlen, smlen; // message and signed message length
    printf("Allocating space for the message and signed message lengths: Success\n");
    
    uint8_t m[MLEN]; // message
    printf("Allocating space for a message of %d bytes: Success\n", MLEN);
    
    uint8_t m2[MLEN]; // message to be verified
    printf("Allocating space for a received message of %d bytes: Success\n", MLEN);
        
    uint8_t sm[MLEN + CRYPTO_BYTES]; // signed message
    printf("Allocating space for a signed message of %d bytes: Success\n", MLEN + CRYPTO_BYTES);
    
    uint8_t pk[CRYPTO_PUBLICKEYBYTES]; // public key
    printf("Allocating space for Dilithium public key of %d bytes: Success\n", CRYPTO_PUBLICKEYBYTES);
    
    uint8_t sk[CRYPTO_SECRETKEYBYTES]; // secret key
    printf("Allocating space for Dilithium secret key of %d bytes: Success\n\n", CRYPTO_SECRETKEYBYTES);
    
    int ret; // return value

    // Generate a random message
    randombytes(m, MLEN);
    printf("Generating a random message: Success\n");
    
    printf("Message (Hexadecimal): ");
    for(int i = 0; i < MLEN; i++) {
        printf("%02x", m[i]);
    }
    printf("\n\n");

    // Generate key pair
    crypto_sign_keypair(pk, sk);
    printf("Generating a Dilithium key pair: Success\n");
    
    printf("Public Key (Hexadecimal): ");
    for(int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        printf("%02x", pk[i]);
    }
    printf("\n\n");
    
    printf("Secret Key (Hexadecimal): ");
    for(int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
        printf("%02x", sk[i]);
    }
    printf("\n\n");

    // Sign the message
    crypto_sign(sm, &smlen, m, MLEN, sk);
    printf("Signing the message: Success\n");
    
    printf("Signed Message (Hexadecimal): ");
    for(int i = 0; i < MLEN + CRYPTO_BYTES; i++) {
        printf("%02x", sm[i]);
    }
    printf("\n\n");
    
    printf("The signed message is sent from the signer to the verifier (not implemented).\n\n");

    // Try to open the signed message
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
    printf("The message is opened: Success\n");
    
    printf("Received Message (Hexadecimal): ");
    for(int i = 0; i < MLEN; i++) {
        printf("%02x", m2[i]);
    }
    printf("\n\n");
    
    printf("Checking validity...\t");
    // Compare the original message with the opened message
    if(ret == 0) {
        for(size_t i = 0; i < MLEN; ++i) {
            if(m[i] != m2[i]) {
                printf("Error.\n");
                return -1;
            }
        }
        printf("Message successfully signed, verified, and matched.\n");
    } else {
        printf("Error.\n");
    }

    return 0;
}

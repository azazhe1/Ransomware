#include <stdio.h>
#include <stdlib.h>
#include "encrypt.h"

void handleErrors(const char *error) {
    fprintf(stderr, "Erreur : %s\n", error);
    exit(EXIT_FAILURE);
}
void encrypt_aes_key(const char *public_key_file, unsigned char *aes_key, unsigned char *encrypted_key, size_t *encrypted_key_len) {
    FILE *pub_file = fopen(public_key_file, "rb");
    if (!pub_file) handleErrors("fopen (clé publique)");

    EVP_PKEY *pkey = PEM_read_PUBKEY(pub_file, NULL, NULL, NULL);
    fclose(pub_file);
    if (!pkey) handleErrors("PEM_read_PUBKEY");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) handleErrors("EVP_PKEY_CTX_new");

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors("EVP_PKEY_encrypt_init");

    if (EVP_PKEY_encrypt(ctx, NULL, encrypted_key_len, aes_key, AES_KEY_SIZE) <= 0) handleErrors("EVP_PKEY_encrypt");

    if (EVP_PKEY_encrypt(ctx, encrypted_key, encrypted_key_len, aes_key, AES_KEY_SIZE) <= 0) handleErrors("EVP_PKEY_encrypt");

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

void create_key(void){
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char encrypted_key[256];
    size_t encrypted_key_len;

    RAND_bytes(aes_key, AES_KEY_SIZE);
    RAND_bytes(iv, AES_BLOCK_SIZE);
    
    printf("AES key:            ");
    for (size_t i = 0; i < AES_KEY_SIZE; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");

    encrypt_aes_key("public.pem", aes_key, encrypted_key, &encrypted_key_len);

    FILE *key_file = fopen("aes_key.enc", "wb");
    fwrite(encrypted_key, 1, encrypted_key_len, key_file);
    fclose(key_file);

    encrypt_file("plaintext.txt", "encrypted.dat", aes_key, iv);

}


void encrypt_file(const char *input_filename, const char *output_filename, unsigned char *aes_key, unsigned char *iv) {
    FILE *in = fopen(input_filename, "rb");
    FILE *out = fopen(output_filename, "wb");
    if (!in || !out) handleErrors("fopen fichier");

    fwrite(iv, 1, AES_BLOCK_SIZE, out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);

    unsigned char buffer[AES_BLOCK_SIZE];
    unsigned char ciphertext[AES_BLOCK_SIZE + AES_BLOCK_SIZE];
    int len;

    while ((len = fread(buffer, 1, AES_BLOCK_SIZE, in)) > 0) {
        EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, len);
        fwrite(ciphertext, 1, len, out);
    }
    EVP_EncryptFinal_ex(ctx, ciphertext, &len);
    fwrite(ciphertext, 1, len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}
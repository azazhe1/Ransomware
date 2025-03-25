#include <stdio.h>
#include <stdlib.h>
#include "decrypt.h"

void decrypt_aes_key(const char *private_key_file, unsigned char *encrypted_key, size_t encrypted_key_len, unsigned char *aes_key) {
    FILE *priv_file = fopen(private_key_file, "rb");
    if (!priv_file) handleErrors("fopen (clé privée)");

    EVP_PKEY *pkey = PEM_read_PrivateKey(priv_file, NULL, NULL, NULL);
    fclose(priv_file);
    if (!pkey) handleErrors("PEM_read_PrivateKey");

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) handleErrors("EVP_PKEY_CTX_new");

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors("EVP_PKEY_decrypt_init");


    size_t decrypted_key_len;
    if (EVP_PKEY_decrypt(ctx, NULL, &decrypted_key_len, encrypted_key, encrypted_key_len) <= 0) 
        handleErrors("EVP_PKEY_decrypt (taille)");

    if (EVP_PKEY_decrypt(ctx, aes_key, &decrypted_key_len, encrypted_key, encrypted_key_len) <= 0) 
        handleErrors("EVP_PKEY_decrypt");


    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

void decrypt_key(void){
    unsigned char encrypted_key[256];
    size_t encrypted_key_len;
    FILE *key_file = fopen("aes_key.enc", "rb");
    if (!key_file) handleErrors("fopen (clé chiffrée)");

    encrypted_key_len = fread(encrypted_key, 1, sizeof(encrypted_key), key_file);
    fclose(key_file);

    unsigned char aes_key[AES_KEY_SIZE];
    decrypt_aes_key("private.pem", encrypted_key, encrypted_key_len, aes_key);

    printf("Clé AES déchiffrée: ");
    for (size_t i = 0; i < AES_KEY_SIZE; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");

    decrypt_file("encrypted.dat", "decrypted.txt", aes_key);
}

void decrypt_file(const char *input_filename, const char *output_filename, unsigned char *aes_key) {
    FILE *in = fopen(input_filename, "rb");
    FILE *out = fopen(output_filename, "wb");
    if (!in || !out) handleErrors("fopen fichier");

    unsigned char iv[AES_BLOCK_SIZE];
    fread(iv, 1, AES_BLOCK_SIZE, in); // Lire l'IV stocké

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);

    unsigned char buffer[AES_BLOCK_SIZE + AES_BLOCK_SIZE];
    unsigned char plaintext[AES_BLOCK_SIZE];
    int len;

    while ((len = fread(buffer, 1, AES_BLOCK_SIZE + AES_BLOCK_SIZE, in)) > 0) {
        EVP_DecryptUpdate(ctx, plaintext, &len, buffer, len);
        fwrite(plaintext, 1, len, out);
    }
    EVP_DecryptFinal_ex(ctx, plaintext, &len);
    fwrite(plaintext, 1, len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}
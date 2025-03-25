#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 32  // Clé AES 256 bits
#define AES_BLOCK_SIZE 16



void handleErrors(const char *error);
void decrypt_aes_key(const char *private_key_file, unsigned char *encrypted_key, size_t encrypted_key_len, unsigned char *aes_key);
void decrypt_key(void);
void decrypt_file(const char *input_filename, const char *output_filename, unsigned char *aes_key);
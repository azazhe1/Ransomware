#include <stdio.h>
#include <stdlib.h>
#include "encrypt.h"
#include "decrypt.h"



int main(int argc, char *argv[]) {
    create_key();
    decrypt_key();

    return 0;
}
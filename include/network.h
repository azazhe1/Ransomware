#include <curl/curl.h>

#ifndef SERVER_IP
    #define SERVER_IP "127.0.0.1"
#endif

void send_data(char *key, char *data, char *url);
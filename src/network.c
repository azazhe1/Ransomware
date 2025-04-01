#include <stdio.h>
#include <stdlib.h>
#include "network.h"
#include "encrypt.h"
#include <stdio.h>

/*Avoid libculr to show the ouput of a request */
static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata){
    (void) ptr;
    (void) userdata;
    return size*nmemb;
}

void send_data(char *key, char *data, char *url){
    CURL *curl;
    CURLcode res;
    char post_data[1024];

    struct curl_slist *chunk = NULL;


    snprintf(post_data, sizeof(post_data), "{\"%s\": \"%s\"}", key,data);

    curl = curl_easy_init();
    if(curl){
        chunk = curl_slist_append(chunk, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
    
        res = curl_easy_perform(curl);
        if(res != CURLE_OK){
            fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
            exit(EXIT_FAILURE);
        }
    
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
    }
    curl_global_cleanup();
}
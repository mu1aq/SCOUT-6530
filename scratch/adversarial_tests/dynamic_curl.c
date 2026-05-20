// Mocking libcurl symbols for headerless compilation
typedef void CURL;
typedef int CURLoption;
typedef int CURLcode;

#define CURLOPT_SSL_VERIFYPEER 64

extern CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...);
extern CURL *curl_easy_init(void);
extern void curl_easy_cleanup(CURL *curl);
extern char *getenv(const char *name);
extern int atoi(const char *nptr);

void dynamic_curl_io(CURL *curl) {
    char *env_val = getenv("INSECURE_MODE");
    long verify = 1L; 
    
    if (env_val && atoi(env_val) == 1) {
        verify = 0L; 
    }

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);
    }
}

int main() {
    CURL *curl = curl_easy_init();
    dynamic_curl_io(curl);
    curl_easy_cleanup(curl);
    return 0;
}

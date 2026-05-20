// Mocking libcurl symbols to test SCOUT 2.0 without headers
typedef void CURL;
typedef int CURLoption;
typedef int CURLcode;

#define CURLOPT_SSL_VERIFYPEER 64
#define CURLOPT_SSL_VERIFYHOST 81

extern CURLcode curl_easy_setopt(CURL *curl, CURLoption option, ...);
extern CURL *curl_easy_init(void);
extern CURLcode curl_easy_perform(CURL *curl);
extern void curl_easy_cleanup(CURL *curl);

void secure_curl_io(CURL *curl) {
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_perform(curl);
    }
}

int main() {
    CURL *curl = curl_easy_init();
    secure_curl_io(curl);
    curl_easy_cleanup(curl);
    return 0;
}

// Dummy libcurl implementation to satisfy the linker
void* curl_easy_init() { return (void*)1; }
int curl_easy_setopt(void* curl, int opt, ...) { return 0; }
int curl_easy_perform(void* curl) { return 0; }
void curl_easy_cleanup(void* curl) {}

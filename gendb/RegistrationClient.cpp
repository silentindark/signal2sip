#include "RegistrationClient.h"

#include <curl/curl.h>

#include <stdexcept>

namespace signal2sip {

namespace {

// Same CA cert every native TLS client in this project pins - see
// main.cpp's AuthSocket construction.
constexpr const char* kCaCertPath = "/home/vlad/GIT/vladonv/signal2sip/layer1/certs/signal-root-ca.pem";

size_t writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    static_cast<std::string*>(userdata)->append(ptr, size * nmemb);
    return size * nmemb;
}

} // namespace

RegistrationClient::RegistrationClient(std::string serverHost) : serverHost_(std::move(serverHost)) {}

HttpResponse RegistrationClient::request(const std::string& method, const std::string& path,
                                         const std::string& jsonBody, const std::string& basicAuthUser,
                                         const std::string& basicAuthPass) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");

    std::string url = "https://" + serverHost_ + path;
    std::string responseBody;
    struct curl_slist* headers = nullptr;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CAINFO, kCaCertPath);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    if (method == "GET") {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    } else {
        // POST/PUT/PATCH - all our calls carry a JSON body (possibly empty).
        if (method != "POST") curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonBody.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(jsonBody.size()));
        if (method == "POST") curl_easy_setopt(curl, CURLOPT_POST, 1L);
    }

    if (!jsonBody.empty()) headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (!basicAuthUser.empty()) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        std::string userpwd = basicAuthUser + ":" + basicAuthPass;
        curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd.c_str());
    }

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::string error = curl_easy_strerror(res);
        if (headers) curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        throw std::runtime_error("HTTP request to " + path + " failed: " + error);
    }

    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return HttpResponse{status, responseBody};
}

} // namespace signal2sip

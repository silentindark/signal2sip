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

HttpResponse doRequest(const std::string& serverHost, const std::string& method, const std::string& path,
                        const std::string& body, const std::string& contentType, const std::string& basicAuthUser,
                        const std::string& basicAuthPass) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl_easy_init failed");

    std::string url = "https://" + serverHost + path;
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
        if (method != "POST") curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        if (method == "POST") curl_easy_setopt(curl, CURLOPT_POST, 1L);
    }

    if (!body.empty()) headers = curl_slist_append(headers, ("Content-Type: " + contentType).c_str());
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

} // namespace

RegistrationClient::RegistrationClient(std::string serverHost) : serverHost_(std::move(serverHost)) {}

HttpResponse RegistrationClient::request(const std::string& method, const std::string& path,
                                         const std::string& jsonBody, const std::string& basicAuthUser,
                                         const std::string& basicAuthPass) {
    return doRequest(serverHost_, method, path, jsonBody, "application/json", basicAuthUser, basicAuthPass);
}

HttpResponse RegistrationClient::requestRaw(const std::string& method, const std::string& path,
                                            const std::string& body, const std::string& contentType,
                                            const std::string& basicAuthUser, const std::string& basicAuthPass) {
    return doRequest(serverHost_, method, path, body, contentType, basicAuthUser, basicAuthPass);
}

} // namespace signal2sip

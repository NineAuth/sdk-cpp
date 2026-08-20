#include "../NineAuth-CPP-EXAMPLE/client.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <bcrypt.h>

#else
#include <openssl/rand.h>
#endif

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <iostream>

using json = nlohmann::json;

namespace nineauth {

    namespace {

        // Callback for capturing HTTP response data from libcurl
        size_t CurlWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
            size_t total_size = size * nmemb;
            auto* str = static_cast<std::string*>(userp);
            str->append(static_cast<char*>(contents), total_size);
            return total_size;
        }

        // Generates 16 cryptographically random bytes via CSPRNG (BCryptGenRandom / OpenSSL) and encodes as 32 hex chars
        std::string GenerateCryptographicNonce() {
            unsigned char buffer[16];
#if defined(_WIN32)
            NTSTATUS status = BCryptGenRandom(nullptr, buffer, sizeof(buffer), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (!BCRYPT_SUCCESS(status)) {
                for (auto& byte : buffer) {
                    byte = static_cast<unsigned char>(rand() % 256);
                }
            }
#else
            if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
                for (auto& byte : buffer) {
                    byte = static_cast<unsigned char>(rand() % 256);
                }
            }
#endif

            std::ostringstream ss;
            ss << std::hex << std::setfill('0');
            for (unsigned char byte : buffer) {
                ss << std::setw(2) << static_cast<int>(byte);
            }
            return ss.str();
        }

        // Formats current system UTC time as ISO 8601: "YYYY-MM-DDTHH:mm:ss.fffZ"
        std::string GetCurrentUtcIso8601() {
            auto now = std::chrono::system_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
            auto timer = std::chrono::system_clock::to_time_t(now);

            std::tm gmt{};
#if defined(_WIN32)
            gmtime_s(&gmt, &timer);
#else
            gmtime_r(&timer, &gmt);
#endif

            std::ostringstream ss;
            ss << std::put_time(&gmt, "%Y-%m-%dT%H:%M:%S")
                << '.' << std::setfill('0') << std::setw(3) << ms.count()
                << 'Z';
            return ss.str();
        }

        // Parses an ISO 8601 UTC string into a std::chrono time_point for comparison
        bool IsTimestampExpired(const std::string& iso_str) {
            if (iso_str.empty()) return true;

            std::tm t{};
            int ms = 0;
#if defined(_WIN32)
            int count = sscanf_s(iso_str.c_str(), "%d-%d-%dT%d:%d:%d.%dZ",
                &t.tm_year, &t.tm_mon, &t.tm_mday,
                &t.tm_hour, &t.tm_min, &t.tm_sec, &ms);
            if (count < 6) {
                count = sscanf_s(iso_str.c_str(), "%d-%d-%dT%d:%d:%dZ",
                    &t.tm_year, &t.tm_mon, &t.tm_mday,
                    &t.tm_hour, &t.tm_min, &t.tm_sec);
            }
#else
            int count = sscanf(iso_str.c_str(), "%d-%d-%dT%d:%d:%d.%dZ",
                &t.tm_year, &t.tm_mon, &t.tm_mday,
                &t.tm_hour, &t.tm_min, &t.tm_sec, &ms);
            if (count < 6) {
                count = sscanf(iso_str.c_str(), "%d-%d-%dT%d:%d:%dZ",
                    &t.tm_year, &t.tm_mon, &t.tm_mday,
                    &t.tm_hour, &t.tm_min, &t.tm_sec);
            }
#endif
            if (count < 6) return true;

            t.tm_year -= 1900;
            t.tm_mon -= 1;

#if defined(_WIN32)
            time_t target_time = _mkgmtime(&t);
#else
            time_t target_time = timegm(&t);
#endif
            time_t current_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

            return current_time >= target_time;
        }

        static std::string SafeString(const json& j, const char* key, const std::string& def = "") {
            if (!j.is_object()) return def;
            auto it = j.find(key);
            if (it == j.end() || it->is_null()) return def;
            if (it->is_string()) return it->get<std::string>();
            return def;
        }

        static bool SafeBool(const json& j, const char* key, bool def = false) {
            if (!j.is_object()) return def;
            auto it = j.find(key);
            if (it == j.end() || it->is_null()) return def;
            if (it->is_boolean()) return it->get<bool>();
            return def;
        }

    } // namespace

    struct NineAuthClient::Impl {
        Options options;
        ApplicationInfo app_info;
        std::string access_token;
        std::string refresh_token;
        std::string access_expires_at;
        std::string refresh_expires_at;
        std::vector<std::string> entitlements;
        bool is_initialized{ false };

        explicit Impl(const Options& opt) : options(opt) {
            if (!options.api_url.empty() && options.api_url.back() == '/') {
                options.api_url.pop_back();
            }
        }

        void ClearSession() {
            access_token.clear();
            refresh_token.clear();
            access_expires_at.clear();
            refresh_expires_at.clear();
            entitlements.clear();
        }

        struct HttpResponse {
            long status_code{ 0 };
            std::string raw_body;
            json json_body;
            bool curl_ok{ false };
            std::string curl_error;
        };

        HttpResponse SendHttpRequest(
            const std::string& method,
            const std::string& endpoint,
            const json& body_payload,
            bool include_auth
        ) {
            HttpResponse result;
            CURL* curl = curl_easy_init();
            if (!curl) {
                result.curl_ok = false;
                result.curl_error = "Failed to initialize libcurl easy handle";
                return result;
            }

            std::string full_url = options.api_url + endpoint;
            curl_easy_setopt(curl, CURLOPT_URL, full_url.c_str());
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(options.timeout_seconds));
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

            // Header list
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            headers = curl_slist_append(headers, "Accept: application/json");
            headers = curl_slist_append(headers, "User-Agent: NineAuth-SDK-CPP/2.0.0");

            std::string app_id_header = "x-application-id: " + options.application_id;
            headers = curl_slist_append(headers, app_id_header.c_str());

            std::string env_header = "x-nineauth-env: " + options.environment;
            headers = curl_slist_append(headers, env_header.c_str());

            if (include_auth && !access_token.empty()) {
                std::string auth_header = "Authorization: Bearer " + access_token;
                headers = curl_slist_append(headers, auth_header.c_str());
            }

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

            std::string serialized_body;
            if (!body_payload.is_null()) {
                serialized_body = body_payload.dump();
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, serialized_body.c_str());
            }
            else if (method == "POST") {
                // Empty POST body
                serialized_body = "{}";
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, serialized_body.c_str());
            }

            if (method == "GET") {
                curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            }
            else if (method == "DELETE") {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            }

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.raw_body);

            CURLcode res = curl_easy_perform(curl);
            if (res == CURLE_OK) {
                result.curl_ok = true;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.status_code);

                if (!result.raw_body.empty()) {
                    try {
                        result.json_body = json::parse(result.raw_body);
                    }
                    catch (...) {
                        result.json_body = json::object();
                    }
                }
            }
            else {
                result.curl_ok = false;
                result.curl_error = curl_easy_strerror(res);
            }

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return result;
        }

        template <typename T>
        Result<T> ParseErrorResponse(const HttpResponse& response, const std::string& fallback_code = "API_ERROR") {
            if (!response.curl_ok) {
                return Result<T>::Err("NETWORK_ERROR", response.curl_error);
            }

            std::string code = fallback_code;
            std::string message = "Request failed with HTTP " + std::to_string(response.status_code);

            if (response.json_body.is_object()) {
                if (response.json_body.contains("error")) {
                    if (response.json_body["error"].is_object()) {
                        auto err_obj = response.json_body["error"];
                        if (err_obj.contains("code") && err_obj["code"].is_string()) {
                            code = err_obj["code"].get<std::string>();
                        }
                        if (err_obj.contains("message") && err_obj["message"].is_string()) {
                            message = err_obj["message"].get<std::string>();
                        }
                    }
                    else if (response.json_body["error"].is_string()) {
                        code = response.json_body["error"].get<std::string>();
                    }
                }

                if (response.json_body.contains("error_code") && response.json_body["error_code"].is_string()) {
                    code = response.json_body["error_code"].get<std::string>();
                }
                else if (response.json_body.contains("code") && response.json_body["code"].is_string()) {
                    code = response.json_body["code"].get<std::string>();
                }

                if (response.json_body.contains("message") && response.json_body["message"].is_string()) {
                    message = response.json_body["message"].get<std::string>();
                }
            }

            return Result<T>::Err(code, message);
        }
    };

    NineAuthClient::NineAuthClient(const Options& options)
        : m_impl(std::make_unique<Impl>(options)) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    NineAuthClient::~NineAuthClient() = default;

    NineAuthClient::NineAuthClient(NineAuthClient&&) noexcept = default;
    NineAuthClient& NineAuthClient::operator=(NineAuthClient&&) noexcept = default;

    const Options& NineAuthClient::GetOptions() const noexcept {
        return m_impl->options;
    }

    const ApplicationInfo& NineAuthClient::GetApplicationInfo() const noexcept {
        return m_impl->app_info;
    }

    Result<void> NineAuthClient::Initialize() {
        if (m_impl->options.application_id.empty()) {
            return Result<void>::Err("CONFIG_ERROR", "Application ID is required to initialize NineAuthClient");
        }

        auto response = m_impl->SendHttpRequest("POST", "/v1/runtime/applications/init", json::object(), false);
        if (!response.curl_ok || response.status_code < 200 || response.status_code >= 300) {
            return m_impl->ParseErrorResponse<void>(response, "INIT_FAILED");
        }

        try {
            m_impl->app_info.application_id = SafeString(response.json_body, "application_id", m_impl->options.application_id);
            m_impl->app_info.name = SafeString(response.json_body, "name", "");
            m_impl->app_info.environment = SafeString(response.json_body, "environment", m_impl->options.environment);
            m_impl->is_initialized = true;
            return Result<void>::Ok();
        }
        catch (const std::exception& ex) {
            return Result<void>::Err("PARSE_ERROR", ex.what());
        }
    }

    Result<std::string> NineAuthClient::Register(const std::string& email, const std::string& password) {
        if (email.empty()) return Result<std::string>::Err("VALIDATION_ERROR", "Email cannot be empty");
        if (password.empty()) return Result<std::string>::Err("VALIDATION_ERROR", "Password cannot be empty");

        json payload = {
            {"email", email},
            {"password", password}
        };

        auto response = m_impl->SendHttpRequest("POST", "/v1/runtime/auth/register", payload, false);
        if (!response.curl_ok || response.status_code < 200 || response.status_code >= 300) {
            return m_impl->ParseErrorResponse<std::string>(response, "REGISTER_FAILED");
        }

        std::string user_id = SafeString(response.json_body, "user_id", "");
        return Result<std::string>::Ok(user_id);
    }

    Result<void> NineAuthClient::Login(
        const std::string& email,
        const std::string& password,
        const std::string& device_fingerprint
    ) {
        if (email.empty()) return Result<void>::Err("VALIDATION_ERROR", "Email cannot be empty");
        if (password.empty()) return Result<void>::Err("VALIDATION_ERROR", "Password cannot be empty");

        json payload = {
            {"email", email},
            {"password", password},
            {"timestamp", GetCurrentUtcIso8601()},
            {"nonce", GenerateCryptographicNonce()}
        };

        if (!device_fingerprint.empty()) {
            payload["device_fingerprint"] = device_fingerprint;
        }

        auto response = m_impl->SendHttpRequest("POST", "/v1/runtime/auth/login", payload, false);
        if (!response.curl_ok || response.status_code < 200 || response.status_code >= 300) {
            return m_impl->ParseErrorResponse<void>(response, "LOGIN_FAILED");
        }

        m_impl->access_token = SafeString(response.json_body, "access_token", "");
        m_impl->refresh_token = SafeString(response.json_body, "refresh_token", "");
        m_impl->access_expires_at = SafeString(response.json_body, "access_expires_at", "");
        m_impl->refresh_expires_at = SafeString(response.json_body, "refresh_expires_at", "");
        m_impl->entitlements.clear();

        return Result<void>::Ok();
    }

    Result<ActivateLicenseResult> NineAuthClient::ActivateLicense(
        const std::string& license_key,
        const std::string& device_fingerprint
    ) {
        if (license_key.empty()) return Result<ActivateLicenseResult>::Err("VALIDATION_ERROR", "License key cannot be empty");
        if (device_fingerprint.empty()) return Result<ActivateLicenseResult>::Err("VALIDATION_ERROR", "Device fingerprint cannot be empty");

        json payload = {
            {"license_key", license_key},
            {"device_fingerprint", device_fingerprint},
            {"timestamp", GetCurrentUtcIso8601()},
            {"nonce", GenerateCryptographicNonce()}
        };

        auto response = m_impl->SendHttpRequest("POST", "/v1/runtime/licenses/activate", payload, true);
        if (!response.curl_ok || response.status_code < 200 || response.status_code >= 300) {
            return m_impl->ParseErrorResponse<ActivateLicenseResult>(response, "ACTIVATION_FAILED");
        }

        try {
            ActivateLicenseResult result;
            result.access_token = SafeString(response.json_body, "access_token", "");
            result.refresh_token = SafeString(response.json_body, "refresh_token", "");
            result.access_expires_at = SafeString(response.json_body, "access_expires_at", "");
            result.refresh_expires_at = SafeString(response.json_body, "refresh_expires_at", "");

            if (response.json_body.contains("entitlements") && response.json_body["entitlements"].is_array()) {
                for (const auto& ent : response.json_body["entitlements"]) {
                    if (ent.is_string()) {
                        result.entitlements.push_back(ent.get<std::string>());
                    }
                }
            }

            if (response.json_body.contains("license") && response.json_body["license"].is_object()) {
                result.license.status = SafeString(response.json_body["license"], "status", "");
                result.license.expires_at = SafeString(response.json_body["license"], "expires_at", "");
            }

            // Update in-memory state
            m_impl->access_token = result.access_token;
            m_impl->refresh_token = result.refresh_token;
            m_impl->access_expires_at = result.access_expires_at;
            m_impl->refresh_expires_at = result.refresh_expires_at;
            m_impl->entitlements = result.entitlements;

            return Result<ActivateLicenseResult>::Ok(result);
        }
        catch (const std::exception& ex) {
            return Result<ActivateLicenseResult>::Err("PARSE_ERROR", ex.what());
        }
    }

    Result<ValidateSessionResult> NineAuthClient::ValidateSession() {
        if (m_impl->access_token.empty()) {
            return Result<ValidateSessionResult>::Err("NOT_AUTHENTICATED", "No active session in memory to validate");
        }

        json payload = {
            {"access_token", m_impl->access_token}
        };

        auto response = m_impl->SendHttpRequest("POST", "/v1/runtime/sessions/validate", payload, false);
        if (!response.curl_ok || response.status_code < 200 || response.status_code >= 300) {
            return m_impl->ParseErrorResponse<ValidateSessionResult>(response, "VALIDATION_FAILED");
        }

        try {
            ValidateSessionResult result;
            result.valid = SafeBool(response.json_body, "valid", false);
            result.expires_at = SafeString(response.json_body, "expires_at", "");
            result.reason = SafeString(response.json_body, "reason", "");

            if (response.json_body.contains("entitlements") && response.json_body["entitlements"].is_array()) {
                for (const auto& ent : response.json_body["entitlements"]) {
                    if (ent.is_string()) {
                        result.entitlements.push_back(ent.get<std::string>());
                    }
                }
            }

            if (result.valid) {
                m_impl->entitlements = result.entitlements;
            }
            else {
                m_impl->ClearSession();
            }

            return Result<ValidateSessionResult>::Ok(result);
        }
        catch (const std::exception& ex) {
            return Result<ValidateSessionResult>::Err("PARSE_ERROR", ex.what());
        }
    }

    bool NineAuthClient::HasEntitlement(const std::string& key) const {
        const auto& list = m_impl->entitlements;
        return std::find(list.begin(), list.end(), key) != list.end();
    }

    std::vector<std::string> NineAuthClient::GetEntitlements() const {
        return m_impl->entitlements;
    }

    Result<bool> NineAuthClient::CheckEntitlement(const std::string& key) {
        if (m_impl->access_token.empty()) {
            return Result<bool>::Err("NOT_AUTHENTICATED", "Active session required to check entitlement");
        }

        std::string endpoint = "/v1/runtime/entitlements/check?key=" + key;
        auto response = m_impl->SendHttpRequest("GET", endpoint, json(), true);
        if (!response.curl_ok || response.status_code < 200 || response.status_code >= 300) {
            return m_impl->ParseErrorResponse<bool>(response, "ENTITLEMENT_CHECK_FAILED");
        }

        bool granted = SafeBool(response.json_body, "granted", false);
        return Result<bool>::Ok(granted);
    }

    Result<void> NineAuthClient::RefreshSession() {
        if (m_impl->refresh_token.empty()) {
            return Result<void>::Err("NOT_AUTHENTICATED", "No refresh token present in memory");
        }

        json payload = {
            {"refresh_token", m_impl->refresh_token}
        };

        auto response = m_impl->SendHttpRequest("POST", "/v1/runtime/sessions/refresh", payload, false);
        if (!response.curl_ok || response.status_code < 200 || response.status_code >= 300) {
            m_impl->ClearSession();
            return m_impl->ParseErrorResponse<void>(response, "REFRESH_FAILED");
        }

        m_impl->access_token = SafeString(response.json_body, "access_token", "");
        m_impl->refresh_token = SafeString(response.json_body, "refresh_token", "");
        m_impl->access_expires_at = SafeString(response.json_body, "access_expires_at", "");
        m_impl->refresh_expires_at = SafeString(response.json_body, "refresh_expires_at", "");

        return Result<void>::Ok();
    }

    Result<bool> NineAuthClient::ResetDevice(
        const std::string& license_key,
        const std::string& device_fingerprint
    ) {
        if (license_key.empty()) return Result<bool>::Err("VALIDATION_ERROR", "License key cannot be empty");
        if (device_fingerprint.empty()) return Result<bool>::Err("VALIDATION_ERROR", "Device fingerprint cannot be empty");

        json payload = {
            {"license_key", license_key},
            {"device_fingerprint", device_fingerprint}
        };

        auto response = m_impl->SendHttpRequest("POST", "/v1/runtime/devices/reset", payload, false);
        if (!response.curl_ok || response.status_code < 200 || response.status_code >= 300) {
            return m_impl->ParseErrorResponse<bool>(response, "RESET_FAILED");
        }

        bool success = SafeBool(response.json_body, "success", false);
        return Result<bool>::Ok(success);
    }

    bool NineAuthClient::IsAuthenticated() const {
        if (m_impl->access_token.empty() || m_impl->access_expires_at.empty()) {
            return false;
        }
        return !IsTimestampExpired(m_impl->access_expires_at);
    }

    SessionState NineAuthClient::GetSessionState() const {
        SessionState state;
        state.access_token = m_impl->access_token;
        state.refresh_token = m_impl->refresh_token;
        state.access_expires_at = m_impl->access_expires_at;
        state.refresh_expires_at = m_impl->refresh_expires_at;
        state.entitlements = m_impl->entitlements;
        return state;
    }

    void NineAuthClient::RestoreSession(const SessionState& state) {
        m_impl->access_token = state.access_token;
        m_impl->refresh_token = state.refresh_token;
        m_impl->access_expires_at = state.access_expires_at;
        m_impl->refresh_expires_at = state.refresh_expires_at;
        m_impl->entitlements = state.entitlements;
    }

    Result<void> NineAuthClient::Logout() {
        if (m_impl->access_token.empty()) {
            m_impl->ClearSession();
            return Result<void>::Ok();
        }

        json payload = {
            {"access_token", m_impl->access_token}
        };

        auto response = m_impl->SendHttpRequest("POST", "/v1/runtime/auth/logout", payload, false);
        m_impl->ClearSession();

        if (!response.curl_ok || response.status_code < 200 || response.status_code >= 300) {
            return m_impl->ParseErrorResponse<void>(response, "LOGOUT_FAILED");
        }

        return Result<void>::Ok();
    }

} // namespace nineauth

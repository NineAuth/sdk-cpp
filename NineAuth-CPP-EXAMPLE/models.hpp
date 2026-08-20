#pragma once

#include <string>
#include <vector>

namespace nineauth {

    /// <summary>
    /// Verified application metadata returned upon client initialization.
    /// </summary>
    struct ApplicationInfo {
        std::string application_id{};
        std::string name{};
        std::string environment{};
    };

    /// <summary>
    /// Status and expiration metadata of an activated software license.
    /// </summary>
    struct LicenseInfo {
        std::string status{};
        std::string expires_at{}; // ISO 8601 UTC string or empty for perpetual
    };

    /// <summary>
    /// Result of license key activation and device binding.
    /// </summary>
    struct ActivateLicenseResult {
        std::string access_token{};
        std::string refresh_token{};
        std::string access_expires_at{};
        std::string refresh_expires_at{};
        std::vector<std::string> entitlements{};
        LicenseInfo license{};
    };

    /// <summary>
    /// Result of session token validation against the backend.
    /// </summary>
    struct ValidateSessionResult {
        bool valid{ false };
        std::vector<std::string> entitlements{};
        std::string expires_at{};
        std::string reason{};
    };

    /// <summary>
    /// Serializable session state for in-memory caching or offline resumption.
    /// </summary>
    struct SessionState {
        std::string access_token{};
        std::string refresh_token{};
        std::string access_expires_at{};
        std::string refresh_expires_at{};
        std::vector<std::string> entitlements{};
    };

} // namespace nineauth

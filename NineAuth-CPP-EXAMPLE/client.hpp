#pragma once

#include <memory>
#include <string>
#include <vector>
#include "options.hpp"
#include "models.hpp"
#include "result.hpp"

namespace nineauth {

    /// <summary>
    /// Official C++17 client for NineAuth Identity, Access and Licensing Infrastructure.
    /// Designed specifically for game loaders, desktop tools, and game engines (Unreal, custom engines).
    /// Operates synchronously with zero exception overhead and static linking support.
    /// </summary>
    class NineAuthClient {
    public:
        explicit NineAuthClient(const Options& options);
        ~NineAuthClient();

        NineAuthClient(const NineAuthClient&) = delete;
        NineAuthClient& operator=(const NineAuthClient&) = delete;
        NineAuthClient(NineAuthClient&&) noexcept;
        NineAuthClient& operator=(NineAuthClient&&) noexcept;

        /// <summary>
        /// Verifies application credentials against the NineAuth API and loads metadata.
        /// </summary>
        Result<void> Initialize();

        /// <summary>
        /// Registers a new end-user account for this application.
        /// Returns the created User ID.
        /// </summary>
        Result<std::string> Register(const std::string& email, const std::string& password);

        /// <summary>
        /// Authenticates an end-user with credentials and hardware fingerprint.
        /// Automatically generates ISO 8601 UTC timestamp and cryptographic nonce for anti-replay protection.
        /// </summary>
        Result<void> Login(const std::string& email, const std::string& password,
            const std::string& device_fingerprint = "");

        /// <summary>
        /// Activates a license key and binds it to a device hardware fingerprint.
        /// Automatically applies cryptographic anti-replay guarantees.
        /// </summary>
        Result<ActivateLicenseResult> ActivateLicense(const std::string& license_key,
            const std::string& device_fingerprint);

        /// <summary>
        /// Validates the current session token with the backend and synchronizes granted entitlements.
        /// </summary>
        Result<ValidateSessionResult> ValidateSession();

        /// <summary>
        /// Local in-memory check for a granted entitlement (zero network latency, 0ms).
        /// </summary>
        bool HasEntitlement(const std::string& key) const;

        /// <summary>
        /// Returns all currently held entitlements from the in-memory session.
        /// </summary>
        std::vector<std::string> GetEntitlements() const;

        /// <summary>
        /// Queries the backend in real-time to check if an entitlement is currently valid and active.
        /// </summary>
        Result<bool> CheckEntitlement(const std::string& key);

        /// <summary>
        /// Refreshes the session using the current refresh token.
        /// </summary>
        Result<void> RefreshSession();

        /// <summary>
        /// Resets hardware association for a license key to allow binding to a new device.
        /// </summary>
        Result<bool> ResetDevice(const std::string& license_key, const std::string& device_fingerprint);

        /// <summary>
        /// Checks whether the client currently holds an unexpired access token in memory.
        /// Note: Does not perform a network call; checks purely in-memory token expiration.
        /// </summary>
        bool IsAuthenticated() const;

        /// <summary>
        /// Exports the current session tokens and entitlements for secure local storage.
        /// </summary>
        SessionState GetSessionState() const;

        /// <summary>
        /// Restores a previously saved session state into memory.
        /// </summary>
        void RestoreSession(const SessionState& state);

        /// <summary>
        /// Revokes the session on the backend and clears all tokens and entitlements from memory.
        /// </summary>
        Result<void> Logout();

        /// <summary>
        /// Returns the configuration options configured for this client.
        /// </summary>
        const Options& GetOptions() const noexcept;

        /// <summary>
        /// Returns the verified application info if initialized.
        /// </summary>
        const ApplicationInfo& GetApplicationInfo() const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace nineauth

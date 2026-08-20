#pragma once

#include <string>

namespace nineauth {

    /// <summary>
    /// Configuration options for initializing the NineAuthClient.
    /// </summary>
    struct Options {
        std::string application_id{};
        std::string api_url{ "https://api.nineauth.xyz" };
        std::string environment{ "production" };
        int timeout_seconds{ 15 };
    };

} // namespace nineauth

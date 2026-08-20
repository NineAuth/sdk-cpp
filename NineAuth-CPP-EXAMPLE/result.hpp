#pragma once

#include <string>
#include <utility>

namespace nineauth {

    /// <summary>
    /// Result type representing either a successful value or a structured error.
    /// Eliminates C++ exception overhead for game engines and high-performance loaders (-fno-exceptions compatible).
    /// </summary>
    template <typename T>
    struct Result {
        bool success{ false };
        T value{};
        std::string error_code{};
        std::string error_message{};

        static Result<T> Ok(T val) {
            Result<T> res;
            res.success = true;
            res.value = std::move(val);
            return res;
        }

        static Result<T> Err(std::string code, std::string message) {
            Result<T> res;
            res.success = false;
            res.error_code = std::move(code);
            res.error_message = std::move(message);
            return res;
        }

        explicit operator bool() const noexcept {
            return success;
        }
    };

    /// <summary>
    /// Result specialization for operations returning void.
    /// </summary>
    template <>
    struct Result<void> {
        bool success{ false };
        std::string error_code{};
        std::string error_message{};

        static Result<void> Ok() {
            Result<void> res;
            res.success = true;
            return res;
        }

        static Result<void> Err(std::string code, std::string message) {
            Result<void> res;
            res.success = false;
            res.error_code = std::move(code);
            res.error_message = std::move(message);
            return res;
        }

        explicit operator bool() const noexcept {
            return success;
        }
    };

} // namespace nineauth

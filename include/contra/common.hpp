#pragma once

// Shared Windows/STL plumbing for the dumper. Kept deliberately small: the
// interesting parts of the tool live in pe.hpp, metadata.hpp and loader.hpp.

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace contra {

class AppError : public std::runtime_error {
public:
    explicit AppError(const std::string& message, int exitCode = 1)
        : std::runtime_error(message), exitCode_(exitCode) {}

    int exitCode() const noexcept { return exitCode_; }

private:
    int exitCode_;
};

enum class LogLevel { Verbose, Info, Warn, Error };

class Logger {
public:
    static Logger& instance();

    void setVerbose(bool value) { verbose_ = value; }
    bool verbose() const { return verbose_; }

    void write(LogLevel level, std::string_view message);

private:
    bool verbose_ = false;
    std::mutex mutex_;
};

inline void logInfo(std::string_view message) { Logger::instance().write(LogLevel::Info, message); }
inline void logWarn(std::string_view message) { Logger::instance().write(LogLevel::Warn, message); }
inline void logError(std::string_view message) { Logger::instance().write(LogLevel::Error, message); }
inline void logVerbose(std::string_view message) { Logger::instance().write(LogLevel::Verbose, message); }

std::string narrow(const std::wstring& value);
std::wstring widen(const std::string& value);

std::string wideToUtf8(const std::wstring& value);
std::wstring utf8ToWide(const std::string& value);

// Metadata strings are normally UTF-8, but obfuscators occasionally emit
// invalid byte sequences. Keep the output valid JSON/C++ by replacing bad
// sequences with U+FFFD instead of failing the whole dump.
std::string sanitizeUtf8(std::string_view value);

std::string toHex(std::uint64_t value, int width = 0);
std::string formatInt(std::int64_t value);

std::string trim(std::string_view value);
std::string lowerAscii(std::string_view value);
bool iequals(std::string_view a, std::string_view b);
bool startsWith(std::string_view value, std::string_view prefix);
bool endsWith(std::string_view value, std::string_view suffix);

std::string currentTimestampUtc();

template <typename T>
constexpr T alignUp(T value, T alignment) {
    return alignment <= 1 ? value : (value + alignment - 1) & ~(alignment - 1);
}

class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) : handle_(handle) {}
    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    HANDLE get() const noexcept { return handle_; }
    explicit operator bool() const noexcept { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

    HANDLE release() noexcept {
        HANDLE value = handle_;
        handle_ = nullptr;
        return value;
    }

    void reset(HANDLE handle = nullptr) noexcept {
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

private:
    HANDLE handle_ = nullptr;
};

std::string win32Error(DWORD code = GetLastError());

}  // namespace contra

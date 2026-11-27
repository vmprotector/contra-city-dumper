#include "contra/common.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace contra {

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

void Logger::write(LogLevel level, std::string_view message) {
    if (level == LogLevel::Verbose && !verbose_) {
        return;
    }

    const char* prefix = "[*]";
    switch (level) {
        case LogLevel::Verbose: prefix = "[.]"; break;
        case LogLevel::Info: prefix = "[+]"; break;
        case LogLevel::Warn: prefix = "[!]"; break;
        case LogLevel::Error: prefix = "[-]"; break;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << prefix << ' ' << message << '\n';
    std::cout.flush();
}

std::string narrow(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring widen(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                         nullptr, 0);
    if (size <= 0) {
        return {};
    }
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                        result.data(), size);
    return result;
}

std::string wideToUtf8(const std::wstring& value) { return narrow(value); }
std::wstring utf8ToWide(const std::string& value) { return widen(value); }

std::string sanitizeUtf8(std::string_view value) {
    std::string out;
    out.reserve(value.size());

    std::size_t i = 0;
    while (i < value.size()) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
            ++i;
            continue;
        }

        std::size_t need = 0;
        std::uint32_t cp = 0;
        if ((c & 0xE0) == 0xC0) {
            need = 1;
            cp = c & 0x1F;
        } else if ((c & 0xF0) == 0xE0) {
            need = 2;
            cp = c & 0x0F;
        } else if ((c & 0xF8) == 0xF0) {
            need = 3;
            cp = c & 0x07;
        } else {
            out += "\xEF\xBF\xBD";
            ++i;
            continue;
        }

        if (i + need >= value.size()) {
            out += "\xEF\xBF\xBD";
            ++i;
            continue;
        }

        bool valid = true;
        for (std::size_t n = 1; n <= need; ++n) {
            const auto cc = static_cast<unsigned char>(value[i + n]);
            if ((cc & 0xC0) != 0x80) {
                valid = false;
                break;
            }
            cp = (cp << 6) | (cc & 0x3F);
        }

        const bool overlong = (need == 1 && cp < 0x80) ||
                              (need == 2 && cp < 0x800) ||
                              (need == 3 && cp < 0x10000);
        const bool surrogate = cp >= 0xD800 && cp <= 0xDFFF;
        const bool tooLarge = cp > 0x10FFFF;

        if (!valid || overlong || surrogate || tooLarge) {
            out += "\xEF\xBF\xBD";
            ++i;
            continue;
        }

        out.append(value.substr(i, need + 1));
        i += need + 1;
    }

    return out;
}

std::string toHex(std::uint64_t value, int width) {
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << std::setfill('0');
    if (width > 0) {
        stream << std::setw(width);
    }
    stream << value;
    return stream.str();
}

std::string formatInt(std::int64_t value) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
}

std::string trim(std::string_view value) {
    std::size_t begin = 0;
    while (begin < value.size() && (value[begin] == ' ' || value[begin] == '\t' ||
                                    value[begin] == '\r' || value[begin] == '\n')) {
        ++begin;
    }
    std::size_t end = value.size();
    while (end > begin && (value[end - 1] == ' ' || value[end - 1] == '\t' ||
                           value[end - 1] == '\r' || value[end - 1] == '\n')) {
        --end;
    }
    return std::string(value.substr(begin, end - begin));
}

std::string lowerAscii(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return result;
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool startsWith(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

bool endsWith(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() &&
           value.substr(value.size() - suffix.size()) == suffix;
}

std::string currentTimestampUtc() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_s(&tm, &time);
    char buffer[32]{};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buffer;
}

std::string win32Error(DWORD code) {
    if (code == ERROR_SUCCESS) {
        return "no error";
    }

    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageW(flags, nullptr, code, 0,
                                        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::string result;
    if (length && buffer) {
        std::wstring text(buffer, length);
        while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) {
            text.pop_back();
        }
        result = wideToUtf8(text);
    } else {
        result = "Win32 error " + std::to_string(code);
    }
    if (buffer) {
        LocalFree(buffer);
    }
    return result;
}

}  // namespace contra

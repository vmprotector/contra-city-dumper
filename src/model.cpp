#include "contra/model.hpp"

#include <algorithm>
#include <array>
#include <cctype>

namespace contra::model {

namespace {

const std::array<const char*, 92> kCppKeywords = {
    "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor",
    "bool", "break", "case", "catch", "char", "char8_t", "char16_t", "char32_t",
    "class", "compl", "concept", "const", "consteval", "constexpr", "constinit",
    "const_cast", "continue", "co_await", "co_return", "co_yield", "decltype",
    "default", "delete", "do", "double", "dynamic_cast", "else", "enum",
    "explicit", "export", "extern", "false", "float", "for", "friend", "goto",
    "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept",
    "not", "not_eq", "nullptr", "operator", "or", "or_eq", "private",
    "protected", "public", "register", "reinterpret_cast", "requires", "return",
    "short", "signed", "sizeof", "static", "static_assert", "static_cast",
    "struct", "switch", "template", "this", "thread_local", "throw", "true",
    "try", "typedef", "typeid", "typename", "union", "unsigned", "using",
    "virtual", "void", "volatile", "wchar_t", "while", "xor", "xor_eq",
};

}  // namespace

ClassInfo* SdkModel::findClass(const std::string& assembly,
                               const std::string& fullName) const {
    const auto exact = classByAssemblyAndName.find(assembly + "\x1f" + fullName);
    if (exact != classByAssemblyAndName.end()) {
        return exact->second;
    }
    const auto global = classByFullName.find(fullName);
    return global == classByFullName.end() ? nullptr : global->second;
}

bool isCppKeyword(std::string_view value) {
    for (const char* keyword : kCppKeywords) {
        if (value == keyword) {
            return true;
        }
    }
    return false;
}

std::string sanitizeIdentifier(std::string_view value, const std::string& fallback) {
    std::string result;
    result.reserve(value.size() + 8);

    bool lastUnderscore = false;
    for (unsigned char c : value) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '_') {
            result.push_back(static_cast<char>(c));
            lastUnderscore = c == '_';
        } else {
            if (!lastUnderscore) {
                result.push_back('_');
                lastUnderscore = true;
            }
        }
    }

    while (!result.empty() && result.back() == '_') {
        result.pop_back();
    }
    while (!result.empty() && result.front() == '_' && result.size() > 1 &&
           !std::isalpha(static_cast<unsigned char>(result[1]))) {
        result.erase(result.begin());
    }

    if (result.empty()) {
        result = fallback;
    }
    if (std::isdigit(static_cast<unsigned char>(result.front()))) {
        result.insert(result.begin(), '_');
    }
    if (isCppKeyword(result)) {
        result.push_back('_');
    }
    return result;
}

}  // namespace contra::model

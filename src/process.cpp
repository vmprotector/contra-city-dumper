#include "contra/process.hpp"

#include <tlhelp32.h>

#include <algorithm>
#include <cctype>
#include <cwctype>

namespace contra {

namespace {

bool equalNoCase(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(a[i]) != std::towlower(b[i])) {
            return false;
        }
    }
    return true;
}

std::wstring baseName(const std::wstring& path) {
    const auto slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

}  // namespace

std::optional<ProcessInfo> Process::findProcess(const std::wstring& imageName) {
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        return std::nullopt;
    }

    const std::wstring withExe =
        imageName.find(L'.') == std::wstring::npos ? imageName + L".exe" : imageName;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry)) {
        return std::nullopt;
    }

    do {
        if (equalNoCase(entry.szExeFile, imageName) ||
            equalNoCase(entry.szExeFile, withExe) ||
            equalNoCase(baseName(entry.szExeFile), imageName) ||
            equalNoCase(baseName(entry.szExeFile), withExe)) {
            ProcessInfo info;
            info.pid = entry.th32ProcessID;
            info.name = entry.szExeFile;
            return info;
        }
    } while (Process32NextW(snapshot.get(), &entry));

    return std::nullopt;
}

std::optional<ProcessInfo> Process::processById(DWORD pid) {
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        return std::nullopt;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry)) {
        return std::nullopt;
    }

    do {
        if (entry.th32ProcessID == pid) {
            ProcessInfo info;
            info.pid = entry.th32ProcessID;
            info.name = entry.szExeFile;
            return info;
        }
    } while (Process32NextW(snapshot.get(), &entry));

    return std::nullopt;
}

bool Process::open(DWORD pid) {
    if (pid == 0) {
        return false;
    }

    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!handle) {
        // PROCESS_QUERY_LIMITED_INFORMATION is enough for VirtualQueryEx and is
        // accepted in a few protected-process cases where QUERY_INFORMATION is not.
        handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    }
    if (!handle) {
        return false;
    }

    handle_.reset(handle);
    pid_ = pid;
    return true;
}

bool Process::read(std::uintptr_t address, void* destination, std::size_t size,
                   std::size_t* bytesRead) const {
    if (!isOpen() || size == 0) {
        if (bytesRead) {
            *bytesRead = 0;
        }
        return size == 0;
    }

    SIZE_T done = 0;
    const BOOL ok = ReadProcessMemory(handle_.get(),
                                      reinterpret_cast<LPCVOID>(address),
                                      destination, size, &done);
    if (bytesRead) {
        *bytesRead = static_cast<std::size_t>(done);
    }
    return ok != FALSE && done == size;
}

std::optional<std::vector<std::uint8_t>> Process::readBytes(std::uintptr_t address,
                                                            std::size_t size) const {
    if (!isOpen() || size == 0) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> result(size);
    std::size_t offset = 0;
    while (offset < size) {
        SIZE_T chunk = 0;
        const std::size_t remaining = size - offset;
        const BOOL ok = ReadProcessMemory(handle_.get(),
                                          reinterpret_cast<LPCVOID>(address + offset),
                                          result.data() + offset, remaining, &chunk);
        if (chunk == 0) {
            // A page inside the requested range is gone. Treat the whole read
            // as failed; callers that need tolerant reads work page by page.
            return std::nullopt;
        }
        offset += static_cast<std::size_t>(chunk);
        if (!ok && offset < size) {
            return std::nullopt;
        }
    }
    return result;
}

std::optional<std::string> Process::readCString(std::uintptr_t address,
                                                std::size_t maxLength) const {
    std::string result;
    result.reserve(std::min<std::size_t>(maxLength, 64));
    for (std::size_t i = 0; i < maxLength; ++i) {
        char value = 0;
        if (!read(address + i, &value, 1)) {
            return std::nullopt;
        }
        if (value == '\0') {
            return result;
        }
        result.push_back(value);
    }
    return result;
}

std::vector<NativeModule> Process::modules() const {
    std::vector<NativeModule> result;
    if (!isOpen()) {
        return result;
    }

    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_));
    if (!snapshot) {
        return result;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot.get(), &entry)) {
        return result;
    }

    do {
        NativeModule module;
        module.name = entry.szModule;
        module.path = entry.szExePath;
        module.base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
        module.size = entry.modBaseSize;

        // Machine type is read from the PE header later; keep the module list
        // cheap and independent of a valid image.
        result.push_back(std::move(module));
    } while (Module32NextW(snapshot.get(), &entry));

    std::sort(result.begin(), result.end(), [](const NativeModule& a, const NativeModule& b) {
        if (a.base != b.base) {
            return a.base < b.base;
        }
        return a.name < b.name;
    });
    result.erase(std::unique(result.begin(), result.end(),
                             [](const NativeModule& a, const NativeModule& b) {
                                 return a.base == b.base && a.name == b.name;
                             }),
                 result.end());
    return result;
}

std::optional<NativeModule> Process::moduleByName(const std::wstring& name) const {
    for (const auto& module : modules()) {
        if (equalNoCase(module.name, name)) {
            return module;
        }
    }
    return std::nullopt;
}

std::vector<MemoryRegion> Process::regions() const {
    std::vector<MemoryRegion> result;
    if (!isOpen()) {
        return result;
    }

    std::uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION info{};
    while (VirtualQueryEx(handle_.get(), reinterpret_cast<LPCVOID>(address),
                          &info, sizeof(info)) == sizeof(info)) {
        MemoryRegion region;
        region.base = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
        region.size = info.RegionSize;
        region.state = info.State;
        region.protect = info.Protect;
        region.type = info.Type;
        result.push_back(region);

        const std::uintptr_t next = region.base + region.size;
        if (next <= address) {
            break;
        }
        address = next;
    }
    return result;
}

bool Process::isReadable(std::uintptr_t address, std::size_t size) const {
    if (!isOpen() || size == 0) {
        return size == 0;
    }

    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQueryEx(handle_.get(), reinterpret_cast<LPCVOID>(address),
                       &info, sizeof(info)) != sizeof(info)) {
        return false;
    }
    if (info.State != MEM_COMMIT || !isReadableProtection(info.Protect)) {
        return false;
    }
    const auto end = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
    return address + size <= end;
}

bool Process::isWow64() const {
    if (!isOpen()) {
        return false;
    }
    BOOL wow64 = FALSE;
    if (!IsWow64Process(handle_.get(), &wow64)) {
        return false;
    }
    return wow64 != FALSE;
}

std::wstring Process::exePath() const {
    if (!isOpen()) {
        return {};
    }
    std::wstring path(32768, L'\0');
    DWORD size = static_cast<DWORD>(path.size());
    if (!QueryFullProcessImageNameW(handle_.get(), 0, path.data(), &size)) {
        return {};
    }
    path.resize(size);
    return path;
}

bool isReadableProtection(DWORD protect) {
    if (protect & PAGE_GUARD) {
        return false;
    }
    protect &= 0xFF;
    switch (protect) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

std::string protectionName(DWORD protect) {
    const DWORD base = protect & 0xFF;
    std::string name;
    switch (base) {
        case PAGE_NOACCESS: name = "NOACCESS"; break;
        case PAGE_READONLY: name = "R"; break;
        case PAGE_READWRITE: name = "RW"; break;
        case PAGE_WRITECOPY: name = "WC"; break;
        case PAGE_EXECUTE: name = "X"; break;
        case PAGE_EXECUTE_READ: name = "XR"; break;
        case PAGE_EXECUTE_READWRITE: name = "XRW"; break;
        case PAGE_EXECUTE_WRITECOPY: name = "XWC"; break;
        default: name = "?"; break;
    }
    if (protect & PAGE_GUARD) name += "|GUARD";
    if (protect & PAGE_NOCACHE) name += "|NOCACHE";
    if (protect & PAGE_WRITECOMBINE) name += "|WC";
    return name;
}

std::string regionTypeName(DWORD type) {
    switch (type) {
        case MEM_IMAGE: return "IMAGE";
        case MEM_MAPPED: return "MAPPED";
        case MEM_PRIVATE: return "PRIVATE";
        default: return "FREE";
    }
}

}  // namespace contra

#pragma once

#include "contra/common.hpp"

#include <optional>
#include <string>
#include <vector>

namespace contra {

struct ProcessInfo {
    DWORD pid = 0;
    std::wstring name;
    std::wstring exePath;
};

struct NativeModule {
    std::wstring name;
    std::wstring path;
    std::uintptr_t base = 0;
    std::uint32_t size = 0;
    std::uint16_t machine = 0;
    bool is64 = false;
};

struct MemoryRegion {
    std::uintptr_t base = 0;
    std::size_t size = 0;
    DWORD state = 0;
    DWORD protect = 0;
    DWORD type = 0;
};

class Process {
public:
    Process() = default;

    static std::optional<ProcessInfo> findProcess(const std::wstring& imageName);
    static std::optional<ProcessInfo> processById(DWORD pid);

    bool open(DWORD pid);
    bool isOpen() const { return handle_.get() != nullptr; }
    DWORD pid() const { return pid_; }
    HANDLE handle() const { return handle_.get(); }

    bool read(std::uintptr_t address, void* destination, std::size_t size,
              std::size_t* bytesRead = nullptr) const;
    std::optional<std::vector<std::uint8_t>> readBytes(std::uintptr_t address,
                                                       std::size_t size) const;

    // Reads until a NUL terminator or maxLength bytes. Returns an empty string
    // when the address is unreadable.
    std::optional<std::string> readCString(std::uintptr_t address,
                                           std::size_t maxLength = 512) const;

    std::vector<NativeModule> modules() const;
    std::optional<NativeModule> moduleByName(const std::wstring& name) const;

    std::vector<MemoryRegion> regions() const;
    bool isReadable(std::uintptr_t address, std::size_t size) const;

    bool isWow64() const;
    std::wstring exePath() const;

private:
    UniqueHandle handle_;
    DWORD pid_ = 0;
};

bool isReadableProtection(DWORD protect);
std::string protectionName(DWORD protect);
std::string regionTypeName(DWORD type);

}  // namespace contra

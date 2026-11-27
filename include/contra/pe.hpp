#pragma once

#include "contra/common.hpp"
#include "contra/process.hpp"

#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace contra::pe {

struct Section {
    std::string name;
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;
    std::uint32_t rawOffset = 0;
    std::uint32_t rawSize = 0;
    std::uint32_t characteristics = 0;
};

struct ExportInfo {
    std::string name;
    std::uint32_t rva = 0;
};

// A PE image in either file form (RVA -> file offset through sections) or
// mapped form (RVA == buffer offset). Metadata parsing only needs RVA reads,
// so both forms share the same interface.
class ImageBuffer {
public:
    static std::optional<ImageBuffer> fromFile(const std::filesystem::path& path,
                                               std::string& error);
    static std::optional<ImageBuffer> fromProcess(const Process& process,
                                                  std::uintptr_t base,
                                                  std::string& error,
                                                  bool requireCli = true);

    const std::uint8_t* at(std::uint32_t rva, std::size_t size = 1) const;
    std::span<const std::uint8_t> span(std::uint32_t rva, std::size_t size) const;
    std::vector<std::uint8_t> copy(std::uint32_t rva, std::size_t size) const;
    std::optional<std::uint32_t> fileOffsetOfRva(std::uint32_t rva) const;
    std::uintptr_t addressOfRva(std::uint32_t rva) const;

    std::uintptr_t base() const { return base_; }
    std::uint32_t size() const { return imageSize_; }
    std::uint32_t preferredBase() const { return preferredBase_; }
    std::uint16_t machine() const { return machine_; }
    bool is64() const { return is64_; }
    bool mapped() const { return mapped_; }
    const std::string& source() const { return source_; }
    const std::vector<Section>& sections() const { return sections_; }
    std::uint32_t cliRva() const { return cliRva_; }
    std::uint32_t cliSize() const { return cliSize_; }
    std::uint32_t metadataRva() const { return metadataRva_; }
    std::uint32_t metadataSize() const { return metadataSize_; }
    std::uint32_t timestamp() const { return timestamp_; }

    std::vector<ExportInfo> exports() const;

private:
    bool parseHeaders(std::string& error);

    std::vector<std::uint8_t> bytes_;
    std::vector<Section> sections_;
    std::uintptr_t base_ = 0;
    std::uint32_t imageSize_ = 0;
    std::uint32_t preferredBase_ = 0;
    std::uint32_t sizeOfHeaders_ = 0;
    std::uint16_t machine_ = 0;
    bool is64_ = false;
    bool mapped_ = false;
    std::uint32_t cliRva_ = 0;
    std::uint32_t cliSize_ = 0;
    std::uint32_t metadataRva_ = 0;
    std::uint32_t metadataSize_ = 0;
    std::uint32_t timestamp_ = 0;
    std::uint32_t exportRva_ = 0;
    std::uint32_t exportSize_ = 0;
    std::string source_;
};

}  // namespace contra::pe

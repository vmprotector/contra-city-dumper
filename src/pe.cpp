#include "contra/pe.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>

namespace contra::pe {

namespace {

constexpr std::uint16_t kMachineI386 = 0x014C;
constexpr std::uint16_t kMachineAmd64 = 0x8664;

std::uint16_t read16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}

std::uint32_t read32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::string sectionName(const std::uint8_t* raw) {
    char name[9]{};
    std::memcpy(name, raw, 8);
    return name;
}

bool isMetadataSignature(const std::uint8_t* p) {
    return p[0] == 'B' && p[1] == 'S' && p[2] == 'J' && p[3] == 'B';
}

}  // namespace

std::optional<ImageBuffer> ImageBuffer::fromFile(const std::filesystem::path& path,
                                                 std::string& error) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        error = "cannot open " + path.string();
        return std::nullopt;
    }

    const auto end = file.tellg();
    if (end <= 0 || static_cast<std::uint64_t>(end) > 512ull * 1024ull * 1024ull) {
        error = "unreasonable file size: " + path.string();
        return std::nullopt;
    }

    ImageBuffer image;
    image.bytes_.resize(static_cast<std::size_t>(end));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(image.bytes_.data()),
                   static_cast<std::streamsize>(image.bytes_.size()))) {
        error = "short read: " + path.string();
        return std::nullopt;
    }

    image.mapped_ = false;
    image.source_ = path.string();
    if (!image.parseHeaders(error)) {
        return std::nullopt;
    }
    image.base_ = image.preferredBase_;
    return image;
}

std::optional<ImageBuffer> ImageBuffer::fromProcess(const Process& process,
                                                    std::uintptr_t base,
                                                    std::string& error,
                                                    bool requireCli) {
    std::vector<std::uint8_t> headers(0x1000);
    if (!process.read(base, headers.data(), headers.size())) {
        error = "unreadable PE headers at " + toHex(base);
        return std::nullopt;
    }

    ImageBuffer scratch;
    scratch.bytes_ = std::move(headers);
    scratch.mapped_ = false;
    scratch.source_ = "process:" + toHex(base);
    if (!scratch.parseHeaders(error)) {
        return std::nullopt;
    }
    const bool hasCli = scratch.cliRva_ != 0;
    if (!hasCli && requireCli) {
        error = "not a CLI image";
        return std::nullopt;
    }

    const auto rvaToFile = [&](std::uint32_t rva) -> std::optional<std::uint32_t> {
        for (const auto& section : scratch.sections_) {
            const std::uint32_t span = std::max(section.virtualSize, section.rawSize);
            if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
                const std::uint32_t delta = rva - section.virtualAddress;
                if (delta >= section.rawSize) {
                    return std::nullopt;
                }
                return section.rawOffset + delta;
            }
        }
        if (rva < scratch.sizeOfHeaders_) {
            return rva;
        }
        return std::nullopt;
    };

    const auto readAt = [&](std::uint32_t offset, void* destination, std::size_t size) {
        return process.read(base + offset, destination, size);
    };

    std::uint32_t metadataRva = 0;
    std::uint32_t metadataSize = 0;
    const auto validateCli = [&](std::uint32_t cliOffset, bool fileLayout) -> bool {
        std::array<std::uint8_t, 16> cli{};
        if (!readAt(cliOffset, cli.data(), cli.size())) {
            return false;
        }
        const std::uint32_t cb = read32(cli.data());
        metadataRva = read32(cli.data() + 8);
        metadataSize = read32(cli.data() + 12);
        if (cb < 16 || cb > 0x1000 || metadataRva == 0 || metadataSize < 16) {
            return false;
        }
        std::uint32_t metadataOffset = metadataRva;
        if (fileLayout) {
            const auto mapped = rvaToFile(metadataRva);
            if (!mapped) {
                return false;
            }
            metadataOffset = *mapped;
        }
        std::array<std::uint8_t, 4> signature{};
        if (!readAt(metadataOffset, signature.data(), signature.size())) {
            return false;
        }
        return signature[0] == 'B' && signature[1] == 'S' && signature[2] == 'J' &&
               signature[3] == 'B';
    };

    // Mono maps assembly files as raw file views rather than as relocated PE
    // images. Try the normal image layout first, then the file layout through
    // the section table.
    bool imageLayout = hasCli ? validateCli(scratch.cliRva_, false) : true;
    bool fileLayout = false;
    if (hasCli && !imageLayout) {
        const auto cliFileOffset = rvaToFile(scratch.cliRva_);
        if (!cliFileOffset) {
            error = "cannot map CLI header";
            return std::nullopt;
        }
        fileLayout = validateCli(*cliFileOffset, true);
    }

    if (hasCli && !imageLayout && !fileLayout) {
        error = "no CLI metadata";
        return std::nullopt;
    }

    ImageBuffer image;
    image.base_ = base;
    image.preferredBase_ = scratch.preferredBase_;
    image.sizeOfHeaders_ = scratch.sizeOfHeaders_;
    image.machine_ = scratch.machine_;
    image.is64_ = scratch.is64_;
    image.cliRva_ = scratch.cliRva_;
    image.cliSize_ = scratch.cliSize_;
    image.metadataRva_ = metadataRva;
    image.metadataSize_ = metadataSize;
    image.timestamp_ = scratch.timestamp_;
    image.exportRva_ = scratch.exportRva_;
    image.exportSize_ = scratch.exportSize_;
    image.source_ = "process:" + toHex(base);

    if (imageLayout) {
        image.sections_ = scratch.sections_;
        image.imageSize_ = scratch.imageSize_;
        if (image.imageSize_ == 0 || image.imageSize_ > 512u * 1024u * 1024u) {
            error = "invalid SizeOfImage at " + toHex(base);
            return std::nullopt;
        }
        image.mapped_ = true;

        // Keep the mapped layout, not the file layout. Metadata and IL RVAs
        // can then be indexed directly. Unreadable pages stay zero-filled.
        image.bytes_.assign(image.imageSize_, 0);
        const std::size_t headerCopy =
            std::min<std::size_t>(image.sizeOfHeaders_, image.bytes_.size());
        if (headerCopy && process.read(base, image.bytes_.data(), headerCopy)) {
            // copied
        } else {
            std::memcpy(image.bytes_.data(), scratch.bytes_.data(),
                        std::min(headerCopy, scratch.bytes_.size()));
        }

        for (const auto& section : image.sections_) {
            if (section.virtualAddress >= image.bytes_.size()) {
                continue;
            }
            const std::size_t writable = std::min<std::size_t>(
                section.virtualSize, image.bytes_.size() - section.virtualAddress);
            if (writable == 0) {
                continue;
            }

            std::uint8_t* destination = image.bytes_.data() + section.virtualAddress;
            std::size_t done = 0;
            while (done < writable) {
                SIZE_T chunk = 0;
                const std::size_t remaining = writable - done;
                ReadProcessMemory(process.handle(),
                                  reinterpret_cast<LPCVOID>(base + section.virtualAddress + done),
                                  destination + done, remaining, &chunk);
                if (chunk == 0) {
                    break;
                }
                done += static_cast<std::size_t>(chunk);
            }
        }
        return image;
    }

    // Raw file view: copy the file bytes and let at() resolve RVAs through the
    // section table. The view may include trailing zero padding.
    image.sections_ = scratch.sections_;
    image.imageSize_ = scratch.imageSize_;
    image.mapped_ = false;

    std::uint64_t fileSize = scratch.sizeOfHeaders_;
    for (const auto& section : scratch.sections_) {
        fileSize = std::max<std::uint64_t>(
            fileSize, static_cast<std::uint64_t>(section.rawOffset) + section.rawSize);
    }
    if (fileSize == 0 || fileSize > 512ull * 1024ull * 1024ull) {
        error = "invalid mapped file size at " + toHex(base);
        return std::nullopt;
    }

    image.bytes_.assign(static_cast<std::size_t>(fileSize), 0);
    std::size_t done = 0;
    while (done < image.bytes_.size()) {
        SIZE_T chunk = 0;
        const std::size_t remaining = image.bytes_.size() - done;
        ReadProcessMemory(process.handle(),
                          reinterpret_cast<LPCVOID>(base + done),
                          image.bytes_.data() + done, remaining, &chunk);
        if (chunk == 0) {
            break;
        }
        done += static_cast<std::size_t>(chunk);
    }
    if (done == 0) {
        error = "cannot read mapped file at " + toHex(base);
        return std::nullopt;
    }

    // Recompute CLI/metadata via the file layout; the first pass only had the
    // first 4 KiB of the view.
    std::string secondError;
    if (!image.parseHeaders(secondError)) {
        error = secondError;
        return std::nullopt;
    }
    if (image.metadataRva_ == 0) {
        error = "file CLI header did not resolve";
        return std::nullopt;
    }
    return image;
}

bool ImageBuffer::parseHeaders(std::string& error) {
    if (bytes_.size() < 0x40) {
        error = "file too small for a DOS header";
        return false;
    }
    if (bytes_[0] != 'M' || bytes_[1] != 'Z') {
        error = "missing MZ signature";
        return false;
    }

    const std::uint32_t peOffset = read32(bytes_.data() + 0x3C);
    if (peOffset > bytes_.size() || bytes_.size() - peOffset < 24) {
        error = "invalid e_lfanew";
        return false;
    }
    const std::uint8_t* nt = bytes_.data() + peOffset;
    if (std::memcmp(nt, "PE\0\0", 4) != 0) {
        error = "missing PE signature";
        return false;
    }

    machine_ = read16(nt + 4);
    const std::uint16_t sectionCount = read16(nt + 6);
    timestamp_ = read32(nt + 8);
    const std::uint16_t optionalSize = read16(nt + 20);
    const std::uint8_t* optional = nt + 24;
    if (optional + optionalSize > bytes_.data() + bytes_.size() || optionalSize < 64) {
        error = "truncated optional header";
        return false;
    }

    const std::uint16_t magic = read16(optional);
    if (magic == 0x20B) {
        is64_ = true;
    } else if (magic == 0x10B) {
        is64_ = false;
    } else {
        error = "unknown optional header magic";
        return false;
    }

    if (machine_ != kMachineI386 && machine_ != kMachineAmd64) {
        error = "unsupported machine type " + toHex(machine_, 4);
        return false;
    }

    imageSize_ = read32(optional + 56);
    sizeOfHeaders_ = read32(optional + 60);
    preferredBase_ = is64_ ? static_cast<std::uint32_t>(read32(optional + 24)) : read32(optional + 28);

    const std::uint32_t directoryCount = read32(optional + (is64_ ? 108 : 92));
    const std::uint8_t* directories = optional + (is64_ ? 112 : 96);
    const std::size_t availableDirs =
        (static_cast<std::size_t>(optional + optionalSize - directories)) / 8;
    const std::uint32_t safeDirs = std::min<std::uint32_t>(
        directoryCount, static_cast<std::uint32_t>(availableDirs));

    if (safeDirs > 0) {
        exportRva_ = read32(directories + 0);
        exportSize_ = read32(directories + 4);
    }
    if (safeDirs > 14) {
        cliRva_ = read32(directories + 14 * 8);
        cliSize_ = read32(directories + 14 * 8 + 4);
    }

    const std::uint8_t* sectionTable = optional + optionalSize;
    if (sectionTable + static_cast<std::size_t>(sectionCount) * 40 > bytes_.data() + bytes_.size()) {
        error = "truncated section table";
        return false;
    }

    sections_.clear();
    sections_.reserve(sectionCount);
    for (std::uint16_t i = 0; i < sectionCount; ++i) {
        const std::uint8_t* raw = sectionTable + static_cast<std::size_t>(i) * 40;
        Section section;
        section.name = sectionName(raw);
        section.virtualSize = read32(raw + 8);
        section.virtualAddress = read32(raw + 12);
        section.rawSize = read32(raw + 16);
        section.rawOffset = read32(raw + 20);
        section.characteristics = read32(raw + 36);
        sections_.push_back(std::move(section));
    }

    if (cliRva_ && cliSize_ >= 16) {
        // IMAGE_COR20_HEADER: cb (4), runtime version (4), metadata directory (8).
        // at() maps the RVA through the section table for file-backed images.
        if (const auto* cli = at(cliRva_, 16)) {
            metadataRva_ = read32(cli + 8);
            metadataSize_ = read32(cli + 12);
        }
    }

    return true;
}

const std::uint8_t* ImageBuffer::at(std::uint32_t rva, std::size_t size) const {
    if (size == 0) {
        return bytes_.data();
    }

    if (mapped_) {
        if (rva > bytes_.size() || size > bytes_.size() - rva) {
            return nullptr;
        }
        return bytes_.data() + rva;
    }

    for (const auto& section : sections_) {
        const std::uint32_t span = std::max(section.virtualSize, section.rawSize);
        if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
            const std::uint32_t delta = rva - section.virtualAddress;
            if (delta >= section.rawSize) {
                return nullptr;
            }
            const std::uint64_t fileOffset = static_cast<std::uint64_t>(section.rawOffset) + delta;
            if (fileOffset > bytes_.size() || size > bytes_.size() - fileOffset) {
                return nullptr;
            }
            return bytes_.data() + fileOffset;
        }
    }

    // Headers are addressable directly.
    if (rva < sizeOfHeaders_ && rva + size <= bytes_.size()) {
        return bytes_.data() + rva;
    }
    return nullptr;
}

std::span<const std::uint8_t> ImageBuffer::span(std::uint32_t rva, std::size_t size) const {
    const auto* pointer = at(rva, size);
    return pointer ? std::span<const std::uint8_t>(pointer, size)
                   : std::span<const std::uint8_t>();
}

std::vector<std::uint8_t> ImageBuffer::copy(std::uint32_t rva, std::size_t size) const {
    const auto* pointer = at(rva, size);
    if (!pointer) {
        return {};
    }
    return std::vector<std::uint8_t>(pointer, pointer + size);
}

std::optional<std::uint32_t> ImageBuffer::fileOffsetOfRva(std::uint32_t rva) const {
    if (mapped_) {
        if (rva > bytes_.size()) {
            return std::nullopt;
        }
        return rva;
    }

    for (const auto& section : sections_) {
        const std::uint32_t span = std::max(section.virtualSize, section.rawSize);
        if (rva >= section.virtualAddress && rva < section.virtualAddress + span) {
            const std::uint32_t delta = rva - section.virtualAddress;
            if (delta >= section.rawSize) {
                return std::nullopt;
            }
            return section.rawOffset + delta;
        }
    }
    if (rva < sizeOfHeaders_) {
        return rva;
    }
    return std::nullopt;
}

std::uintptr_t ImageBuffer::addressOfRva(std::uint32_t rva) const {
    const auto offset = fileOffsetOfRva(rva);
    if (!offset) {
        return 0;
    }
    return base_ + *offset;
}

std::vector<ExportInfo> ImageBuffer::exports() const {
    std::vector<ExportInfo> result;
    if (exportRva_ == 0 || exportSize_ < 40) {
        return result;
    }

    const std::uint8_t* directory = at(exportRva_, 40);
    if (!directory) {
        return result;
    }

    const std::uint32_t nameCount = read32(directory + 24);
    const std::uint32_t namesRva = read32(directory + 32);
    const std::uint32_t ordinalsRva = read32(directory + 36);
    if (nameCount > 65536 || !namesRva || !ordinalsRva) {
        return result;
    }

    for (std::uint32_t i = 0; i < nameCount; ++i) {
        const std::uint8_t* namePointer = at(namesRva + i * 4, 4);
        const std::uint8_t* ordinalPointer = at(ordinalsRva + i * 2, 2);
        if (!namePointer || !ordinalPointer) {
            continue;
        }
        const std::uint32_t nameRva = read32(namePointer);
        const std::uint16_t ordinal = read16(ordinalPointer);
        const char* name = reinterpret_cast<const char*>(at(nameRva, 1));
        if (!name) {
            continue;
        }
        // The export name is NUL-terminated. Bound the search to the image.
        const std::size_t maxName = 512;
        std::size_t length = 0;
        while (length < maxName) {
            const char* c = reinterpret_cast<const char*>(
                at(nameRva + static_cast<std::uint32_t>(length), 1));
            if (!c || *c == '\0') {
                break;
            }
            ++length;
        }
        if (length == 0 || length == maxName) {
            continue;
        }

        ExportInfo info;
        info.name.assign(name, length);
        // AddressOfFunctions is the first directory entry; ordinal indexes it.
        const auto* functions = at(exportRva_, exportSize_);
        if (functions) {
            const std::uint32_t functionRva = read32(functions + 28);
            const auto* function = at(functionRva + ordinal * 4, 4);
            if (function) {
                info.rva = read32(function);
            }
        }
        result.push_back(std::move(info));
    }
    return result;
}

}  // namespace contra::pe

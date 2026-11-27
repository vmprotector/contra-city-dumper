#include "contra/loader.hpp"

#include "contra/layout.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <unordered_set>

namespace contra {

namespace {

constexpr std::uint32_t kMethodStatic = 0x0010;
constexpr std::uint32_t kMethodVirtual = 0x0040;
constexpr std::uint32_t kMethodAbstract = 0x0400;
constexpr std::uint32_t kMethodSpecialName = 0x0800;
constexpr std::uint32_t kMethodRTSpecialName = 0x1000;
constexpr std::uint32_t kMethodPInvoke = 0x2000;
constexpr std::uint32_t kMethodAccessMask = 0x0007;
constexpr std::uint32_t kMethodPublic = 0x0006;
constexpr std::uint32_t kMethodPrivate = 0x0001;

constexpr std::uint32_t kFieldStatic = 0x0010;
constexpr std::uint32_t kFieldInitOnly = 0x0020;
constexpr std::uint32_t kFieldLiteral = 0x0040;
constexpr std::uint32_t kFieldAccessMask = 0x0007;
constexpr std::uint32_t kFieldPublic = 0x0006;
constexpr std::uint32_t kFieldPrivate = 0x0001;

constexpr std::uint32_t kTypeLayoutMask = 0x0018;
constexpr std::uint32_t kTypeSequential = 0x0008;
constexpr std::uint32_t kTypeExplicit = 0x0010;
constexpr std::uint32_t kTypeInterface = 0x0020;
constexpr std::uint32_t kTypeAbstract = 0x0080;
constexpr std::uint32_t kTypeSealed = 0x0100;
constexpr std::uint32_t kTypeVisibilityMask = 0x0007;
constexpr std::uint32_t kTypePublic = 0x0001;
constexpr std::uint32_t kTypeNestedPublic = 0x0002;

std::uint16_t read16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}

std::uint32_t read32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t read64(const std::uint8_t* p) {
    return static_cast<std::uint64_t>(read32(p)) |
           (static_cast<std::uint64_t>(read32(p + 4)) << 32);
}

std::string stripGenericArguments(const std::string& name) {
    const auto pos = name.find('<');
    return pos == std::string::npos ? name : name.substr(0, pos);
}

model::FieldTypeKind kindFromSignature(const metadata::Metadata::TypeSig& sig) {
    using Kind = metadata::Metadata::TypeSig::Kind;
    switch (sig.kind) {
        case Kind::Boolean:
        case Kind::Char:
        case Kind::I1:
        case Kind::U1:
        case Kind::I2:
        case Kind::U2:
        case Kind::I4:
        case Kind::U4:
        case Kind::I8:
        case Kind::U8:
        case Kind::R4:
        case Kind::R8:
        case Kind::Void:
            return model::FieldTypeKind::Primitive;
        case Kind::String:
        case Kind::Object:
        case Kind::Class:
        case Kind::Array:
            return model::FieldTypeKind::Reference;
        case Kind::ValueType:
            return model::FieldTypeKind::ValueType;
        case Kind::GenericInst:
            return sig.isValueType ? model::FieldTypeKind::ValueType
                                   : model::FieldTypeKind::Reference;
        case Kind::Pointer:
        case Kind::ByRef:
        case Kind::FnPtr:
            return model::FieldTypeKind::Pointer;
        case Kind::GenericParam:
            return model::FieldTypeKind::GenericParameter;
        case Kind::TypedByRef:
            return model::FieldTypeKind::ValueType;
        case Kind::Unknown:
        default:
            return model::FieldTypeKind::Unknown;
    }
}

std::string parseConstant(const metadata::ConstantRow& row,
                          std::span<const std::uint8_t> value) {
    if (value.empty()) {
        return {};
    }

    switch (row.type) {
        case 0x02:
            return value[0] ? "true" : "false";
        case 0x03: {
            if (value.size() < 2) break;
            return std::to_string(read16(value.data()));
        }
        case 0x04:
            return std::to_string(static_cast<std::int8_t>(value[0]));
        case 0x05:
            return std::to_string(value[0]);
        case 0x06:
            if (value.size() < 2) break;
            return std::to_string(static_cast<std::int16_t>(read16(value.data())));
        case 0x07:
            if (value.size() < 2) break;
            return std::to_string(read16(value.data()));
        case 0x08:
            if (value.size() < 4) break;
            return std::to_string(static_cast<std::int32_t>(read32(value.data())));
        case 0x09:
            if (value.size() < 4) break;
            return std::to_string(read32(value.data()));
        case 0x0A:
            if (value.size() < 8) break;
            return std::to_string(static_cast<std::int64_t>(read64(value.data())));
        case 0x0B:
            if (value.size() < 8) break;
            return std::to_string(read64(value.data()));
        case 0x0C: {
            if (value.size() < 4) break;
            float number = 0;
            const std::uint32_t bits = read32(value.data());
            std::memcpy(&number, &bits, sizeof(number));
            std::ostringstream stream;
            stream.precision(9);
            stream << number;
            return stream.str();
        }
        case 0x0D: {
            if (value.size() < 8) break;
            double number = 0;
            const std::uint64_t bits = read64(value.data());
            std::memcpy(&number, &bits, sizeof(number));
            std::ostringstream stream;
            stream.precision(17);
            stream << number;
            return stream.str();
        }
        case 0x0E: {
            std::wstring text;
            for (std::size_t i = 0; i + 1 < value.size(); i += 2) {
                text.push_back(static_cast<wchar_t>(read16(value.data() + i)));
            }
            return "\"" + sanitizeUtf8(wideToUtf8(text)) + "\"";
        }
        case 0x12:
        case 0x1C:
            return "null";
        default:
            break;
    }

    std::ostringstream stream;
    stream << "0x";
    for (std::uint8_t byte : value) {
        stream << std::hex << static_cast<int>(byte >> 4) << static_cast<int>(byte & 0xF);
    }
    return stream.str();
}

struct ParsedMethodSignature {
    std::string text;
    std::string returnType;
    std::vector<std::string> paramTypes;
};

ParsedMethodSignature parseMethodSignature(const metadata::Metadata& md,
                                           std::span<const std::uint8_t> blob,
                                           const std::string& name) {
    ParsedMethodSignature result;
    if (blob.empty()) {
        result.text = "void " + name + "()";
        result.returnType = "System.Void";
        return result;
    }

    const std::uint8_t* cursor = blob.data();
    const std::uint8_t* end = blob.data() + blob.size();
    const std::uint8_t calling = *cursor++;
    if (calling & 0x10) {
        (void)md.readCompressedUint(cursor, end);
    }
    const std::uint32_t paramCount = md.readCompressedUint(cursor, end);
    const auto returnSig = md.readType(cursor, end);
    result.returnType = md.typeSigName(returnSig);

    result.paramTypes.reserve(paramCount);
    for (std::uint32_t i = 0; i < paramCount && cursor < end; ++i) {
        const auto sig = md.readType(cursor, end);
        result.paramTypes.push_back(md.typeSigName(sig));
    }

    std::string params;
    for (std::size_t i = 0; i < result.paramTypes.size(); ++i) {
        if (i) params += ", ";
        params += result.paramTypes[i];
    }
    result.text = result.returnType + " " + name + "(" + params + ")";
    return result;
}

std::string decodeUserString(const metadata::Metadata& md, std::uint32_t offset,
                             bool& ok) {
    ok = false;
    const auto bytes = md.userString(offset);
    if (bytes.empty() || bytes.size() < 1) {
        return {};
    }

    // The heap length includes the trailing terminal byte. The payload itself
    // is UTF-16LE, so ignore a stray odd byte rather than reading past the end.
    const std::size_t payload = bytes.size() - 1;
    std::wstring text;
    text.reserve(payload / 2);
    for (std::size_t i = 0; i + 1 < payload; i += 2) {
        text.push_back(static_cast<wchar_t>(read16(bytes.data() + i)));
    }
    ok = true;
    return sanitizeUtf8(wideToUtf8(text));
}

std::array<std::uint8_t, 256> makeOpcode1Lengths() {
    std::array<std::uint8_t, 256> table{};
    table.fill(1);

    for (int op = 0x0E; op <= 0x13; ++op) table[op] = 2;
    table[0x1F] = 2;
    table[0x20] = 5;
    table[0x21] = 9;
    table[0x22] = 5;
    table[0x23] = 9;
    table[0x27] = 5;
    table[0x28] = 5;
    table[0x29] = 5;
    for (int op = 0x2B; op <= 0x37; ++op) table[op] = 2;
    for (int op = 0x38; op <= 0x44; ++op) table[op] = 5;

    const std::uint8_t fiveByte[] = {
        0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x79,
        0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81,
        0x8C, 0x8D, 0x8F, 0xA3, 0xA4, 0xA5,
        0xC2, 0xC6, 0xD0, 0xDD,
    };
    for (std::uint8_t op : fiveByte) table[op] = 5;
    table[0xDE] = 2;
    return table;
}

std::array<std::uint8_t, 256> makeOpcode2Lengths() {
    std::array<std::uint8_t, 256> table{};
    table.fill(2);

    table[0x06] = 6;
    table[0x07] = 6;
    for (int op = 0x09; op <= 0x0E; ++op) table[op] = 4;
    table[0x12] = 4;
    table[0x15] = 6;
    table[0x16] = 6;
    table[0x19] = 4;
    table[0x1C] = 6;
    return table;
}

const std::array<std::uint8_t, 256> kOpcode1 = makeOpcode1Lengths();
const std::array<std::uint8_t, 256> kOpcode2 = makeOpcode2Lengths();

std::uint32_t addStringLiteral(model::SdkModel& model, const std::string& assembly,
                               const std::string& value, std::uint32_t token,
                               std::uint32_t heapOffset,
                               const model::StringUsage& usage) {
    const std::string key = assembly + "\x1f" + std::to_string(heapOffset);
    const auto found = model.stringByHeapOffset.find(key);
    if (found != model.stringByHeapOffset.end()) {
        auto& literal = model.strings[found->second];
        const bool duplicate = std::any_of(
            literal.usages.begin(), literal.usages.end(), [&](const model::StringUsage& u) {
                return u.className == usage.className && u.methodName == usage.methodName &&
                       u.methodSignature == usage.methodSignature &&
                       u.ilOffset == usage.ilOffset;
            });
        if (!duplicate) {
            literal.usages.push_back(usage);
        }
        return found->second;
    }

    const std::uint32_t index = static_cast<std::uint32_t>(model.strings.size());
    model::StringLiteral literal;
    literal.assembly = assembly;
    literal.value = value;
    literal.token = token;
    literal.heapOffset = heapOffset;
    literal.usages.push_back(usage);
    model.strings.push_back(std::move(literal));
    model.stringByHeapOffset[key] = index;
    return index;
}

void parseMethodBody(model::SdkModel& model, const pe::ImageBuffer& image,
                     const metadata::Metadata& md, const std::string& assembly,
                     const model::ClassInfo& klass, model::MethodInfo& method) {
    if (method.rva == 0 || image.at(method.rva, 1) == nullptr) {
        return;
    }

    const auto headerBytes = image.span(method.rva, 12);
    if (headerBytes.empty()) {
        return;
    }

    const std::uint8_t first = headerBytes[0];
    std::uint32_t codeRva = 0;
    std::uint32_t codeSize = 0;
    std::uint32_t headerSize = 0;

    if ((first & 0x03) == 0x02) {
        // Tiny format: one header byte, code size in bits 2..7.
        headerSize = 1;
        codeSize = first >> 2;
        codeRva = method.rva + 1;
    } else if ((first & 0x03) == 0x03) {
        const std::uint16_t flags = read16(headerBytes.data());
        headerSize = static_cast<std::uint32_t>((flags >> 12) & 0x0F) * 4;
        if (headerSize < 12 || headerBytes.size() < 12) {
            return;
        }
        codeSize = read32(headerBytes.data() + 4);
        codeRva = method.rva + headerSize;
    } else {
        return;
    }

    if (codeSize > 16u * 1024u * 1024u) {
        return;
    }

    const auto code = image.span(codeRva, codeSize);
    if (code.empty()) {
        return;
    }

    method.hasBody = true;
    method.ilSize = codeSize;
    method.bodySize = headerSize + codeSize;

    std::size_t offset = 0;
    while (offset < code.size()) {
        const std::uint8_t opcode = code[offset];
        std::uint32_t length = kOpcode1[opcode];
        std::uint32_t token = 0;

        if (opcode == 0xFE) {
            if (offset + 1 >= code.size()) {
                break;
            }
            const std::uint8_t second = code[offset + 1];
            length = kOpcode2[second];
        } else if (opcode == 0x45) {
            if (offset + 5 > code.size()) {
                break;
            }
            const std::uint32_t count = read32(code.data() + offset + 1);
            if (count > (code.size() - offset - 5) / 4) {
                break;
            }
            length = 1 + 4 + count * 4;
        } else if (opcode == 0x72) {
            if (offset + 5 > code.size()) {
                break;
            }
            token = read32(code.data() + offset + 1);
        }

        if (length == 0 || offset + length > code.size()) {
            break;
        }

        if (opcode == 0x72 && (token & 0xFF000000u) == 0x70000000u) {
            const std::uint32_t heapOffset = token & 0x00FFFFFFu;
            bool ok = false;
            const std::string value = decodeUserString(md, heapOffset, ok);
            if (ok && (heapOffset != 0 || !value.empty())) {
                model::StringUsage usage;
                usage.assembly = assembly;
                usage.className = klass.fullName;
                usage.methodName = method.name;
                usage.methodSignature = method.signature;
                usage.ilOffset = static_cast<std::uint32_t>(offset);
                usage.token = token;
                const std::uint32_t index =
                    addStringLiteral(model, assembly, value, token, heapOffset, usage);
                method.stringRefs.emplace_back(index, static_cast<std::uint32_t>(offset));
            }
        }

        offset += length;
    }
}

std::vector<pe::ImageBuffer> discoverManagedImages(const Process& process,
                                                   const LoadOptions& options) {
    std::vector<pe::ImageBuffer> images;
    std::unordered_set<std::uintptr_t> seen;
    const auto regions = process.regions();
    std::size_t budget = options.scanBudgetBytes;

    const auto tryBase = [&](std::uintptr_t base) {
        if (base == 0 || seen.count(base) != 0) {
            return;
        }
        std::string error;
        auto image = pe::ImageBuffer::fromProcess(process, base, error);
        if (!image || image->metadataRva() == 0) {
            logVerbose("image probe " + toHex(base) + " skipped: " + error);
            return;
        }
        seen.insert(base);
        logVerbose("managed image at " + toHex(base) + " layout=" +
                   (image->mapped() ? "mapped" : "file") + " size=" +
                   toHex(image->size()));
        images.push_back(std::move(*image));
    };

    for (const auto& region : regions) {
        if (region.state != MEM_COMMIT || !isReadableProtection(region.protect)) {
            continue;
        }
        if (region.size < 0x1000) {
            continue;
        }

        tryBase(region.base);

        if (budget == 0 || region.size <= 0x1000) {
            continue;
        }

        // Some loaders place a small header before the mapped PE file. Scan a
        // prefix of every readable region; --deep-scan extends the search over
        // the whole region under the configured budget.
        constexpr std::size_t kPrefixScan = 64 * 1024;
        constexpr std::size_t kChunkSize = 1024 * 1024;
        const std::size_t limit = options.deepScan ? std::min(region.size, budget)
                                                   : std::min(region.size, kPrefixScan);
        std::vector<std::uint8_t> chunk(std::min(kChunkSize, limit));
        std::size_t offset = 4;
        while (offset + 0x40 < limit && budget != 0) {
            const std::size_t toRead = std::min(chunk.size(), limit - offset);
            const std::size_t got = [&] {
                SIZE_T done = 0;
                ReadProcessMemory(process.handle(),
                                  reinterpret_cast<LPCVOID>(region.base + offset),
                                  chunk.data(), toRead, &done);
                return static_cast<std::size_t>(done);
            }();
            if (got < 0x40) {
                break;
            }
            budget -= std::min(budget, got);

            for (std::size_t i = 0; i + 0x40 < got; ++i) {
                if (chunk[i] == 'M' && chunk[i + 1] == 'Z') {
                    tryBase(region.base + offset + i);
                }
            }
            offset += got;
        }
    }

    std::sort(images.begin(), images.end(), [](const pe::ImageBuffer& a,
                                               const pe::ImageBuffer& b) {
        return a.base() < b.base();
    });
    return images;
}

std::string assemblyNameOf(const metadata::Metadata& md) {
    if (md.rows(metadata::Table::Assembly) == 0) {
        return {};
    }
    const auto row = md.assembly(1);
    return sanitizeUtf8(md.string(row.name));
}

std::string assemblyVersionOf(const metadata::Metadata& md) {
    if (md.rows(metadata::Table::Assembly) == 0) {
        return {};
    }
    const auto row = md.assembly(1);
    return std::to_string(row.major) + "." + std::to_string(row.minor) + "." +
           std::to_string(row.build) + "." + std::to_string(row.revision);
}

std::string moduleFileNameOf(const metadata::Metadata& md,
                             const std::string& assemblyName) {
    if (md.rows(metadata::Table::Module) != 0) {
        const auto row = md.module(1);
        const std::string name(sanitizeUtf8(md.string(row.name)));
        if (!name.empty()) {
            return name;
        }
    }
    return assemblyName.empty() ? "unknown.dll" : assemblyName + ".dll";
}

std::uint32_t pointerSizeOf(const Process& process,
                            const std::vector<NativeModule>& modules) {
    if (process.isWow64()) {
        return 4;
    }

    // Reading the main image header is more reliable than IsWow64Process when
    // the dumper itself is 32-bit. Prefer an .exe over the first loaded module.
    const NativeModule* main = nullptr;
    for (const auto& module : modules) {
        if (module.name.size() >= 4 &&
            iequals(wideToUtf8(module.name).substr(module.name.size() - 4), ".exe")) {
            main = &module;
            break;
        }
        if (!main) {
            main = &module;
        }
    }
    if (main) {
        std::array<std::uint8_t, 0x400> header{};
        if (process.read(main->base, header.data(), header.size()) &&
            header[0] == 'M' && header[1] == 'Z') {
            const std::uint32_t peOffset = read32(header.data() + 0x3C);
            if (peOffset + 6 < header.size() &&
                std::memcmp(header.data() + peOffset, "PE\0\0", 4) == 0) {
                const std::uint16_t machine = read16(header.data() + peOffset + 4);
                return machine == 0x8664 ? 8 : 4;
            }
        }
    }
    return 4;
}

}  // namespace

bool isGameAssemblyName(const std::string& assemblyName, const LoadOptions& options) {
    if (options.allAssemblies) {
        return true;
    }

    for (const auto& filter : options.includeSubstrings) {
        if (!filter.empty() && assemblyName.find(filter) != std::string::npos) {
            return true;
        }
    }

    if (assemblyName == "Assembly-CSharp" || assemblyName == "Assembly-CSharp-firstpass" ||
        assemblyName == "CCHitregV3" || assemblyName == "OPS.Obfuscator") {
        return true;
    }
    // The CC runtime modules carry per-build suffixes in their assembly names
    // (CCVoice.Runtime.pure_opus.candidate, CCWeaponTransport.Runtime.r13, ...).
    return startsWith(assemblyName, "CC") && assemblyName.find(".Runtime") != std::string::npos;
}

std::string readBuildVersionNear(const std::filesystem::path& start) {
    std::filesystem::path directory = start;
    std::error_code ec;
    if (std::filesystem::is_regular_file(directory, ec)) {
        directory = directory.parent_path();
    }

    for (int depth = 0; depth < 5 && !directory.empty(); ++depth) {
        const auto candidate = directory / "game.version";
        std::ifstream file(candidate);
        if (file) {
            std::string line;
            std::getline(file, line);
            line = trim(line);
            if (!line.empty()) {
                return line;
            }
        }
        const auto parent = directory.parent_path();
        if (parent == directory) {
            break;
        }
        directory = parent;
    }
    return {};
}

model::SdkModel Loader::loadFromProcess(const Process& process, const LoadOptions& options) {
    model::SdkModel model;
    model.mode = "live";
    model.generatedAt = currentTimestampUtc();
    model.pid = process.pid();
    model.pointerSize = pointerSizeOf(process, process.modules());
    model.processPath = wideToUtf8(process.exePath());
    model.processName = wideToUtf8(std::filesystem::path(process.exePath()).filename().wstring());
    model.buildVersion = readBuildVersionNear(process.exePath());

    const auto nativeModules = process.modules();
    const auto findNative = [&](const std::wstring& needle) -> const NativeModule* {
        for (const auto& module : nativeModules) {
            if (iequals(wideToUtf8(module.name), wideToUtf8(needle))) {
                return &module;
            }
        }
        return nullptr;
    };

    // These two are the usual IL2CPP anchors. Unity 5.6 statically links
    // UnityPlayer into the player executable, so a missing UnityPlayer.dll is
    // normal for this build line.
    if (!findNative(L"GameAssembly.dll")) {
        logVerbose("GameAssembly.dll not loaded");
    }
    if (!findNative(L"UnityPlayer.dll")) {
        logVerbose("UnityPlayer.dll not loaded (static Unity player build)");
    }
    if (!findNative(L"mono.dll") && !findNative(L"mono-2.0-bdwgc.dll")) {
        logVerbose("mono runtime module not found by common name");
    }

    bool hasMono = false;
    bool hasIl2Cpp = false;
    for (const auto& native : nativeModules) {
        model::ModuleInfo info;
        info.name = wideToUtf8(native.name);
        info.path = wideToUtf8(native.path);
        info.kind = "native";
        info.runtime = "native";
        info.base = native.base;
        info.size = native.size;
        info.is64 = model.pointerSize == 8;
        info.present = true;

        const auto lower = lowerAscii(info.name);
        if (lower.find("mono") != std::string::npos) {
            info.runtime = "mono";
            hasMono = true;
        } else if (lower == "gameassembly.dll") {
            info.runtime = "il2cpp";
            hasIl2Cpp = true;
        }

        // Keep the module list compact but complete; exports are only scanned
        // for the IL2CPP image, where they are actually useful.
        if (lower == "gameassembly.dll") {
            std::string error;
            if (auto image = pe::ImageBuffer::fromProcess(process, native.base, error, false)) {
                for (const auto& exportInfo : image->exports()) {
                    if (startsWith(exportInfo.name, "il2cpp_")) {
                        info.exports.push_back(exportInfo.name + " @ " +
                                               toHex(exportInfo.rva));
                    }
                }
            }
        }

        model.modules.push_back(std::move(info));
    }

    model.runtimeKind = hasMono ? "mono" : (hasIl2Cpp ? "il2cpp" : "unknown");

    const auto images = discoverManagedImages(process, options);
    logInfo("managed images discovered: " + std::to_string(images.size()));

    std::unordered_set<std::string> loadedAssemblies;
    for (const auto& raw : images) {
        ManagedImage image;
        image.image = raw;
        std::string error;
        if (!image.metadata.parse(image.image, error)) {
            logVerbose("metadata parse failed at " + toHex(image.image.base()) + ": " + error);
            continue;
        }
        if (model.runtimeVersion.empty()) {
            model.runtimeVersion = image.metadata.version();
        }

        const std::string assemblyName = assemblyNameOf(image.metadata);
        if (assemblyName.empty()) {
            continue;
        }
        if (loadedAssemblies.count(assemblyName) != 0) {
            logVerbose("duplicate managed assembly skipped: " + assemblyName);
            continue;
        }
        loadedAssemblies.insert(assemblyName);

        image.selected = isGameAssemblyName(assemblyName, options);
        image.module.name = moduleFileNameOf(image.metadata, assemblyName);
        image.module.kind = "managed";
        image.module.runtime = "mono";
        image.module.base = image.image.base();
        image.module.size = image.image.size();
        image.module.machine = image.image.machine();
        image.module.is64 = image.image.is64();
        image.module.present = true;
        image.module.selected = image.selected;
        image.module.fileLayout = !image.image.mapped();
        image.module.assemblyName = assemblyName;
        image.module.assemblyVersion = assemblyVersionOf(image.metadata);

        buildClassSkeletons(image, model, options);
        image.module.classCount = static_cast<std::uint32_t>(image.classes.size());
        model.modules.push_back(image.module);

        logInfo("managed " + image.module.name + " base=" + toHex(image.module.base) +
                " classes=" + std::to_string(image.module.classCount) +
                (image.selected ? " [selected]" : " [context]"));
    }

    LayoutOptions layout;
    layout.enabled = !options.noLayout;
    layout.gcAware = options.gcAwareLayout;
    computeLayouts(model, layout);

    if (model.runtimeKind == "il2cpp" && images.empty()) {
        model.warnings.push_back(
            "GameAssembly.dll is present but no Mono metadata was found. This build "
            "line uses Mono; IL2CPP metadata parsing is not implemented.");
    } else if (images.empty()) {
        model.warnings.push_back(
            "no managed assemblies were found; run elevated and try --deep-scan if "
            "the game is already past the loading screen");
    }

    return model;
}

model::SdkModel Loader::loadFromDirectory(const std::filesystem::path& managedDirectory,
                                          const LoadOptions& options) {
    model::SdkModel model;
    model.mode = "offline";
    model.generatedAt = currentTimestampUtc();
    model.pointerSize = 4;
    model.runtimeKind = "mono";
    model.processName = "offline";
    model.processPath = managedDirectory.string();
    model.buildVersion = readBuildVersionNear(managedDirectory);

    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(managedDirectory, ec)) {
        if (entry.is_regular_file() && endsWith(lowerAscii(entry.path().extension().string()),
                                                ".dll")) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());

    std::unordered_set<std::string> loadedAssemblies;
    for (const auto& path : files) {
        std::string error;
        auto raw = pe::ImageBuffer::fromFile(path, error);
        if (!raw) {
            logVerbose("skipped " + path.string() + ": " + error);
            continue;
        }

        ManagedImage image;
        image.image = std::move(*raw);
        if (!image.metadata.parse(image.image, error)) {
            logVerbose("metadata failed for " + path.filename().string() + ": " + error);
            continue;
        }
        if (model.runtimeVersion.empty()) {
            model.runtimeVersion = image.metadata.version();
        }

        const std::string assemblyName = assemblyNameOf(image.metadata);
        if (assemblyName.empty()) {
            logVerbose("no assembly row in " + path.filename().string());
            continue;
        }
        if (loadedAssemblies.count(assemblyName) != 0) {
            logVerbose("duplicate assembly " + assemblyName + " in " + path.filename().string());
            continue;
        }
        loadedAssemblies.insert(assemblyName);

        image.selected = isGameAssemblyName(assemblyName, options);
        image.module.name = moduleFileNameOf(image.metadata, assemblyName);
        image.module.path = path.string();
        image.module.kind = "managed";
        image.module.runtime = "mono";
        image.module.base = image.image.preferredBase();
        image.module.baseIsPreferred = true;
        image.module.fileLayout = true;
        image.module.size = image.image.size();
        image.module.machine = image.image.machine();
        image.module.is64 = image.image.is64();
        image.module.present = true;
        image.module.selected = image.selected;
        image.module.assemblyName = assemblyName;
        image.module.assemblyVersion = assemblyVersionOf(image.metadata);

        buildClassSkeletons(image, model, options);
        image.module.classCount = static_cast<std::uint32_t>(image.classes.size());
        model.modules.push_back(image.module);

        if (image.selected) {
            logInfo("offline " + image.module.name + " rva-base=" +
                    toHex(image.module.base) + " classes=" +
                    std::to_string(image.module.classCount));
        }
    }

    LayoutOptions layout;
    layout.enabled = !options.noLayout;
    layout.gcAware = options.gcAwareLayout;
    computeLayouts(model, layout);

    return model;
}

void Loader::buildClassSkeletons(ManagedImage& image, model::SdkModel& sdk,
                                 const LoadOptions& options) {
    auto& md = image.metadata;
    const std::string assemblyName = image.module.assemblyName;

    std::unordered_map<std::uint32_t, std::uint32_t> nestedToEnclosing;
    for (std::uint32_t i = 1; i <= md.rows(metadata::Table::NestedClass); ++i) {
        const auto row = md.nestedClass(i);
        nestedToEnclosing[row.nested] = row.enclosing;
    }

    struct ClassLayoutInfo {
        std::uint16_t packing = 0;
        std::uint32_t size = 0;
    };
    std::unordered_map<std::uint32_t, ClassLayoutInfo> classLayouts;
    for (std::uint32_t i = 1; i <= md.rows(metadata::Table::ClassLayout); ++i) {
        const auto row = md.classLayout(i);
        classLayouts[row.parent] = {row.packing, row.classSize};
    }

    std::unordered_map<std::uint32_t, std::uint32_t> fieldLayouts;
    for (std::uint32_t i = 1; i <= md.rows(metadata::Table::FieldLayout); ++i) {
        const auto row = md.fieldLayout(i);
        fieldLayouts[row.field] = row.offset;
    }

    std::unordered_map<std::uint32_t, std::string> constants;
    std::unordered_map<std::uint32_t, std::uint32_t> constantTokens;
    for (std::uint32_t i = 1; i <= md.rows(metadata::Table::Constant); ++i) {
        const auto row = md.constant(i);
        metadata::Table parentTable = metadata::Table::Count;
        const std::uint32_t parentRow =
            md.decodeCoded(metadata::CodedIndex::HasConstant, row.parent, parentTable);
        if (parentTable != metadata::Table::Field) {
            continue;
        }
        constants[parentRow] = parseConstant(row, md.blob(row.value));
        constantTokens[parentRow] = 0x0B000000u | i;
    }

    const std::uint32_t typeDefRows = md.rows(metadata::Table::TypeDef);
    const std::uint32_t fieldRows = md.rows(metadata::Table::Field);
    const std::uint32_t methodRows = md.rows(metadata::Table::MethodDef);
    const std::uint32_t paramRows = md.rows(metadata::Table::Param);

    for (std::uint32_t typeRow = 1; typeRow <= typeDefRows; ++typeRow) {
        const auto td = md.typeDef(typeRow);
        auto& klass = sdk.classes.emplace_back();
        klass.assembly = assemblyName;
        klass.name = sanitizeUtf8(md.string(td.name));
        klass.nameSpace = sanitizeUtf8(md.string(td.nameSpace));
        klass.fullName = md.typeDefFullName(typeRow);
        klass.token = 0x02000000u | typeRow;
        klass.flags = td.flags;
        klass.baseType = md.resolveTypeDefOrRef(td.extends);
        klass.isNested = nestedToEnclosing.count(typeRow) != 0;
        klass.isInterface = (td.flags & kTypeInterface) != 0;
        klass.isAbstract = (td.flags & kTypeAbstract) != 0;
        klass.isSealed = (td.flags & kTypeSealed) != 0;
        klass.isPublic = (td.flags & kTypeVisibilityMask) == kTypePublic ||
                         (td.flags & kTypeVisibilityMask) == kTypeNestedPublic;
        klass.isEnum = klass.baseType == "System.Enum";
        klass.isValueType = klass.isEnum || klass.baseType == "System.ValueType";
        klass.emit = image.selected;
        if (klass.emit && !options.includeClasses.empty()) {
            klass.emit = std::any_of(options.includeClasses.begin(),
                                     options.includeClasses.end(),
                                     [&](const std::string& filter) {
                                         return !filter.empty() &&
                                                klass.fullName.find(filter) != std::string::npos;
                                     });
        }

        const std::uint32_t layout = td.flags & kTypeLayoutMask;
        if (layout == kTypeSequential) {
            klass.layoutKind = "sequential";
        } else if (layout == kTypeExplicit) {
            klass.layoutKind = "explicit";
        } else {
            klass.layoutKind = "auto";
        }

        const auto layoutIt = classLayouts.find(typeRow);
        if (layoutIt != classLayouts.end()) {
            klass.packing = layoutIt->second.packing;
            klass.declaredSize = static_cast<std::int32_t>(layoutIt->second.size);
        }

        const std::uint32_t fieldStart = td.fieldList;
        std::uint32_t fieldEnd = fieldRows + 1;
        if (typeRow < typeDefRows) {
            fieldEnd = md.typeDef(typeRow + 1).fieldList;
        }
        if (fieldStart == 0) {
            fieldEnd = fieldStart;
        }

        for (std::uint32_t fieldRow = fieldStart; fieldRow < fieldEnd && fieldRow <= fieldRows;
             ++fieldRow) {
            const auto fr = md.field(fieldRow);
            model::FieldInfo field;
            field.name = sanitizeUtf8(md.string(fr.name));
            field.declaringType = klass.fullName;
            field.token = 0x04000000u | fieldRow;
            field.flags = fr.flags;
            field.signature = fr.signature;
            field.isStatic = (fr.flags & kFieldStatic) != 0;
            field.isLiteral = (fr.flags & kFieldLiteral) != 0;
            field.isInitOnly = (fr.flags & kFieldInitOnly) != 0;
            field.isPublic = (fr.flags & kFieldAccessMask) == kFieldPublic;
            field.isPrivate = (fr.flags & kFieldAccessMask) == kFieldPrivate;

            const auto signature = md.blob(fr.signature);
            if (!signature.empty() && signature[0] == 0x06) {
                const std::uint8_t* cursor = signature.data() + 1;
                const std::uint8_t* end = signature.data() + signature.size();
                const auto sig = md.readType(cursor, end);
                field.typeName = md.typeSigName(sig);
                field.typeKind = kindFromSignature(sig);
                if (field.typeKind == model::FieldTypeKind::ValueType ||
                    field.typeKind == model::FieldTypeKind::Reference) {
                    field.typeClassName = stripGenericArguments(sig.name);
                } else if (sig.kind == metadata::Metadata::TypeSig::Kind::GenericInst) {
                    field.typeClassName = stripGenericArguments(sig.name);
                }
            } else {
                field.typeName = "unknown";
                field.typeKind = model::FieldTypeKind::Unknown;
            }

            const auto constantIt = constants.find(fieldRow);
            if (constantIt != constants.end()) {
                field.constant = constantIt->second;
                field.constantToken = constantTokens[fieldRow];
            }

            const auto fieldLayoutIt = fieldLayouts.find(fieldRow);
            if (fieldLayoutIt != fieldLayouts.end()) {
                field.explicitOffset = static_cast<std::int32_t>(fieldLayoutIt->second);
            }

            klass.fields.push_back(std::move(field));
        }

        const std::uint32_t methodStart = td.methodList;
        std::uint32_t methodEnd = methodRows + 1;
        if (typeRow < typeDefRows) {
            methodEnd = md.typeDef(typeRow + 1).methodList;
        }
        if (methodStart == 0) {
            methodEnd = methodStart;
        }

        for (std::uint32_t methodRow = methodStart;
             methodRow < methodEnd && methodRow <= methodRows; ++methodRow) {
            const auto mr = md.methodDef(methodRow);
            model::MethodInfo method;
            method.name = sanitizeUtf8(md.string(mr.name));
            method.token = 0x06000000u | methodRow;
            method.flags = mr.flags;
            method.implFlags = mr.implFlags;
            method.rva = mr.rva;
            method.address = (mr.rva == 0 || sdk.mode != "live")
                                 ? 0
                                 : image.image.addressOfRva(mr.rva);
            method.isStatic = (mr.flags & kMethodStatic) != 0;
            method.isVirtual = (mr.flags & kMethodVirtual) != 0;
            method.isAbstract = (mr.flags & kMethodAbstract) != 0;
            method.isPInvoke = (mr.flags & kMethodPInvoke) != 0;
            method.isSpecialName = (mr.flags & kMethodSpecialName) != 0;
            method.isPublic = (mr.flags & kMethodAccessMask) == kMethodPublic;
            method.isPrivate = (mr.flags & kMethodAccessMask) == kMethodPrivate;
            method.isConstructor = method.name == ".ctor" || method.name == ".cctor" ||
                                   (mr.flags & kMethodRTSpecialName) != 0;

            const auto parsed = parseMethodSignature(md, md.blob(mr.signature), method.name);
            method.signature = parsed.text;
            method.returnType = parsed.returnType;
            method.paramTypes = parsed.paramTypes;

            std::uint32_t paramStart = mr.paramList;
            std::uint32_t paramEnd = paramRows + 1;
            if (methodRow < methodRows) {
                paramEnd = md.methodDef(methodRow + 1).paramList;
            }
            if (paramStart == 0) {
                paramStart = paramEnd;
            }

            std::vector<std::string> names(parsed.paramTypes.size());
            for (std::uint32_t p = paramStart; p < paramEnd && p <= paramRows; ++p) {
                const auto pr = md.param(p);
                if (pr.sequence == 0 || pr.sequence > names.size()) {
                    continue;
                }
                names[pr.sequence - 1] = sanitizeUtf8(md.string(pr.name));
            }
            for (std::size_t i = 0; i < names.size(); ++i) {
                if (names[i].empty()) {
                    names[i] = "arg" + std::to_string(i);
                }
            }
            method.paramNames = std::move(names);

            if (!options.noStrings) {
                parseMethodBody(sdk, image.image, md, assemblyName, klass, method);
            }

            klass.methods.push_back(std::move(method));
        }

        const std::string exactKey = assemblyName + "\x1f" + klass.fullName;
        sdk.classByAssemblyAndName.emplace(exactKey, &klass);
        if (sdk.classByFullName.find(klass.fullName) == sdk.classByFullName.end()) {
            sdk.classByFullName.emplace(klass.fullName, &klass);
        }
        image.classes.push_back(&klass);
    }

    (void)paramRows;
}

}  // namespace contra

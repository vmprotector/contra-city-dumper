#include "contra/metadata.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace contra::metadata {

namespace {

constexpr std::uint32_t kBsjb = 0x424A5342;

std::uint16_t read16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}

std::uint32_t read32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

struct CodedSpec {
    const Table* tables;
    std::uint8_t count;
    std::uint8_t tagBits;
};

const Table kTypeDefOrRef[] = {Table::TypeDef, Table::TypeRef, Table::TypeSpec};
const Table kHasConstant[] = {Table::Field, Table::Param, Table::Property};
const Table kHasCustomAttribute[] = {
    Table::MethodDef, Table::Field, Table::TypeRef, Table::TypeDef, Table::Param,
    Table::InterfaceImpl, Table::MemberRef, Table::Module, Table::DeclSecurity,
    Table::Property, Table::Event, Table::StandAloneSig, Table::ModuleRef,
    Table::TypeSpec, Table::Assembly, Table::AssemblyRef, Table::File,
    Table::ExportedType, Table::ManifestResource, Table::GenericParam,
    Table::GenericParamConstraint, Table::MethodSpec,
};
const Table kHasFieldMarshal[] = {Table::Field, Table::Param};
const Table kHasDeclSecurity[] = {Table::TypeDef, Table::MethodDef, Table::Assembly};
const Table kMemberRefParent[] = {Table::TypeDef, Table::TypeRef, Table::ModuleRef,
                                  Table::MethodDef, Table::TypeSpec};
const Table kHasSemantics[] = {Table::Event, Table::Property};
const Table kMethodDefOrRef[] = {Table::MethodDef, Table::MemberRef};
const Table kMemberForwarded[] = {Table::Field, Table::MethodDef};
const Table kImplementation[] = {Table::File, Table::AssemblyRef, Table::ExportedType};
const Table kCustomAttributeType[] = {Table::MethodDef, Table::MemberRef};
const Table kResolutionScope[] = {Table::Module, Table::ModuleRef, Table::AssemblyRef,
                                  Table::TypeRef};
const Table kTypeOrMethodDef[] = {Table::TypeDef, Table::MethodDef};

CodedSpec specFor(CodedIndex index) {
    switch (index) {
        case CodedIndex::TypeDefOrRef:
            return {kTypeDefOrRef, 3, 2};
        case CodedIndex::HasConstant:
            return {kHasConstant, 3, 2};
        case CodedIndex::HasCustomAttribute:
            return {kHasCustomAttribute, 22, 5};
        case CodedIndex::HasFieldMarshal:
            return {kHasFieldMarshal, 2, 1};
        case CodedIndex::HasDeclSecurity:
            return {kHasDeclSecurity, 3, 2};
        case CodedIndex::MemberRefParent:
            return {kMemberRefParent, 5, 3};
        case CodedIndex::HasSemantics:
            return {kHasSemantics, 2, 1};
        case CodedIndex::MethodDefOrRef:
            return {kMethodDefOrRef, 2, 1};
        case CodedIndex::MemberForwarded:
            return {kMemberForwarded, 2, 1};
        case CodedIndex::Implementation:
            return {kImplementation, 3, 2};
        case CodedIndex::CustomAttributeType:
            // Tags 2 and 3 are MethodDef and MemberRef; tags 0/1 are unused.
            return {kCustomAttributeType, 2, 3};
        case CodedIndex::ResolutionScope:
            return {kResolutionScope, 4, 2};
        case CodedIndex::TypeOrMethodDef:
            return {kTypeOrMethodDef, 2, 1};
    }
    return {nullptr, 0, 0};
}

class RowCursor {
public:
    RowCursor(const std::uint8_t* row, const Metadata& metadata)
        : cursor_(row), metadata_(metadata) {}

    std::uint8_t u8() {
        return *cursor_++;
    }

    std::uint16_t u16() {
        const std::uint16_t value = read16(cursor_);
        cursor_ += 2;
        return value;
    }

    std::uint32_t u32() {
        const std::uint32_t value = read32(cursor_);
        cursor_ += 4;
        return value;
    }

    std::uint32_t index(Table table) {
        const std::uint32_t size = metadata_.layout(table).rows < 0x10000 ? 2 : 4;
        return readIndex(size);
    }

    std::uint32_t coded(CodedIndex codedIndex) {
        const auto spec = specFor(codedIndex);
        std::uint32_t maxRows = 0;
        for (std::uint8_t i = 0; i < spec.count; ++i) {
            maxRows = std::max(maxRows, metadata_.rows(spec.tables[i]));
        }
        const std::uint32_t size = maxRows < (1u << (16 - spec.tagBits)) ? 2 : 4;
        return readIndex(size);
    }

    std::uint32_t stringIndex() { return readIndex(metadata_.heapIndexSize(0x01)); }
    std::uint32_t guidIndex() { return readIndex(metadata_.heapIndexSize(0x02)); }
    std::uint32_t blobIndex() { return readIndex(metadata_.heapIndexSize(0x04)); }

private:
    std::uint32_t readIndex(std::uint32_t size) {
        if (size == 2) {
            const std::uint16_t value = read16(cursor_);
            cursor_ += 2;
            return value;
        }
        return u32();
    }

    const std::uint8_t* cursor_;
    const Metadata& metadata_;
};

}  // namespace

bool Metadata::parse(const pe::ImageBuffer& image, std::string& error) {
    if (image.metadataRva() == 0 || image.metadataSize() < 16) {
        error = "image has no CLI metadata directory";
        return false;
    }

    metadata_ = image.copy(image.metadataRva(), image.metadataSize());
    if (metadata_.empty()) {
        error = "cannot read CLI metadata";
        return false;
    }

    if (read32(metadata_.data()) != kBsjb) {
        error = "bad metadata signature";
        return false;
    }

    const std::uint32_t versionLength = read32(metadata_.data() + 12);
    const std::uint32_t versionOffset = 16;
    if (versionLength > metadata_.size() - versionOffset) {
        error = "truncated metadata version";
        return false;
    }
    version_.assign(reinterpret_cast<const char*>(metadata_.data() + versionOffset),
                    versionLength);
    while (!version_.empty() && version_.back() == '\0') {
        version_.pop_back();
    }

    std::size_t cursor = versionOffset + versionLength;
    cursor = alignUp(cursor, std::size_t{4});
    if (cursor + 4 > metadata_.size()) {
        error = "truncated metadata header";
        return false;
    }

    const std::uint16_t streamCount = read16(metadata_.data() + cursor + 2);
    cursor += 4;

    for (std::uint16_t i = 0; i < streamCount; ++i) {
        cursor = alignUp(cursor, std::size_t{4});
        if (cursor + 8 > metadata_.size()) {
            error = "truncated stream header";
            return false;
        }
        const std::uint32_t offset = read32(metadata_.data() + cursor);
        const std::uint32_t size = read32(metadata_.data() + cursor + 4);
        cursor += 8;

        const char* name = reinterpret_cast<const char*>(metadata_.data() + cursor);
        std::size_t nameLength = 0;
        while (cursor + nameLength < metadata_.size() && name[nameLength] != '\0') {
            ++nameLength;
        }
        if (cursor + nameLength >= metadata_.size()) {
            error = "unterminated stream name";
            return false;
        }
        const std::string streamName(name, nameLength);
        cursor += alignUp(nameLength + 1, std::size_t{4});

        if (offset > metadata_.size() || size > metadata_.size() - offset) {
            error = "stream out of range: " + streamName;
            return false;
        }

        const std::uint8_t* data = metadata_.data() + offset;
        if (streamName == "#~" || streamName == "#-") {
            tableStreamOffset_ = offset;
            tableStreamSize_ = size;
        } else if (streamName == "#Strings") {
            strings_.assign(data, data + size);
        } else if (streamName == "#US") {
            userStrings_.assign(data, data + size);
        } else if (streamName == "#Blob") {
            blobs_.assign(data, data + size);
        } else if (streamName == "#GUID") {
            guids_.assign(data, data + size);
        }
    }

    if (tableStreamOffset_ == 0 || tableStreamSize_ < 24) {
        error = "missing #~ table stream";
        return false;
    }

    if (!parseTableStream(error)) {
        return false;
    }

    pointerSize_ = image.is64() ? 8 : 4;
    return true;
}

bool Metadata::parseTableStream(std::string& error) {
    const std::uint8_t* stream = metadata_.data() + tableStreamOffset_;
    if (tableStreamSize_ < 24) {
        error = "table stream too small";
        return false;
    }

    heapSizes_ = stream[6];
    const std::uint64_t valid = static_cast<std::uint64_t>(read32(stream + 8)) |
                                (static_cast<std::uint64_t>(read32(stream + 12)) << 32);

    std::size_t cursor = 24;
    for (std::uint32_t i = 0; i < tableId(Table::Count); ++i) {
        if ((valid & (1ull << i)) == 0) {
            continue;
        }
        if (cursor + 4 > tableStreamSize_) {
            error = "truncated row count table";
            return false;
        }
        rowCounts_[i] = read32(stream + cursor);
        cursor += 4;
    }

    computeTableLayouts();

    const std::uint64_t dataStart = cursor;
    std::uint64_t relative = dataStart;
    for (std::uint32_t i = 0; i < tableId(Table::Count); ++i) {
        auto& table = tables_[i];
        // Table offsets are relative to the metadata root, not to the #~ stream.
        table.offset = static_cast<std::uint32_t>(tableStreamOffset_ + relative);
        relative += static_cast<std::uint64_t>(table.rows) * table.rowSize;
        if (relative > tableStreamSize_) {
            error = "table data exceeds stream";
            return false;
        }
    }

    return true;
}

std::uint32_t Metadata::simpleIndexSize(Table table) const {
    return rows(table) < 0x10000 ? 2 : 4;
}

std::uint32_t Metadata::heapIndexSize(std::uint8_t flag) const {
    return (heapSizes_ & flag) ? 4 : 2;
}

std::uint32_t Metadata::codedIndexSize(CodedIndex index) const {
    const auto spec = specFor(index);
    std::uint32_t maxRows = 0;
    for (std::uint8_t i = 0; i < spec.count; ++i) {
        maxRows = std::max(maxRows, rows(spec.tables[i]));
    }
    return maxRows < (1u << (16 - spec.tagBits)) ? 2 : 4;
}

void Metadata::computeTableLayouts() {
    const std::uint32_t str = heapIndexSize(0x01);
    const std::uint32_t guid = heapIndexSize(0x02);
    const std::uint32_t blob = heapIndexSize(0x04);

    const auto sized = [&](Table table, auto&& builder) {
        std::uint32_t size = 0;
        builder(size);
        tables_[tableId(table)].rowSize = size;
        tables_[tableId(table)].rows = rowCounts_[tableId(table)];
    };

    const auto idx = [&](Table table) { return simpleIndexSize(table); };
    const auto coded = [&](CodedIndex index) { return codedIndexSize(index); };

    sized(Table::Module, [&](std::uint32_t& s) { s = 2 + str + guid * 3; });
    sized(Table::TypeRef, [&](std::uint32_t& s) {
        s = coded(CodedIndex::ResolutionScope) + str * 2;
    });
    sized(Table::TypeDef, [&](std::uint32_t& s) {
        s = 4 + str * 2 + coded(CodedIndex::TypeDefOrRef) + idx(Table::Field) +
            idx(Table::MethodDef);
    });
    sized(Table::FieldPtr, [&](std::uint32_t& s) { s = idx(Table::Field); });
    sized(Table::Field, [&](std::uint32_t& s) { s = 2 + str + blob; });
    sized(Table::MethodPtr, [&](std::uint32_t& s) { s = idx(Table::MethodDef); });
    sized(Table::MethodDef, [&](std::uint32_t& s) {
        s = 4 + 2 + 2 + str + blob + idx(Table::Param);
    });
    sized(Table::ParamPtr, [&](std::uint32_t& s) { s = idx(Table::Param); });
    sized(Table::Param, [&](std::uint32_t& s) { s = 2 + 2 + str; });
    sized(Table::InterfaceImpl, [&](std::uint32_t& s) {
        s = idx(Table::TypeDef) + coded(CodedIndex::TypeDefOrRef);
    });
    sized(Table::MemberRef, [&](std::uint32_t& s) {
        s = coded(CodedIndex::MemberRefParent) + str + blob;
    });
    sized(Table::Constant, [&](std::uint32_t& s) {
        s = 1 + 1 + coded(CodedIndex::HasConstant) + blob;
    });
    sized(Table::CustomAttribute, [&](std::uint32_t& s) {
        s = coded(CodedIndex::HasCustomAttribute) +
            coded(CodedIndex::CustomAttributeType) + blob;
    });
    sized(Table::FieldMarshal, [&](std::uint32_t& s) {
        s = coded(CodedIndex::HasFieldMarshal) + blob;
    });
    sized(Table::DeclSecurity, [&](std::uint32_t& s) {
        s = 2 + coded(CodedIndex::HasDeclSecurity) + blob;
    });
    sized(Table::ClassLayout, [&](std::uint32_t& s) {
        s = 2 + 4 + idx(Table::TypeDef);
    });
    sized(Table::FieldLayout, [&](std::uint32_t& s) { s = 4 + idx(Table::Field); });
    sized(Table::StandAloneSig, [&](std::uint32_t& s) { s = blob; });
    sized(Table::EventMap, [&](std::uint32_t& s) {
        s = idx(Table::TypeDef) + idx(Table::Event);
    });
    sized(Table::EventPtr, [&](std::uint32_t& s) { s = idx(Table::Event); });
    sized(Table::Event, [&](std::uint32_t& s) {
        s = 2 + str + coded(CodedIndex::TypeDefOrRef);
    });
    sized(Table::PropertyMap, [&](std::uint32_t& s) {
        s = idx(Table::TypeDef) + idx(Table::Property);
    });
    sized(Table::PropertyPtr, [&](std::uint32_t& s) { s = idx(Table::Property); });
    sized(Table::Property, [&](std::uint32_t& s) { s = 2 + str + blob; });
    sized(Table::MethodSemantics, [&](std::uint32_t& s) {
        s = 2 + idx(Table::MethodDef) + coded(CodedIndex::HasSemantics);
    });
    sized(Table::MethodImpl, [&](std::uint32_t& s) {
        s = idx(Table::TypeDef) + coded(CodedIndex::MethodDefOrRef) * 2;
    });
    sized(Table::ModuleRef, [&](std::uint32_t& s) { s = str; });
    sized(Table::TypeSpec, [&](std::uint32_t& s) { s = blob; });
    sized(Table::ImplMap, [&](std::uint32_t& s) {
        s = 2 + coded(CodedIndex::MemberForwarded) + str + idx(Table::ModuleRef);
    });
    sized(Table::FieldRVA, [&](std::uint32_t& s) { s = 4 + idx(Table::Field); });
    sized(Table::ENCLog, [&](std::uint32_t& s) { s = 4 + 4; });
    sized(Table::ENCMap, [&](std::uint32_t& s) { s = 4; });
    sized(Table::Assembly, [&](std::uint32_t& s) {
        s = 4 + 2 + 2 + 2 + 2 + 4 + blob + str + str;
    });
    sized(Table::AssemblyProcessor, [&](std::uint32_t& s) { s = 4; });
    sized(Table::AssemblyOS, [&](std::uint32_t& s) { s = 4 + 4 + 4; });
    sized(Table::AssemblyRef, [&](std::uint32_t& s) {
        s = 2 + 2 + 2 + 2 + 4 + blob + str + str + blob;
    });
    sized(Table::AssemblyRefProcessor, [&](std::uint32_t& s) {
        s = 4 + idx(Table::AssemblyRef);
    });
    sized(Table::AssemblyRefOS, [&](std::uint32_t& s) {
        s = 4 + 4 + 4 + idx(Table::AssemblyRef);
    });
    sized(Table::File, [&](std::uint32_t& s) { s = 4 + str + blob; });
    sized(Table::ExportedType, [&](std::uint32_t& s) {
        s = 4 + 4 + str + str + coded(CodedIndex::Implementation);
    });
    sized(Table::ManifestResource, [&](std::uint32_t& s) {
        s = 4 + 4 + str + coded(CodedIndex::Implementation);
    });
    sized(Table::NestedClass, [&](std::uint32_t& s) {
        s = idx(Table::TypeDef) * 2;
    });
    sized(Table::GenericParam, [&](std::uint32_t& s) {
        s = 2 + 2 + coded(CodedIndex::TypeOrMethodDef) + str;
    });
    sized(Table::MethodSpec, [&](std::uint32_t& s) {
        s = coded(CodedIndex::MethodDefOrRef) + blob;
    });
    sized(Table::GenericParamConstraint, [&](std::uint32_t& s) {
        s = idx(Table::GenericParam) + coded(CodedIndex::TypeDefOrRef);
    });
}

std::uint32_t Metadata::rows(Table table) const {
    return tables_[tableId(table)].rows;
}

const TableLayout& Metadata::layout(Table table) const {
    return tables_[tableId(table)];
}

const std::uint8_t* Metadata::row(Table table, std::uint32_t oneBasedRow) const {
    const auto& info = layout(table);
    if (oneBasedRow == 0 || oneBasedRow > info.rows || info.rowSize == 0) {
        return nullptr;
    }
    const std::uint64_t offset = static_cast<std::uint64_t>(info.offset) +
                                 static_cast<std::uint64_t>(oneBasedRow - 1) * info.rowSize;
    if (offset + info.rowSize > metadata_.size()) {
        return nullptr;
    }
    return metadata_.data() + offset;
}

std::string_view Metadata::string(std::uint32_t index) const {
    if (index == 0 || index >= strings_.size()) {
        return {};
    }
    const char* start = reinterpret_cast<const char*>(strings_.data() + index);
    std::size_t max = strings_.size() - index;
    std::size_t length = 0;
    while (length < max && start[length] != '\0') {
        ++length;
    }
    return std::string_view(start, length);
}

std::span<const std::uint8_t> Metadata::blob(std::uint32_t index) const {
    if (index == 0 || index >= blobs_.size()) {
        return {};
    }
    const std::uint8_t* cursor = blobs_.data() + index;
    const std::uint8_t* end = blobs_.data() + blobs_.size();
    const std::uint32_t length = readCompressedUint(cursor, end);
    if (length == 0 || cursor > end || length > static_cast<std::uint32_t>(end - cursor)) {
        return {};
    }
    return std::span<const std::uint8_t>(cursor, length);
}

std::span<const std::uint8_t> Metadata::userString(std::uint32_t index) const {
    if (index == 0 || index >= userStrings_.size()) {
        return {};
    }
    const std::uint8_t* cursor = userStrings_.data() + index;
    const std::uint8_t* end = userStrings_.data() + userStrings_.size();
    const std::uint32_t length = readCompressedUint(cursor, end);
    if (length == 0 || cursor > end || length > static_cast<std::uint32_t>(end - cursor)) {
        return {};
    }
    return std::span<const std::uint8_t>(cursor, length);
}

std::uint32_t Metadata::readCompressedUint(const std::uint8_t*& cursor,
                                           const std::uint8_t* end) const {
    if (cursor >= end) {
        return 0;
    }
    const std::uint8_t first = *cursor++;
    if ((first & 0x80) == 0) {
        return first;
    }
    if ((first & 0xC0) == 0x80) {
        if (cursor >= end) {
            return 0;
        }
        return (static_cast<std::uint32_t>(first & 0x3F) << 8) | *cursor++;
    }
    if ((first & 0xE0) == 0xC0) {
        if (end - cursor < 3) {
            return 0;
        }
        const std::uint32_t value = (static_cast<std::uint32_t>(first & 0x1F) << 24) |
                                    (static_cast<std::uint32_t>(cursor[0]) << 16) |
                                    (static_cast<std::uint32_t>(cursor[1]) << 8) |
                                    cursor[2];
        cursor += 3;
        return value;
    }
    return 0;
}

std::uint32_t Metadata::decodeCoded(CodedIndex kind, std::uint32_t value,
                                    Table& table) const {
    const auto spec = specFor(kind);
    const std::uint32_t tag = value & ((1u << spec.tagBits) - 1);
    std::uint32_t row = value >> spec.tagBits;
    table = Table::Count;

    if (kind == CodedIndex::CustomAttributeType) {
        if (tag == 2) {
            table = Table::MethodDef;
        } else if (tag == 3) {
            table = Table::MemberRef;
        }
        return row;
    }

    if (tag < spec.count) {
        table = spec.tables[tag];
    }
    return row;
}

std::uint32_t Metadata::encodeTypeDefOrRefTag(Table table) const {
    switch (table) {
        case Table::TypeDef: return 0;
        case Table::TypeRef: return 1;
        case Table::TypeSpec: return 2;
        default: return 0;
    }
}

TypeDefRow Metadata::typeDef(std::uint32_t rowIndex) const {
    TypeDefRow result;
    const auto* data = row(Table::TypeDef, rowIndex);
    if (!data) {
        return result;
    }
    RowCursor cursor(data, *this);
    result.flags = cursor.u32();
    result.name = cursor.stringIndex();
    result.nameSpace = cursor.stringIndex();
    result.extends = cursor.coded(CodedIndex::TypeDefOrRef);
    result.fieldList = cursor.index(Table::Field);
    result.methodList = cursor.index(Table::MethodDef);
    return result;
}

TypeRefRow Metadata::typeRef(std::uint32_t rowIndex) const {
    TypeRefRow result;
    const auto* data = row(Table::TypeRef, rowIndex);
    if (!data) {
        return result;
    }
    RowCursor cursor(data, *this);
    result.resolutionScope = cursor.coded(CodedIndex::ResolutionScope);
    result.name = cursor.stringIndex();
    result.nameSpace = cursor.stringIndex();
    return result;
}

FieldRow Metadata::field(std::uint32_t rowIndex) const {
    FieldRow result;
    const auto* data = row(Table::Field, rowIndex);
    if (!data) {
        return result;
    }
    RowCursor cursor(data, *this);
    result.flags = cursor.u16();
    result.name = cursor.stringIndex();
    result.signature = cursor.blobIndex();
    return result;
}

MethodDefRow Metadata::methodDef(std::uint32_t rowIndex) const {
    MethodDefRow result;
    const auto* data = row(Table::MethodDef, rowIndex);
    if (!data) {
        return result;
    }
    RowCursor cursor(data, *this);
    result.rva = cursor.u32();
    result.implFlags = cursor.u16();
    result.flags = cursor.u16();
    result.name = cursor.stringIndex();
    result.signature = cursor.blobIndex();
    result.paramList = cursor.index(Table::Param);
    return result;
}

ParamRow Metadata::param(std::uint32_t rowIndex) const {
    ParamRow result;
    const auto* data = row(Table::Param, rowIndex);
    if (!data) {
        return result;
    }
    RowCursor cursor(data, *this);
    result.flags = cursor.u16();
    result.sequence = cursor.u16();
    result.name = cursor.stringIndex();
    return result;
}

ClassLayoutRow Metadata::classLayout(std::uint32_t rowIndex) const {
    ClassLayoutRow result;
    const auto* data = row(Table::ClassLayout, rowIndex);
    if (!data) {
        return result;
    }
    RowCursor cursor(data, *this);
    result.packing = cursor.u16();
    result.classSize = cursor.u32();
    result.parent = cursor.index(Table::TypeDef);
    return result;
}

FieldLayoutRow Metadata::fieldLayout(std::uint32_t rowIndex) const {
    FieldLayoutRow result;
    const auto* data = row(Table::FieldLayout, rowIndex);
    if (!data) {
        return result;
    }
    RowCursor cursor(data, *this);
    result.offset = cursor.u32();
    result.field = cursor.index(Table::Field);
    return result;
}

NestedClassRow Metadata::nestedClass(std::uint32_t rowIndex) const {
    NestedClassRow result;
    const auto* data = row(Table::NestedClass, rowIndex);
    if (!data) {
        return result;
    }
    RowCursor cursor(data, *this);
    result.nested = cursor.index(Table::TypeDef);
    result.enclosing = cursor.index(Table::TypeDef);
    return result;
}

ConstantRow Metadata::constant(std::uint32_t rowIndex) const {
    ConstantRow result;
    const auto* data = row(Table::Constant, rowIndex);
    if (!data) {
        return result;
    }
    RowCursor cursor(data, *this);
    result.type = cursor.u8();
    (void)cursor.u8();
    result.parent = cursor.coded(CodedIndex::HasConstant);
    result.value = cursor.blobIndex();
    return result;
}

AssemblyRow Metadata::assembly(std::uint32_t rowIndex) const {
    AssemblyRow result;
    const auto* data = row(Table::Assembly, rowIndex);
    if (!data) {
        return result;
    }
    RowCursor cursor(data, *this);
    result.hashAlg = cursor.u32();
    result.major = cursor.u16();
    result.minor = cursor.u16();
    result.build = cursor.u16();
    result.revision = cursor.u16();
    result.flags = cursor.u32();
    result.publicKey = cursor.blobIndex();
    result.name = cursor.stringIndex();
    result.culture = cursor.stringIndex();
    return result;
}

ModuleRow Metadata::module(std::uint32_t rowIndex) const {
    ModuleRow result;
    const auto* data = row(Table::Module, rowIndex);
    if (!data) {
        return result;
    }
    RowCursor cursor(data, *this);
    result.generation = cursor.u16();
    result.name = cursor.stringIndex();
    return result;
}

std::string Metadata::typeDefFullName(std::uint32_t rowIndex, int depth) const {
    if (rowIndex == 0 || rowIndex > rows(Table::TypeDef) || depth > 32) {
        return {};
    }
    const auto cached = typeDefNameCache_.find(rowIndex);
    if (cached != typeDefNameCache_.end()) {
        return cached->second;
    }

    const auto rowData = typeDef(rowIndex);
    const std::string name(sanitizeUtf8(string(rowData.name)));
    const std::string nameSpace(sanitizeUtf8(string(rowData.nameSpace)));

    std::string full;
    bool nested = false;
    for (std::uint32_t i = 1; i <= rows(Table::NestedClass); ++i) {
        const auto nestedRow = nestedClass(i);
        if (nestedRow.nested == rowIndex && nestedRow.enclosing != 0) {
            full = typeDefFullName(nestedRow.enclosing, depth + 1);
            if (!full.empty()) {
                full += '.';
            }
            full += name;
            nested = true;
            break;
        }
    }

    if (!nested) {
        full = nameSpace.empty() ? name : nameSpace + "." + name;
    }

    typeDefNameCache_[rowIndex] = full;
    return full;
}

std::string Metadata::typeRefFullName(std::uint32_t rowIndex, int depth) const {
    if (rowIndex == 0 || rowIndex > rows(Table::TypeRef) || depth > 32) {
        return {};
    }
    const auto cached = typeRefNameCache_.find(rowIndex);
    if (cached != typeRefNameCache_.end()) {
        return cached->second;
    }

    const auto rowData = typeRef(rowIndex);
    const std::string name(sanitizeUtf8(string(rowData.name)));
    const std::string nameSpace(sanitizeUtf8(string(rowData.nameSpace)));

    Table scopeTable = Table::Count;
    const std::uint32_t scopeRow =
        decodeCoded(CodedIndex::ResolutionScope, rowData.resolutionScope, scopeTable);

    std::string full;
    if (scopeTable == Table::TypeRef && scopeRow != 0) {
        full = typeRefFullName(scopeRow, depth + 1);
        if (!full.empty()) {
            full += '.';
        }
        full += name;
    } else {
        full = nameSpace.empty() ? name : nameSpace + "." + name;
    }

    typeRefNameCache_[rowIndex] = full;
    return full;
}

std::string Metadata::typeSpecName(std::uint32_t rowIndex, int depth) const {
    if (rowIndex == 0 || rowIndex > rows(Table::TypeSpec) || depth > 32) {
        return {};
    }
    const auto cached = typeSpecNameCache_.find(rowIndex);
    if (cached != typeSpecNameCache_.end()) {
        return cached->second;
    }

    const auto* data = row(Table::TypeSpec, rowIndex);
    if (!data) {
        return {};
    }
    RowCursor cursor(data, *this);
    const std::uint32_t blobIndex = cursor.blobIndex();
    const auto signature = blob(blobIndex);
    if (signature.empty()) {
        return {};
    }

    const std::uint8_t* ptr = signature.data();
    const std::uint8_t* end = signature.data() + signature.size();
    const auto sig = readType(ptr, end, depth + 1);
    const std::string name = typeSigName(sig);
    typeSpecNameCache_[rowIndex] = name;
    return name;
}

std::string Metadata::resolveTypeDefOrRef(std::uint32_t coded, int depth) const {
    Table table = Table::Count;
    const std::uint32_t rowIndex =
        decodeCoded(CodedIndex::TypeDefOrRef, coded, table);
    switch (table) {
        case Table::TypeDef:
            return typeDefFullName(rowIndex, depth + 1);
        case Table::TypeRef:
            return typeRefFullName(rowIndex, depth + 1);
        case Table::TypeSpec:
            return typeSpecName(rowIndex, depth + 1);
        default:
            return {};
    }
}

Metadata::TypeSig Metadata::readType(const std::uint8_t*& cursor,
                                     const std::uint8_t* end, int depth) const {
    TypeSig result;
    if (cursor >= end || depth > 32) {
        return result;
    }

    const std::uint8_t element = *cursor++;
    switch (element) {
        case 0x01: result.kind = TypeSig::Kind::Void; result.name = "System.Void"; break;
        case 0x02: result.kind = TypeSig::Kind::Boolean; result.name = "System.Boolean"; break;
        case 0x03: result.kind = TypeSig::Kind::Char; result.name = "System.Char"; break;
        case 0x04: result.kind = TypeSig::Kind::I1; result.name = "System.SByte"; break;
        case 0x05: result.kind = TypeSig::Kind::U1; result.name = "System.Byte"; break;
        case 0x06: result.kind = TypeSig::Kind::I2; result.name = "System.Int16"; break;
        case 0x07: result.kind = TypeSig::Kind::U2; result.name = "System.UInt16"; break;
        case 0x08: result.kind = TypeSig::Kind::I4; result.name = "System.Int32"; break;
        case 0x09: result.kind = TypeSig::Kind::U4; result.name = "System.UInt32"; break;
        case 0x0A: result.kind = TypeSig::Kind::I8; result.name = "System.Int64"; break;
        case 0x0B: result.kind = TypeSig::Kind::U8; result.name = "System.UInt64"; break;
        case 0x0C: result.kind = TypeSig::Kind::R4; result.name = "System.Single"; break;
        case 0x0D: result.kind = TypeSig::Kind::R8; result.name = "System.Double"; break;
        case 0x0E:
            result.kind = TypeSig::Kind::String;
            result.name = "System.String";
            result.isReference = true;
            break;
        case 0x0F: {
            const auto inner = readType(cursor, end, depth + 1);
            result.kind = TypeSig::Kind::Pointer;
            result.name = typeSigName(inner) + "*";
            break;
        }
        case 0x10: {
            const auto inner = readType(cursor, end, depth + 1);
            result.kind = TypeSig::Kind::ByRef;
            result.name = typeSigName(inner) + "&";
            break;
        }
        case 0x11:
        case 0x12: {
            const std::uint32_t coded = readCompressedUint(cursor, end);
            result.kind = element == 0x11 ? TypeSig::Kind::ValueType : TypeSig::Kind::Class;
            result.typeDefRef = coded;
            result.name = resolveTypeDefOrRef(coded, depth + 1);
            result.isValueType = element == 0x11;
            result.isReference = element == 0x12;
            break;
        }
        case 0x13:
        case 0x1E: {
            const std::uint32_t number = readCompressedUint(cursor, end);
            result.kind = TypeSig::Kind::GenericParam;
            result.name = (element == 0x13 ? "!" : "!!") + std::to_string(number);
            result.isReference = true;
            break;
        }
        case 0x14: {
            const auto inner = readType(cursor, end, depth + 1);
            const std::uint32_t rank = readCompressedUint(cursor, end);
            const std::uint32_t sizes = readCompressedUint(cursor, end);
            for (std::uint32_t i = 0; i < sizes; ++i) {
                (void)readCompressedUint(cursor, end);
            }
            const std::uint32_t loBounds = readCompressedUint(cursor, end);
            for (std::uint32_t i = 0; i < loBounds; ++i) {
                (void)readCompressedUint(cursor, end);
            }
            std::string suffix = "[";
            for (std::uint32_t i = 1; i < rank; ++i) {
                suffix += ',';
            }
            suffix += "]";
            result.kind = TypeSig::Kind::Array;
            result.name = typeSigName(inner) + suffix;
            result.isReference = true;
            break;
        }
        case 0x15: {
            const auto generic = readType(cursor, end, depth + 1);
            const std::uint32_t argCount = readCompressedUint(cursor, end);
            std::string args;
            for (std::uint32_t i = 0; i < argCount; ++i) {
                const auto arg = readType(cursor, end, depth + 1);
                if (i) {
                    args += ",";
                }
                args += typeSigName(arg);
            }
            result.kind = TypeSig::Kind::GenericInst;
            result.name = typeSigName(generic);
            if (!args.empty()) {
                result.name += "<" + args + ">";
            }
            result.isValueType = generic.isValueType;
            result.isReference = !generic.isValueType;
            break;
        }
        case 0x16:
            result.kind = TypeSig::Kind::TypedByRef;
            result.name = "System.TypedReference";
            result.isValueType = true;
            break;
        case 0x18:
            result.kind = TypeSig::Kind::GenericParam;
            result.name = "native int";
            break;
        case 0x19:
            result.kind = TypeSig::Kind::GenericParam;
            result.name = "native uint";
            break;
        case 0x1B:
            result.kind = TypeSig::Kind::FnPtr;
            result.name = "fnptr";
            break;
        case 0x1C:
            result.kind = TypeSig::Kind::Object;
            result.name = "System.Object";
            result.isReference = true;
            break;
        case 0x1D: {
            const auto inner = readType(cursor, end, depth + 1);
            result.kind = TypeSig::Kind::Array;
            result.name = typeSigName(inner) + "[]";
            result.isReference = true;
            break;
        }
        case 0x1F:
        case 0x20:
            // Custom modifiers wrap the real type.
            (void)readCompressedUint(cursor, end);
            return readType(cursor, end, depth + 1);
        case 0x45:
            // PINNED
            return readType(cursor, end, depth + 1);
        case 0x41:
            // SENTINEL
            return readType(cursor, end, depth + 1);
        default:
            result.kind = TypeSig::Kind::Unknown;
            result.name = "unknown";
            break;
    }

    return result;
}

std::string Metadata::typeSigName(const TypeSig& sig) const {
    if (!sig.name.empty()) {
        return sanitizeUtf8(sig.name);
    }
    return "unknown";
}

}  // namespace contra::metadata

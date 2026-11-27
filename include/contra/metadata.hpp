#pragma once

#include "contra/common.hpp"
#include "contra/pe.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace contra::metadata {

// ECMA-335 metadata table ids. Values match the on-disk ordering.
enum class Table : std::uint8_t {
    Module = 0,
    TypeRef = 1,
    TypeDef = 2,
    FieldPtr = 3,
    Field = 4,
    MethodPtr = 5,
    MethodDef = 6,
    ParamPtr = 7,
    Param = 8,
    InterfaceImpl = 9,
    MemberRef = 10,
    Constant = 11,
    CustomAttribute = 12,
    FieldMarshal = 13,
    DeclSecurity = 14,
    ClassLayout = 15,
    FieldLayout = 16,
    StandAloneSig = 17,
    EventMap = 18,
    EventPtr = 19,
    Event = 20,
    PropertyMap = 21,
    PropertyPtr = 22,
    Property = 23,
    MethodSemantics = 24,
    MethodImpl = 25,
    ModuleRef = 26,
    TypeSpec = 27,
    ImplMap = 28,
    FieldRVA = 29,
    ENCLog = 30,
    ENCMap = 31,
    Assembly = 32,
    AssemblyProcessor = 33,
    AssemblyOS = 34,
    AssemblyRef = 35,
    AssemblyRefProcessor = 36,
    AssemblyRefOS = 37,
    File = 38,
    ExportedType = 39,
    ManifestResource = 40,
    NestedClass = 41,
    GenericParam = 42,
    MethodSpec = 43,
    GenericParamConstraint = 44,
    Count = 45,
};

constexpr std::uint32_t tableId(Table table) { return static_cast<std::uint32_t>(table); }

enum class CodedIndex : std::uint8_t {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
};

struct TableLayout {
    std::uint32_t rows = 0;
    std::uint32_t rowSize = 0;
    std::uint32_t offset = 0;  // offset into the copied metadata blob
};

struct TypeDefRow {
    std::uint32_t flags = 0;
    std::uint32_t name = 0;
    std::uint32_t nameSpace = 0;
    std::uint32_t extends = 0;  // TypeDefOrRef coded index
    std::uint32_t fieldList = 0;
    std::uint32_t methodList = 0;
};

struct TypeRefRow {
    std::uint32_t resolutionScope = 0;
    std::uint32_t name = 0;
    std::uint32_t nameSpace = 0;
};

struct FieldRow {
    std::uint16_t flags = 0;
    std::uint32_t name = 0;
    std::uint32_t signature = 0;
};

struct MethodDefRow {
    std::uint32_t rva = 0;
    std::uint16_t implFlags = 0;
    std::uint16_t flags = 0;
    std::uint32_t name = 0;
    std::uint32_t signature = 0;
    std::uint32_t paramList = 0;
};

struct ParamRow {
    std::uint16_t flags = 0;
    std::uint16_t sequence = 0;
    std::uint32_t name = 0;
};

struct ClassLayoutRow {
    std::uint16_t packing = 0;
    std::uint32_t classSize = 0;
    std::uint32_t parent = 0;  // TypeDef row
};

struct FieldLayoutRow {
    std::uint32_t offset = 0;
    std::uint32_t field = 0;  // Field row
};

struct NestedClassRow {
    std::uint32_t nested = 0;   // TypeDef row
    std::uint32_t enclosing = 0;  // TypeDef row
};

struct ConstantRow {
    std::uint8_t type = 0;
    std::uint32_t parent = 0;  // HasConstant coded index
    std::uint32_t value = 0;   // blob
};

struct AssemblyRow {
    std::uint32_t hashAlg = 0;
    std::uint16_t major = 0;
    std::uint16_t minor = 0;
    std::uint16_t build = 0;
    std::uint16_t revision = 0;
    std::uint32_t flags = 0;
    std::uint32_t publicKey = 0;
    std::uint32_t name = 0;
    std::uint32_t culture = 0;
};

struct ModuleRow {
    std::uint16_t generation = 0;
    std::uint32_t name = 0;
};

class Metadata {
public:
    bool parse(const pe::ImageBuffer& image, std::string& error);

    std::uint32_t rows(Table table) const;
    const TableLayout& layout(Table table) const;
    const std::uint8_t* row(Table table, std::uint32_t oneBasedRow) const;

    std::string_view string(std::uint32_t index) const;
    std::span<const std::uint8_t> blob(std::uint32_t index) const;
    std::span<const std::uint8_t> userString(std::uint32_t index) const;

    TypeDefRow typeDef(std::uint32_t row) const;
    TypeRefRow typeRef(std::uint32_t row) const;
    FieldRow field(std::uint32_t row) const;
    MethodDefRow methodDef(std::uint32_t row) const;
    ParamRow param(std::uint32_t row) const;
    ClassLayoutRow classLayout(std::uint32_t row) const;
    FieldLayoutRow fieldLayout(std::uint32_t row) const;
    NestedClassRow nestedClass(std::uint32_t row) const;
    ConstantRow constant(std::uint32_t row) const;
    AssemblyRow assembly(std::uint32_t row) const;
    ModuleRow module(std::uint32_t row) const;

    std::uint32_t decodeCoded(CodedIndex kind, std::uint32_t value, Table& table) const;
    std::uint32_t encodeTypeDefOrRefTag(Table table) const;

    std::uint32_t metadataRootOffset() const { return 0; }
    const std::string& version() const { return version_; }
    std::uint32_t pointerSize() const { return pointerSize_; }
    void setPointerSize(std::uint32_t value) { pointerSize_ = value; }

    std::uint32_t readCompressedUint(const std::uint8_t*& cursor,
                                     const std::uint8_t* end) const;
    std::uint32_t heapIndexSize(std::uint8_t flag) const;

    // Signature type descriptors. Names are the CLR names (System.Int32 etc.)
    // because they are stable across decompilers and easier to diff.
    struct TypeSig {
        enum class Kind {
            Void,
            Boolean,
            Char,
            I1,
            U1,
            I2,
            U2,
            I4,
            U4,
            I8,
            U8,
            R4,
            R8,
            String,
            Object,
            Class,
            ValueType,
            Pointer,
            ByRef,
            Array,
            GenericInst,
            GenericParam,
            FnPtr,
            TypedByRef,
            Unknown,
        };

        Kind kind = Kind::Unknown;
        std::string name;
        std::uint32_t typeDefRef = 0;  // TypeDefOrRef coded value for Class/ValueType
        std::uint32_t genericArgCount = 0;
        bool isReference = false;
        bool isValueType = false;
    };

    TypeSig readType(const std::uint8_t*& cursor, const std::uint8_t* end,
                     int depth = 0) const;

    std::string resolveTypeDefOrRef(std::uint32_t coded, int depth = 0) const;
    std::string typeDefFullName(std::uint32_t row, int depth = 0) const;
    std::string typeRefFullName(std::uint32_t row, int depth = 0) const;
    std::string typeSpecName(std::uint32_t row, int depth = 0) const;

    std::string typeSigName(const TypeSig& sig) const;

private:
    bool parseTableStream(std::string& error);
    void computeTableLayouts();
    std::uint32_t simpleIndexSize(Table table) const;
    std::uint32_t codedIndexSize(CodedIndex kind) const;

    std::uint32_t readIndex(const std::uint8_t*& cursor, std::uint32_t size) const;
    std::uint32_t readCoded(const std::uint8_t*& cursor, CodedIndex kind) const;

    std::vector<std::uint8_t> metadata_;
    std::vector<std::uint8_t> strings_;
    std::vector<std::uint8_t> blobs_;
    std::vector<std::uint8_t> userStrings_;
    std::vector<std::uint8_t> guids_;

    std::array<TableLayout, tableId(Table::Count)> tables_{};
    std::array<std::uint32_t, tableId(Table::Count)> rowCounts_{};
    std::uint8_t heapSizes_ = 0;
    std::uint32_t tableStreamOffset_ = 0;
    std::uint32_t tableStreamSize_ = 0;
    std::string version_;
    std::uint32_t pointerSize_ = 4;

    mutable std::unordered_map<std::uint32_t, std::string> typeDefNameCache_;
    mutable std::unordered_map<std::uint32_t, std::string> typeRefNameCache_;
    mutable std::unordered_map<std::uint32_t, std::string> typeSpecNameCache_;
};

}  // namespace contra::metadata

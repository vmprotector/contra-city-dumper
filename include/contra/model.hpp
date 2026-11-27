#pragma once

#include "contra/common.hpp"

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace contra::model {

struct ModuleInfo {
    std::string name;
    std::string path;
    std::string kind;     // "native" or "managed"
    std::string runtime;  // "mono", "il2cpp", "native"
    std::uintptr_t base = 0;
    std::uint32_t size = 0;
    std::uint16_t machine = 0;
    bool is64 = false;
    bool selected = false;
    bool present = false;
    bool baseIsPreferred = false;
    bool fileLayout = false;
    std::string assemblyName;
    std::string assemblyVersion;
    std::uint32_t classCount = 0;
    std::vector<std::string> exports;
};

enum class FieldTypeKind : std::uint8_t {
    Unknown = 0,
    Primitive,
    Reference,
    ValueType,
    Pointer,
    GenericParameter,
};

struct FieldInfo {
    std::string name;
    std::string typeName;
    std::string typeClassName;
    std::string declaringType;
    FieldTypeKind typeKind = FieldTypeKind::Unknown;
    std::uint32_t token = 0;
    std::uint32_t flags = 0;
    std::uint32_t signature = 0;
    std::uint32_t constantToken = 0;
    std::string constant;
    std::int32_t offset = -1;
    std::int32_t staticOffset = -1;
    std::int32_t explicitOffset = -1;
    std::uint32_t size = 0;
    std::uint32_t align = 0;
    bool isStatic = false;
    bool isLiteral = false;
    bool isInitOnly = false;
    bool isPublic = false;
    bool isPrivate = false;
    bool hasReferences = false;
    bool offsetComputed = false;
};

struct StringUsage {
    std::string assembly;
    std::string className;
    std::string methodName;
    std::string methodSignature;
    std::uint32_t ilOffset = 0;
    std::uint32_t token = 0;
};

struct StringLiteral {
    std::string assembly;
    std::string value;
    std::uint32_t token = 0;       // 0x70xxxxxx
    std::uint32_t heapOffset = 0;
    std::vector<StringUsage> usages;
};

struct MethodInfo {
    std::string name;
    std::string signature;
    std::string returnType;
    std::vector<std::string> paramTypes;
    std::vector<std::string> paramNames;
    std::uint32_t token = 0;
    std::uint32_t flags = 0;
    std::uint32_t implFlags = 0;
    std::uint32_t rva = 0;
    std::uintptr_t address = 0;
    std::uint32_t ilSize = 0;
    std::uint32_t bodySize = 0;
    bool isStatic = false;
    bool isVirtual = false;
    bool isAbstract = false;
    bool isPInvoke = false;
    bool isConstructor = false;
    bool isSpecialName = false;
    bool isPublic = false;
    bool isPrivate = false;
    bool hasBody = false;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> stringRefs;
};

struct ClassInfo {
    std::string assembly;
    std::string name;
    std::string nameSpace;
    std::string fullName;
    std::string baseType;
    std::uint32_t token = 0;
    std::uint32_t flags = 0;
    std::uint32_t packing = 0;
    std::int32_t declaredSize = 0;
    std::int32_t instanceSize = -1;
    std::uint32_t valueSize = 0;
    std::uint32_t valueAlign = 1;
    bool isValueType = false;
    bool isEnum = false;
    bool isNested = false;
    bool isPublic = false;
    bool isAbstract = false;
    bool isSealed = false;
    bool isInterface = false;
    bool hasReferences = false;
    bool layoutComputed = false;
    bool layoutRunning = false;
    bool layoutExact = true;
    bool emit = false;
    std::string layoutKind;  // auto, sequential, explicit
    ClassInfo* parent = nullptr;
    std::vector<FieldInfo> fields;
    std::vector<MethodInfo> methods;
};

struct SdkModel {
    std::string toolVersion = "1.0.0";
    std::string generatedAt;
    std::string processName;
    std::string processPath;
    std::string buildVersion;
    std::string runtimeKind;
    std::string runtimeVersion;
    std::string mode = "live";
    std::uint32_t pid = 0;
    std::uint32_t pointerSize = 4;
    std::vector<ModuleInfo> modules;
    std::deque<ClassInfo> classes;
    std::vector<StringLiteral> strings;
    std::vector<std::string> warnings;

    std::unordered_map<std::string, ClassInfo*> classByFullName;
    std::unordered_map<std::string, ClassInfo*> classByAssemblyAndName;
    std::unordered_map<std::string, std::uint32_t> stringByHeapOffset;
    std::unordered_map<std::string, ModuleInfo*> moduleByName;

    ClassInfo* findClass(const std::string& assembly, const std::string& fullName) const;
};

std::string sanitizeIdentifier(std::string_view value, const std::string& fallback);
bool isCppKeyword(std::string_view value);

}  // namespace contra::model

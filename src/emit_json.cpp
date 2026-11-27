#include "contra/json.hpp"

#include <algorithm>
#include <fstream>
#include <unordered_map>
#include <unordered_set>

namespace contra::emit {

namespace {

struct ClassGroup {
    const model::ModuleInfo* module = nullptr;
    std::vector<const model::ClassInfo*> classes;
};

std::string offsetHex(std::int64_t value) {
    if (value < 0) {
        return "0xFFFFFFFF";
    }
    return toHex(static_cast<std::uint64_t>(value), 1);
}

std::string addressHex(std::uintptr_t value) {
    return toHex(static_cast<std::uint64_t>(value), 1);
}

void writeField(JsonWriter& json, const model::FieldInfo& field) {
    json.beginObject();
    json.key("name");
    json.string(field.name);
    json.key("type");
    json.string(field.typeName);
    json.key("token");
    json.string(toHex(field.token, 8));
    json.key("static");
    json.boolean(field.isStatic);
    json.key("literal");
    json.boolean(field.isLiteral);
    json.key("public");
    json.boolean(field.isPublic);
    json.key("private");
    json.boolean(field.isPrivate);
    json.key("initOnly");
    json.boolean(field.isInitOnly);
    json.key("size");
    json.number(static_cast<std::uint64_t>(field.size));

    if (field.isStatic) {
        json.key("offset");
        json.null();
    } else if (field.offset >= 0) {
        json.key("offset");
        json.number(static_cast<std::int64_t>(field.offset));
        json.key("offsetHex");
        json.string(offsetHex(field.offset));
    } else {
        json.key("offset");
        json.null();
    }

    if (field.staticOffset >= 0) {
        json.key("staticOffset");
        json.number(static_cast<std::int64_t>(field.staticOffset));
    }
    if (!field.constant.empty()) {
        json.key("constant");
        json.string(field.constant);
    }

    json.endObject();
}

void writeMethod(JsonWriter& json, const model::SdkModel& model,
                 const model::ClassInfo& klass, const model::MethodInfo& method,
                 const model::ModuleInfo* module) {
    json.beginObject();
    json.key("name");
    json.string(method.name);
    json.key("token");
    json.string(toHex(method.token, 8));
    json.key("signature");
    json.string(method.signature);
    json.key("returnType");
    json.string(method.returnType);
    json.key("static");
    json.boolean(method.isStatic);
    json.key("virtual");
    json.boolean(method.isVirtual);
    json.key("abstract");
    json.boolean(method.isAbstract);
    json.key("pinvoke");
    json.boolean(method.isPInvoke);
    json.key("constructor");
    json.boolean(method.isConstructor);
    json.key("public");
    json.boolean(method.isPublic);
    json.key("private");
    json.boolean(method.isPrivate);

    json.key("rva");
    json.number(static_cast<std::uint64_t>(method.rva));
    if (method.rva != 0) {
        json.key("rvaHex");
        json.string(toHex(method.rva, 1));
        json.key("rvaPath");
        json.string(module ? module->name + "+" + toHex(method.rva, 1)
                           : toHex(method.rva, 1));
        json.key("address");
        json.string(addressHex(method.address));
        json.key("addressKind");
        json.string(module && module->baseIsPreferred
                       ? "preferred"
                       : (module && module->fileLayout ? "file" : "image"));
    }
    json.key("bodySize");
    json.number(static_cast<std::uint64_t>(method.bodySize));
    json.key("ilSize");
    json.number(static_cast<std::uint64_t>(method.ilSize));

    json.key("params");
    json.beginArray();
    const std::size_t count = std::max(method.paramTypes.size(), method.paramNames.size());
    for (std::size_t i = 0; i < count; ++i) {
        json.beginObject();
        json.key("name");
        json.string(i < method.paramNames.size() ? method.paramNames[i]
                                                 : "arg" + std::to_string(i));
        json.key("type");
        json.string(i < method.paramTypes.size() ? method.paramTypes[i] : "unknown");
        json.endObject();
    }
    json.endArray();

    if (!method.stringRefs.empty()) {
        json.key("strings");
        json.beginArray();
        for (const auto& ref : method.stringRefs) {
            if (ref.first >= model.strings.size()) {
                continue;
            }
            const auto& literal = model.strings[ref.first];
            json.beginObject();
            json.key("value");
            json.string(literal.value);
            json.key("token");
            json.string(toHex(literal.token, 8));
            json.key("heapOffset");
            json.string(toHex(literal.heapOffset, 1));
            json.key("ilOffset");
            json.string(toHex(ref.second, 4));
            json.endObject();
        }
        json.endArray();
    }

    (void)klass;
    json.endObject();
}

void writeClass(JsonWriter& json, const model::SdkModel& model,
                const model::ClassInfo& klass, const model::ModuleInfo* module) {
    json.beginObject();
    json.key("name");
    json.string(klass.name);
    json.key("namespace");
    json.string(klass.nameSpace);
    json.key("fullName");
    json.string(klass.fullName);
    json.key("token");
    json.string(toHex(klass.token, 8));
    json.key("flags");
    json.string(toHex(klass.flags, 4));
    json.key("base");
    json.string(klass.baseType);
    json.key("layout");
    json.string(klass.layoutKind);
    json.key("packing");
    json.number(static_cast<std::uint64_t>(klass.packing));
    json.key("public");
    json.boolean(klass.isPublic);
    json.key("abstract");
    json.boolean(klass.isAbstract);
    json.key("sealed");
    json.boolean(klass.isSealed);
    json.key("interface");
    json.boolean(klass.isInterface);
    json.key("valueType");
    json.boolean(klass.isValueType);
    json.key("enum");
    json.boolean(klass.isEnum);
    json.key("nested");
    json.boolean(klass.isNested);
    json.key("size");
    if (klass.instanceSize >= 0) {
        json.number(static_cast<std::int64_t>(klass.instanceSize));
        json.key("sizeHex");
        json.string(offsetHex(klass.instanceSize));
    } else {
        json.null();
    }
    json.key("valueSize");
    json.number(static_cast<std::uint64_t>(klass.valueSize));
    json.key("valueAlign");
    json.number(static_cast<std::uint64_t>(klass.valueAlign));
    json.key("layoutExact");
    json.boolean(klass.layoutExact);

    json.key("fields");
    json.beginArray();
    for (const auto& field : klass.fields) {
        writeField(json, field);
    }
    json.endArray();

    json.key("methods");
    json.beginArray();
    for (const auto& method : klass.methods) {
        writeMethod(json, model, klass, method, module);
    }
    json.endArray();

    json.endObject();
}

}  // namespace

void writeJson(const model::SdkModel& model, const std::filesystem::path& path) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw AppError("cannot open JSON output: " + path.string(), 5);
    }

    std::unordered_map<std::string, std::vector<const model::ClassInfo*>> classesByAssembly;
    for (const auto& klass : model.classes) {
        if (klass.emit) {
            classesByAssembly[klass.assembly].push_back(&klass);
        }
    }
    for (auto& [assembly, classes] : classesByAssembly) {
        std::sort(classes.begin(), classes.end(), [](const auto* a, const auto* b) {
            return a->fullName < b->fullName;
        });
    }

    JsonWriter json(file);
    json.beginObject();
    json.key("schema");
    json.string("contracity-sdk/1");
    json.key("tool");
    json.beginObject();
    json.key("name");
    json.string("ContraCityDumper");
    json.key("version");
    json.string(model.toolVersion);
    json.key("generatedAt");
    json.string(model.generatedAt);
    json.endObject();

    json.key("target");
    json.beginObject();
    json.key("process");
    json.string(model.processName);
    json.key("pid");
    json.number(static_cast<std::uint64_t>(model.pid));
    json.key("build");
    json.string(model.buildVersion);
    json.key("mode");
    json.string(model.mode);
    json.key("pointerSize");
    json.number(static_cast<std::uint64_t>(model.pointerSize));
    json.endObject();

    json.key("runtime");
    json.beginObject();
    json.key("kind");
    json.string(model.runtimeKind);
    json.key("metadataVersion");
    json.string(model.runtimeVersion);
    json.endObject();

    json.key("modules");
    json.beginArray();
    for (const auto& module : model.modules) {
        json.beginObject();
        json.key("name");
        json.string(module.name);
        json.key("kind");
        json.string(module.kind);
        json.key("runtime");
        json.string(module.runtime);
        json.key("base");
        json.string(addressHex(module.base));
        json.key("size");
        json.number(static_cast<std::uint64_t>(module.size));
        json.key("included");
        json.boolean(module.selected || module.kind == "native");
        if (!module.assemblyName.empty()) {
            json.key("assembly");
            json.string(module.assemblyName);
            json.key("assemblyVersion");
            json.string(module.assemblyVersion);
        }
        if (module.baseIsPreferred) {
            json.key("baseKind");
            json.string("preferred");
        }
        if (module.kind == "managed") {
            json.key("layout");
            json.string(module.fileLayout ? "file" : "image");
        }
        if (!module.exports.empty()) {
            json.key("exports");
            json.beginArray();
            for (const auto& exportName : module.exports) {
                json.string(exportName);
            }
            json.endArray();
        }
        json.key("classCount");
        json.number(static_cast<std::uint64_t>(module.classCount));

        if (module.kind == "managed" && module.selected) {
            json.key("classes");
            json.beginArray();
            const auto group = classesByAssembly.find(module.assemblyName);
            if (group != classesByAssembly.end()) {
                for (const auto* klass : group->second) {
                    writeClass(json, model, *klass, &module);
                }
            }
            json.endArray();
        }
        json.endObject();
    }
    json.endArray();

    std::unordered_set<std::uint32_t> referencedStrings;
    std::unordered_set<std::string> emittedClassNames;
    for (const auto& klass : model.classes) {
        if (!klass.emit) {
            continue;
        }
        emittedClassNames.insert(klass.fullName);
        for (const auto& method : klass.methods) {
            for (const auto& ref : method.stringRefs) {
                referencedStrings.insert(ref.first);
            }
        }
    }

    if (!referencedStrings.empty()) {
        json.key("strings");
        json.beginArray();
        for (std::uint32_t index = 0; index < model.strings.size(); ++index) {
            if (referencedStrings.count(index) == 0) {
                continue;
            }
            const auto& literal = model.strings[index];
            json.beginObject();
            json.key("assembly");
            json.string(literal.assembly);
            json.key("value");
            json.string(literal.value);
            json.key("token");
            json.string(toHex(literal.token, 8));
            json.key("heapOffset");
            json.string(toHex(literal.heapOffset, 1));
            json.key("usages");
            json.beginArray();
            for (const auto& usage : literal.usages) {
                if (emittedClassNames.count(usage.className) == 0) {
                    continue;
                }
                json.beginObject();
                json.key("class");
                json.string(usage.className);
                json.key("method");
                json.string(usage.methodName);
                json.key("signature");
                json.string(usage.methodSignature);
                json.key("ilOffset");
                json.string(toHex(usage.ilOffset, 4));
                json.endObject();
            }
            json.endArray();
            json.endObject();
        }
        json.endArray();
    }

    std::uint64_t fieldCount = 0;
    std::uint64_t methodCount = 0;
    std::uint64_t classCount = 0;
    for (const auto& klass : model.classes) {
        if (!klass.emit) {
            continue;
        }
        ++classCount;
        fieldCount += klass.fields.size();
        methodCount += klass.methods.size();
    }

    json.key("stats");
    json.beginObject();
    json.key("modules");
    json.number(static_cast<std::uint64_t>(model.modules.size()));
    json.key("classes");
    json.number(classCount);
    json.key("fields");
    json.number(fieldCount);
    json.key("methods");
    json.number(methodCount);
    json.key("strings");
    json.number(static_cast<std::uint64_t>(referencedStrings.size()));
    json.endObject();

    if (!model.warnings.empty()) {
        json.key("warnings");
        json.beginArray();
        for (const auto& warning : model.warnings) {
            json.string(warning);
        }
        json.endArray();
    }

    json.endObject();
    file.flush();
    if (!file) {
        throw AppError("failed writing JSON output: " + path.string(), 5);
    }
}

}  // namespace contra::emit

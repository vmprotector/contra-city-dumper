#include "contra/layout.hpp"

#include <algorithm>
#include <string>
#include <unordered_set>
#include <vector>

namespace contra {

namespace {

struct Metric {
    std::uint32_t size = 4;
    std::uint32_t align = 4;
    bool hasReferences = false;
    bool exact = true;
};

Metric primitiveMetric(const std::string& name, std::uint32_t pointerSize) {
    Metric metric;
    if (name == "System.Boolean" || name == "System.SByte" || name == "System.Byte") {
        metric.size = 1;
        metric.align = 1;
    } else if (name == "System.Char" || name == "System.Int16" || name == "System.UInt16") {
        metric.size = 2;
        metric.align = 2;
    } else if (name == "System.Int32" || name == "System.UInt32" || name == "System.Single") {
        metric.size = 4;
        metric.align = 4;
    } else if (name == "System.Int64" || name == "System.UInt64" || name == "System.Double") {
        metric.size = 8;
        metric.align = 8;
    } else if (name == "System.IntPtr" || name == "System.UIntPtr" || name == "System.Void") {
        metric.size = pointerSize;
        metric.align = pointerSize;
    } else {
        metric.size = pointerSize;
        metric.align = pointerSize;
        metric.hasReferences = true;
        metric.exact = false;
    }
    return metric;
}

void layoutClass(model::SdkModel& model, model::ClassInfo& klass, bool gcAware);

Metric metricForField(model::SdkModel& model, model::ClassInfo& owner,
                      model::FieldInfo& field, bool gcAware) {
    Metric metric;
    const std::uint32_t pointerSize = model.pointerSize;

    switch (field.typeKind) {
        case model::FieldTypeKind::Primitive:
            return primitiveMetric(field.typeName, pointerSize);

        case model::FieldTypeKind::Reference:
            metric.size = pointerSize;
            metric.align = pointerSize;
            metric.hasReferences = true;
            return metric;

        case model::FieldTypeKind::Pointer:
        case model::FieldTypeKind::GenericParameter:
            metric.size = pointerSize;
            metric.align = pointerSize;
            metric.hasReferences = field.typeKind == model::FieldTypeKind::GenericParameter;
            return metric;

        case model::FieldTypeKind::ValueType: {
            auto* type = model.findClass(owner.assembly, field.typeClassName);
            if (!type) {
                type = model.findClass("", field.typeClassName);
            }
            if (!type) {
                metric.size = pointerSize;
                metric.align = pointerSize;
                metric.hasReferences = true;
                metric.exact = false;
                return metric;
            }
            if (type != &owner) {
                layoutClass(model, *type, gcAware);
            }
            if (type->instanceSize < 0) {
                metric.size = pointerSize;
                metric.align = pointerSize;
                metric.hasReferences = true;
                metric.exact = false;
                return metric;
            }
            metric.size = type->valueSize;
            metric.align = std::max<std::uint32_t>(1, type->valueAlign);
            metric.hasReferences = type->hasReferences;
            metric.exact = type->layoutExact;
            if (metric.size == 0) {
                metric.size = pointerSize;
                metric.exact = false;
            }
            return metric;
        }

        case model::FieldTypeKind::Unknown:
        default:
            metric.size = pointerSize;
            metric.align = pointerSize;
            metric.hasReferences = true;
            metric.exact = false;
            return metric;
    }
}

void layoutClass(model::SdkModel& model, model::ClassInfo& klass, bool gcAware) {
    if (klass.layoutComputed) {
        return;
    }
    if (klass.layoutRunning) {
        klass.layoutExact = false;
        return;
    }
    klass.layoutRunning = true;

    if (klass.parent && klass.parent != &klass) {
        layoutClass(model, *klass.parent, gcAware);
    }

    std::vector<Metric> metrics(klass.fields.size());
    bool hasReferences = false;

    // Resolve value-type sizes first. A field type may live in another image
    // (UnityEngine.Vector3, System.DateTime, ...), so layout is recursive.
    for (std::size_t i = 0; i < klass.fields.size(); ++i) {
        auto& field = klass.fields[i];
        if (field.isStatic || field.isLiteral) {
            continue;
        }
        metrics[i] = metricForField(model, klass, field, gcAware);
        field.size = metrics[i].size;
        field.align = metrics[i].align;
        field.hasReferences = metrics[i].hasReferences;
        hasReferences = hasReferences || metrics[i].hasReferences;
        if (!metrics[i].exact) {
            klass.layoutExact = false;
        }
    }
    klass.hasReferences = hasReferences;

    // Static fields live in the vtable data block and start at offset zero.
    std::uint32_t staticCursor = 0;
    for (auto& field : klass.fields) {
        if (!field.isStatic || field.isLiteral) {
            continue;
        }
        const Metric metric = metricForField(model, klass, field, gcAware);
        field.size = metric.size;
        field.align = metric.align;
        field.hasReferences = metric.hasReferences;
        if (!metric.exact) {
            klass.layoutExact = false;
        }
        const std::uint32_t align = std::max<std::uint32_t>(1, metric.align);
        staticCursor = alignUp(staticCursor, align);
        field.staticOffset = static_cast<std::int32_t>(staticCursor);
        staticCursor += metric.size;
    }

    if (klass.isEnum) {
        for (auto& field : klass.fields) {
            if (field.name == "value__" && !field.isStatic) {
                const Metric metric = metricForField(model, klass, field, gcAware);
                klass.valueSize = metric.size;
                klass.valueAlign = std::max<std::uint32_t>(1, metric.align);
                field.offset = 8;
                field.offsetComputed = true;
                break;
            }
        }
        if (klass.valueSize == 0) {
            klass.valueSize = 4;
            klass.valueAlign = 4;
        }
        klass.instanceSize = static_cast<std::int32_t>(
            alignUp<std::uint32_t>(8 + klass.valueSize, klass.valueAlign));
        klass.layoutComputed = true;
        klass.layoutRunning = false;
        return;
    }

    const auto packing = [&](std::uint32_t align) {
        if (klass.packing) {
            align = std::min<std::uint32_t>(klass.packing, align);
        }
        return std::max<std::uint32_t>(1, align);
    };

    if (klass.isValueType) {
        std::uint32_t real = 8;
        std::uint32_t minAlign = 1;
        const std::uint32_t minimum = 8 + static_cast<std::uint32_t>(
                                                std::max<std::int32_t>(0, klass.declaredSize));

        // Value types use declaration order (Mono disables GC-aware layout for
        // value types), with the MonoObject header still present in field offsets.
        for (std::size_t i = 0; i < klass.fields.size(); ++i) {
            auto& field = klass.fields[i];
            if (field.isStatic || field.isLiteral) {
                continue;
            }
            std::uint32_t align = packing(metrics[i].align);
            if (metrics[i].hasReferences) {
                align = std::max<std::uint32_t>(align, model.pointerSize);
            }
            minAlign = std::max(minAlign, align);
            real = alignUp(real, align);
            field.offset = static_cast<std::int32_t>(real);
            field.offsetComputed = true;
            real += metrics[i].size;
        }

        std::uint32_t instanceSize = alignUp(std::max(real, minimum), minAlign);
        klass.instanceSize = static_cast<std::int32_t>(instanceSize);
        klass.valueSize = instanceSize >= 8 ? instanceSize - 8 : 0;
        klass.valueAlign = minAlign;
        klass.layoutComputed = true;
        klass.layoutRunning = false;
        return;
    }

    // Reference types keep the parent's instance size. UnityEngine.Object and
    // friends are parsed from UnityEngine.dll, so the chain is normally exact.
    std::uint32_t base = 8;
    std::uint32_t minAlign = 1;
    if (klass.parent && klass.parent->instanceSize >= 0) {
        base = static_cast<std::uint32_t>(klass.parent->instanceSize);
        minAlign = std::max<std::uint32_t>(1, klass.parent->valueAlign);
    } else if (!klass.baseType.empty() && klass.baseType != "System.Object") {
        base = 0x0C;
        klass.layoutExact = false;
        if (klass.emit && model.warnings.size() < 32) {
            model.warnings.push_back("layout: unresolved base " + klass.baseType +
                                     " for " + klass.fullName + "; assuming 0x0C");
        }
    }

    const std::uint32_t minimum = base + static_cast<std::uint32_t>(
                                             std::max<std::int32_t>(0, klass.declaredSize));

    if (klass.layoutKind == "explicit") {
        std::uint32_t real = base;
        for (std::size_t i = 0; i < klass.fields.size(); ++i) {
            auto& field = klass.fields[i];
            if (field.isStatic || field.isLiteral) {
                continue;
            }
            const std::uint32_t align = packing(metrics[i].align);
            minAlign = std::max(minAlign, align);
            if (field.explicitOffset >= 0) {
                field.offset = 8 + field.explicitOffset;
            } else {
                real = alignUp(real, align);
                field.offset = static_cast<std::int32_t>(real);
            }
            field.offsetComputed = true;
            real = std::max(real, static_cast<std::uint32_t>(field.offset) + metrics[i].size);
        }
        klass.instanceSize = static_cast<std::int32_t>(
            alignUp(std::max(real, minimum), minAlign));
    } else {
        std::uint32_t real = base;
        const int passes = (gcAware && klass.layoutKind == "auto") ? 2 : 1;
        for (int pass = 0; pass < passes; ++pass) {
            for (std::size_t i = 0; i < klass.fields.size(); ++i) {
                auto& field = klass.fields[i];
                if (field.isStatic || field.isLiteral) {
                    continue;
                }
                if (passes == 2) {
                    if (pass == 0 && !metrics[i].hasReferences) {
                        continue;
                    }
                    if (pass == 1 && metrics[i].hasReferences) {
                        continue;
                    }
                }

                std::uint32_t align = packing(metrics[i].align);
                if (metrics[i].hasReferences) {
                    align = std::max<std::uint32_t>(align, model.pointerSize);
                }
                minAlign = std::max(minAlign, align);
                real = alignUp(real, align);
                field.offset = static_cast<std::int32_t>(real);
                field.offsetComputed = true;
                real += metrics[i].size;
            }
        }
        klass.instanceSize = static_cast<std::int32_t>(
            alignUp(std::max(real, minimum), minAlign));
    }

    klass.valueSize = model.pointerSize;
    klass.valueAlign = minAlign;
    klass.layoutComputed = true;
    klass.layoutRunning = false;
}

}  // namespace

void computeLayouts(model::SdkModel& model, const LayoutOptions& options) {
    // Resolve parent links first. Exact assembly match is preferred so a type
    // name that exists in both mscorlib and UnityEngine does not cross-link.
    // Generic bases are resolved against their open definition (List`1, ...).
    for (auto& klass : model.classes) {
        if (klass.baseType.empty()) {
            continue;
        }
        klass.parent = model.findClass(klass.assembly, klass.baseType);
        if (!klass.parent) {
            const auto open = klass.baseType.find('<');
            if (open != std::string::npos) {
                klass.parent = model.findClass(klass.assembly,
                                               klass.baseType.substr(0, open));
            }
        }
    }

    if (!options.enabled) {
        for (auto& klass : model.classes) {
            klass.layoutComputed = true;
            klass.layoutExact = false;
        }
        return;
    }

    for (auto& klass : model.classes) {
        layoutClass(model, klass, options.gcAware);
    }
}

}  // namespace contra

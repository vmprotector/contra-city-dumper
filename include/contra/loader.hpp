#pragma once

#include "contra/metadata.hpp"
#include "contra/model.hpp"
#include "contra/pe.hpp"
#include "contra/process.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace contra {

struct LoadOptions {
    bool allAssemblies = false;
    bool noStrings = false;
    bool noLayout = false;
    bool gcAwareLayout = true;
    bool deepScan = false;
    bool verbose = false;
    std::size_t scanBudgetBytes = 1024ull * 1024ull * 1024ull;
    std::vector<std::string> includeSubstrings;
    std::vector<std::string> includeClasses;
};

class Loader {
public:
    model::SdkModel loadFromProcess(const Process& process, const LoadOptions& options);
    model::SdkModel loadFromDirectory(const std::filesystem::path& managedDirectory,
                                      const LoadOptions& options);

private:
    struct ManagedImage {
        pe::ImageBuffer image;
        metadata::Metadata metadata;
        model::ModuleInfo module;
        std::vector<model::ClassInfo*> classes;
        bool selected = false;
    };

    void buildClassSkeletons(ManagedImage& image, model::SdkModel& model,
                             const LoadOptions& options);
};

bool isGameAssemblyName(const std::string& assemblyName,
                        const LoadOptions& options);
std::string readBuildVersionNear(const std::filesystem::path& start);

}  // namespace contra

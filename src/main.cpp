#include "contra/json.hpp"
#include "contra/loader.hpp"
#include "contra/process.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

struct Options {
    std::wstring processName = L"ContraCity.exe";
    DWORD pid = 0;
    std::filesystem::path outputDirectory = "output";
    std::filesystem::path imageDirectory;
    std::vector<std::string> includes;
    std::vector<std::string> classes;
    std::size_t scanBudgetMb = 1024;
    bool allAssemblies = false;
    bool noStrings = false;
    bool noLayout = false;
    bool noGcLayout = false;
    bool deepScan = false;
    bool listOnly = false;
    bool jsonOnly = false;
    bool hppOnly = false;
    bool verbose = false;
    bool help = false;
};

void printUsage() {
    std::cout
        << "ContraCityDumper 1.0.0 - Contra City SDK / offset dumper\n"
        << "\n"
        << "Usage:\n"
        << "  ContraCityDumper.exe [options]\n"
        << "\n"
        << "Live process (default):\n"
        << "  --process <name>       Process image name (default: ContraCity.exe)\n"
        << "  --pid <pid>            Attach to an explicit process id\n"
        << "  --deep-scan            Scan whole readable regions for PE headers\n"
        << "  --scan-budget <mb>     Deep-scan budget in MiB (default: 1024)\n"
        << "\n"
        << "Offline assembly directory:\n"
        << "  --image-dir <dir>      Read <dir>/*.dll instead of attaching\n"
        << "\n"
        << "Output:\n"
        << "  --output <dir>         Output directory (default: ./output)\n"
        << "  --all                  Include framework assemblies, not only game ones\n"
        << "  --include <text>       Add an assembly-name substring to the game filter\n"
        << "  --class <text>         Emit only classes whose full name contains <text>\n"
        << "  --no-strings           Skip IL string-literal extraction\n"
        << "  --no-layout            Do not compute field offsets\n"
        << "  --no-gc-layout         Use one-pass declaration layout (debugging aid)\n"
        << "  --json-only            Write only the JSON file\n"
        << "  --hpp-only             Write only the C++ header\n"
        << "  --list                 Print the module table and exit\n"
        << "  --verbose              Print scan diagnostics\n"
        << "  --help                 Show this help\n"
        << "\n"
        << "The dumper needs read access to the game process. Run it elevated if\n"
        << "OpenProcess returns ACCESS_DENIED. Builds 1.0.187-1.0.192 ship Mono;\n"
        << "IL2CPP modules are listed but their metadata is not parsed.\n";
}

bool parseUnsigned(const std::wstring& text, std::size_t& value) {
    try {
        std::size_t consumed = 0;
        const unsigned long long parsed = std::stoull(text, &consumed, 0);
        if (consumed != text.size()) {
            return false;
        }
        value = static_cast<std::size_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

Options parseOptions(int argc, wchar_t** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        const auto requireValue = [&](const wchar_t* name) -> std::wstring {
            if (i + 1 >= argc) {
                throw contra::AppError(std::string("missing value for ") +
                                       contra::narrow(name));
            }
            return argv[++i];
        };

        if (arg == L"--help" || arg == L"-h") {
            options.help = true;
        } else if (arg == L"--process") {
            options.processName = requireValue(L"--process");
        } else if (arg == L"--pid") {
            std::size_t value = 0;
            if (!parseUnsigned(requireValue(L"--pid"), value) || value == 0 ||
                value > 0xFFFFFFFFull) {
                throw contra::AppError("invalid --pid value");
            }
            options.pid = static_cast<DWORD>(value);
        } else if (arg == L"--output") {
            options.outputDirectory = requireValue(L"--output");
        } else if (arg == L"--image-dir") {
            options.imageDirectory = requireValue(L"--image-dir");
        } else if (arg == L"--include") {
            options.includes.push_back(contra::narrow(requireValue(L"--include")));
        } else if (arg == L"--class") {
            options.classes.push_back(contra::narrow(requireValue(L"--class")));
        } else if (arg == L"--scan-budget") {
            std::size_t value = 0;
            if (!parseUnsigned(requireValue(L"--scan-budget"), value) || value == 0) {
                throw contra::AppError("invalid --scan-budget value");
            }
            options.scanBudgetMb = value;
        } else if (arg == L"--all") {
            options.allAssemblies = true;
        } else if (arg == L"--no-strings") {
            options.noStrings = true;
        } else if (arg == L"--no-layout") {
            options.noLayout = true;
        } else if (arg == L"--no-gc-layout") {
            options.noGcLayout = true;
        } else if (arg == L"--deep-scan") {
            options.deepScan = true;
        } else if (arg == L"--list") {
            options.listOnly = true;
        } else if (arg == L"--json-only") {
            options.jsonOnly = true;
        } else if (arg == L"--hpp-only") {
            options.hppOnly = true;
        } else if (arg == L"--verbose" || arg == L"-v") {
            options.verbose = true;
        } else {
            throw contra::AppError("unknown option: " + contra::narrow(arg));
        }
    }

    if (options.jsonOnly && options.hppOnly) {
        throw contra::AppError("--json-only and --hpp-only are mutually exclusive");
    }
    return options;
}

void printModuleTable(const contra::model::SdkModel& model) {
    std::cout << "\n"
              << "  BASE        SIZE        KIND     RUNTIME  NAME\n"
              << "  ----------  ----------  -------  -------  ------------------------------\n";
    for (const auto& module : model.modules) {
        const std::string base = module.base ? contra::toHex(module.base, 8) : "        ";
        const std::string size = module.size ? contra::toHex(module.size, 8) : "        ";
        std::cout << "  " << base << "  " << size << "  " << module.kind
                  << std::string(module.kind.size() < 7 ? 7 - module.kind.size() : 0, ' ')
                  << "  " << module.runtime
                  << std::string(module.runtime.size() < 7 ? 7 - module.runtime.size() : 0, ' ')
                  << "  " << module.name;
        if (!module.assemblyName.empty() && module.assemblyName != module.name) {
            std::cout << "  [" << module.assemblyName << "]";
        }
        if (!module.selected && module.kind == "managed") {
            std::cout << "  (context)";
        }
        std::cout << "\n";
    }
    std::cout << "\n";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    Options options;
    try {
        options = parseOptions(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "[-] " << error.what() << "\n";
        printUsage();
        return 1;
    }

    if (options.help) {
        printUsage();
        return 0;
    }

    contra::Logger::instance().setVerbose(options.verbose);

    contra::LoadOptions loadOptions;
    loadOptions.allAssemblies = options.allAssemblies;
    loadOptions.noStrings = options.noStrings;
    loadOptions.noLayout = options.noLayout;
    loadOptions.gcAwareLayout = !options.noGcLayout;
    loadOptions.deepScan = options.deepScan;
    loadOptions.verbose = options.verbose;
    loadOptions.includeSubstrings = options.includes;
    loadOptions.includeClasses = options.classes;
    loadOptions.scanBudgetBytes =
        options.scanBudgetMb * 1024ull * 1024ull;

    try {
        contra::Loader loader;
        contra::model::SdkModel model;

        if (!options.imageDirectory.empty()) {
            std::error_code ec;
            if (!std::filesystem::is_directory(options.imageDirectory, ec)) {
                throw contra::AppError("image directory does not exist: " +
                                       options.imageDirectory.string(), 2);
            }
            contra::logInfo("reading managed assemblies from " +
                            options.imageDirectory.string());
            model = loader.loadFromDirectory(options.imageDirectory, loadOptions);
        } else {
            std::optional<contra::ProcessInfo> info;
            if (options.pid != 0) {
                info = contra::Process::processById(options.pid);
                if (!info) {
                    throw contra::AppError("process id not found: " +
                                           std::to_string(options.pid), 2);
                }
            } else {
                info = contra::Process::findProcess(options.processName);
                if (!info) {
                    throw contra::AppError("process not running: " +
                                           contra::narrow(options.processName) +
                                           " (start the game or pass --pid)", 2);
                }
            }

            contra::Process process;
            if (!process.open(info->pid)) {
                const DWORD error = GetLastError();
                if (error == ERROR_ACCESS_DENIED) {
                    throw contra::AppError(
                        "OpenProcess ACCESS_DENIED for pid " + std::to_string(info->pid) +
                            "; run the dumper elevated", 3);
                }
                throw contra::AppError("OpenProcess failed for pid " +
                                           std::to_string(info->pid) + ": " +
                                           contra::win32Error(error),
                                       3);
            }

            contra::logInfo("attached to " + contra::narrow(info->name) + " pid=" +
                            std::to_string(info->pid));
            model = loader.loadFromProcess(process, loadOptions);
        }

        if (model.modules.empty()) {
            throw contra::AppError("no modules were resolved", 4);
        }

        if (options.listOnly) {
            printModuleTable(model);
            return 0;
        }

        std::error_code ec;
        std::filesystem::create_directories(options.outputDirectory, ec);
        if (ec) {
            throw contra::AppError("cannot create output directory: " +
                                       options.outputDirectory.string() + ": " +
                                       ec.message(),
                                   5);
        }

        std::uint32_t emittedClasses = 0;
        std::uint64_t emittedMethods = 0;
        std::uint64_t emittedFields = 0;
        for (const auto& klass : model.classes) {
            if (klass.emit) {
                ++emittedClasses;
                emittedMethods += klass.methods.size();
                emittedFields += klass.fields.size();
            }
        }

        const auto jsonPath = options.outputDirectory / "ContraCity_SDK.json";
        const auto hppPath = options.outputDirectory / "ContraCity_SDK.hpp";

        if (!options.hppOnly) {
            contra::emit::writeJson(model, jsonPath);
            contra::logInfo("wrote " + jsonPath.string());
        }
        if (!options.jsonOnly) {
            contra::emit::writeHpp(model, hppPath);
            contra::logInfo("wrote " + hppPath.string());
        }

        contra::logInfo("classes=" + std::to_string(emittedClasses) +
                        " fields=" + std::to_string(emittedFields) +
                        " methods=" + std::to_string(emittedMethods) +
                        " strings=" + std::to_string(model.strings.size()));
        if (!model.buildVersion.empty()) {
            contra::logInfo("detected build " + model.buildVersion);
        }
        for (const auto& warning : model.warnings) {
            contra::logWarn(warning);
        }

        if (emittedClasses == 0) {
            contra::logWarn("no game classes were emitted; check --include or --all");
            return 4;
        }
        return 0;
    } catch (const contra::AppError& error) {
        contra::logError(error.what());
        return error.exitCode();
    } catch (const std::exception& error) {
        contra::logError(std::string("unhandled error: ") + error.what());
        return 1;
    }
}

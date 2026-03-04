#include "analysis/fileanalysis/pe_analyzer.h"

#include <array>
#include <climits>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>

#include <pe-parse/parse.h>

namespace shieldtier {

namespace {

std::mutex g_pe_parse_mutex;

struct PeDeleter {
    void operator()(peparse::parsed_pe* pe) const {
        if (pe) peparse::DestructParsedPE(pe);
    }
};
using PePtr = std::unique_ptr<peparse::parsed_pe, PeDeleter>;

std::string format_timestamp(uint32_t timestamp) {
    std::time_t t = static_cast<std::time_t>(timestamp);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &t);
#else
    gmtime_r(&t, &utc);
#endif
    std::ostringstream oss;
    oss << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

struct SectionData {
    PeSection section;
    const uint8_t* raw_data;
    uint32_t raw_len;
};

}  // namespace

double PeAnalyzer::calculate_section_entropy(const uint8_t* data,
                                              size_t size) {
    if (size == 0) return 0.0;

    std::array<uint64_t, 256> freq{};
    for (size_t i = 0; i < size; ++i) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    double log2_val = std::log(2.0);
    for (auto count : freq) {
        if (count == 0) continue;
        double p = static_cast<double>(count) / static_cast<double>(size);
        entropy -= p * (std::log(p) / log2_val);
    }
    return entropy;
}

Result<PeInfo> PeAnalyzer::analyze(const FileBuffer& file) {
    if (file.size() < 2 || file.ptr()[0] != 'M' || file.ptr()[1] != 'Z') {
        return Error("Not a valid PE file: missing MZ signature");
    }

    if (file.size() > UINT32_MAX) {
        return Error("File too large for PE parsing (>4GB)");
    }

    PePtr pe;
    {
        std::lock_guard<std::mutex> lock(g_pe_parse_mutex);
        pe.reset(peparse::ParsePEFromPointer(
            const_cast<uint8_t*>(file.ptr()),  // pe-parse API requires non-const
            static_cast<uint32_t>(file.size())));

        if (!pe) {
            return Error("Failed to parse PE: " + peparse::GetPEErrString());
        }
    }

    PeInfo info{};

    const auto& nt = pe->peHeader.nt;
    bool is_64 = (nt.OptionalMagic == peparse::NT_OPTIONAL_64_MAGIC);
    info.is_64bit = is_64;
    info.is_dll =
        (nt.FileHeader.Characteristics & peparse::IMAGE_FILE_DLL) != 0;

    if (is_64) {
        info.entry_point = nt.OptionalHeader64.AddressOfEntryPoint;
        info.subsystem = nt.OptionalHeader64.Subsystem;
    } else {
        info.entry_point = nt.OptionalHeader.AddressOfEntryPoint;
        info.subsystem = nt.OptionalHeader.Subsystem;
    }

    info.compile_timestamp = format_timestamp(nt.FileHeader.TimeDateStamp);

    uint16_t dll_chars = is_64 ? nt.OptionalHeader64.DllCharacteristics
                               : nt.OptionalHeader.DllCharacteristics;

    info.security.aslr =
        (dll_chars & peparse::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    info.security.dep =
        (dll_chars & peparse::IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    info.security.cfg =
        (dll_chars & peparse::IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    info.security.seh =
        (dll_chars & peparse::IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;

    const auto& data_dirs =
        is_64 ? nt.OptionalHeader64.DataDirectory
              : nt.OptionalHeader.DataDirectory;
    info.security.authenticode =
        data_dirs[peparse::DIR_SECURITY].Size > 0;

    // Collect sections with their raw data pointers for entropy calculation
    std::vector<SectionData> section_data_vec;

    peparse::IterSec(
        pe.get(),
        [](void* cbd, const peparse::VA&, const std::string& name,
           const peparse::image_section_header& header,
           const peparse::bounded_buffer* data) -> int {
            auto* vec = static_cast<std::vector<SectionData>*>(cbd);
            SectionData sd;
            sd.section.name = name;
            sd.section.virtual_size = header.Misc.VirtualSize;
            sd.section.virtual_address = header.VirtualAddress;
            sd.section.raw_size = header.SizeOfRawData;
            sd.section.characteristics = header.Characteristics;
            sd.section.entropy = 0.0;
            sd.raw_data = (data && data->buf) ? data->buf : nullptr;
            sd.raw_len = (data && data->buf) ? data->bufLen : 0;
            vec->push_back(std::move(sd));
            return 0;
        },
        &section_data_vec);

    for (auto& sd : section_data_vec) {
        if (sd.raw_data && sd.raw_len > 0) {
            sd.section.entropy =
                calculate_section_entropy(sd.raw_data, sd.raw_len);
        }
        info.sections.push_back(std::move(sd.section));
    }

    // Collect imports
    std::vector<PeImport> import_vec;

    peparse::IterImpVAString(
        pe.get(),
        [](void* cbd, const peparse::VA&, const std::string& module,
           const std::string& function) -> int {
            auto* vec = static_cast<std::vector<PeImport>*>(cbd);
            vec->push_back({module, function});
            return 0;
        },
        &import_vec);

    info.imports = std::move(import_vec);
    info.suspicious_imports = check_suspicious_imports(info.imports);

    return info;
}

std::vector<std::string> PeAnalyzer::check_suspicious_imports(
    const std::vector<PeImport>& imports) {
    std::set<std::string> func_names;
    for (const auto& imp : imports) {
        func_names.insert(imp.function_name);
    }

    std::vector<std::string> suspicious;

    if (func_names.count("VirtualAllocEx") &&
        func_names.count("WriteProcessMemory") &&
        func_names.count("CreateRemoteThread")) {
        suspicious.push_back(
            "Process injection pattern: VirtualAllocEx + WriteProcessMemory + "
            "CreateRemoteThread");
    }

    if ((func_names.count("SetWindowsHookExA") ||
         func_names.count("SetWindowsHookExW")) &&
        func_names.count("GetAsyncKeyState")) {
        suspicious.push_back(
            "Keylogging pattern: SetWindowsHookEx + GetAsyncKeyState");
    }

    if (func_names.count("IsDebuggerPresent")) {
        suspicious.push_back("Anti-debug: IsDebuggerPresent");
    }
    if (func_names.count("CheckRemoteDebuggerPresent")) {
        suspicious.push_back("Anti-debug: CheckRemoteDebuggerPresent");
    }

    if (func_names.count("RegSetValueExA") ||
        func_names.count("RegSetValueExW")) {
        suspicious.push_back("Persistence: RegSetValueEx (registry write)");
    }

    if ((func_names.count("InternetOpenA") ||
         func_names.count("InternetOpenW")) &&
        (func_names.count("URLDownloadToFileA") ||
         func_names.count("URLDownloadToFileW"))) {
        suspicious.push_back(
            "Network download pattern: InternetOpen + URLDownloadToFile");
    }

    return suspicious;
}

std::vector<Finding> PeAnalyzer::generate_findings(const PeInfo& info) {
    std::vector<Finding> findings;

    for (const auto& section : info.sections) {
        if (section.entropy > 7.0) {
            findings.push_back({
                "High entropy section: " + section.name,
                "Section '" + section.name + "' has entropy " +
                    std::to_string(section.entropy) +
                    " (possible packing or encryption)",
                Severity::kMedium,
                AnalysisEngine::kFileAnalysis,
                {{"section_name", section.name},
                 {"entropy", section.entropy}},
            });
        }
    }

    if (!info.security.aslr) {
        findings.push_back({
            "ASLR not enabled",
            "Binary does not have ASLR (DYNAMIC_BASE) enabled",
            Severity::kLow,
            AnalysisEngine::kFileAnalysis,
            {{"feature", "aslr"}},
        });
    }

    if (!info.security.dep) {
        findings.push_back({
            "DEP not enabled",
            "Binary does not have DEP (NX_COMPAT) enabled",
            Severity::kLow,
            AnalysisEngine::kFileAnalysis,
            {{"feature", "dep"}},
        });
    }

    for (const auto& desc : info.suspicious_imports) {
        Severity sev = Severity::kMedium;
        if (desc.find("Process injection") != std::string::npos) {
            sev = Severity::kHigh;
        }
        findings.push_back({
            "Suspicious import pattern detected",
            desc,
            sev,
            AnalysisEngine::kFileAnalysis,
            {{"pattern", desc}},
        });
    }

    if (!info.compile_timestamp.empty()) {
        int year = 0;
        try {
            year = std::stoi(info.compile_timestamp.substr(0, 4));
        } catch (...) {
        }

        if (year > 0 && (year < 2000 || year > 2030)) {
            findings.push_back({
                "Suspicious compile timestamp",
                "Compile time " + info.compile_timestamp +
                    " is outside expected range (possible timestomping)",
                Severity::kMedium,
                AnalysisEngine::kFileAnalysis,
                {{"timestamp", info.compile_timestamp}},
            });
        }
    }

    return findings;
}

}  // namespace shieldtier

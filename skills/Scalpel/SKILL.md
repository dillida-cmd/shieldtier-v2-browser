---
name: Scalpel
description: Use when building file analysis engines — PE analyzer (pe-parse), PDF analyzer, Office/OLE macro extractor, archive handler (libarchive), and general file analysis (entropy, strings, magic bytes)
---

# S4 — Scalpel: File Analysis PE/PDF/Office/Archive/General

## Overview

Port V1's file analysis subsystem from TypeScript to C++. Each analyzer takes a `FileBuffer` and returns `AnalysisEngineResult`. Uses pe-parse for PE files, libarchive for archives, custom parsers for PDF/Office.

## Dependencies

- **Requires:** S0 (foundation) — pe-parse, libarchive via FetchContent, shared types
- **Blocks:** S10 (scoring engine consumes file analysis results)

## File Ownership

```
src/native/analysis/fileanalysis/
  manager.cpp/.h          (orchestrator — dispatches to correct analyzer)
  pe_analyzer.cpp/.h      (pe-parse: imports, sections, entropy, capabilities)
  pdf_analyzer.cpp/.h     (stream extraction, /JavaScript detection)
  office_analyzer.cpp/.h  (OLE compound doc, OOXML macro extraction)
  archive_analyzer.cpp/.h (libarchive: ZIP/RAR/7z recursive extraction)
  general_analyzer.cpp/.h (entropy, strings, magic bytes, file type detection)
```

## Exit Criteria

Feed PE/PDF/Office/ZIP buffer → structured `AnalysisEngineResult` JSON with findings. PE: imports, sections, entropy, suspicious capabilities. Archive: recursive extraction from memory. PDF: JavaScript/embedded content detection.

---

## Analysis Manager (Orchestrator)

```cpp
class FileAnalysisManager {
public:
    AnalysisEngineResult analyze(const FileBuffer& file) {
        auto start = std::chrono::steady_clock::now();
        AnalysisEngineResult result;
        result.engine = AnalysisEngine::kFileAnalysis;

        // Detect file type
        auto file_type = detect_type(file);

        // Run general analysis on everything
        auto general = general_analyzer_.analyze(file);
        result.findings.insert(result.findings.end(),
            general.begin(), general.end());

        // Dispatch to specific analyzer
        switch (file_type) {
            case FileType::kPE:
                merge(result, pe_analyzer_.analyze(file));
                break;
            case FileType::kPDF:
                merge(result, pdf_analyzer_.analyze(file));
                break;
            case FileType::kOfficeOLE:
            case FileType::kOfficeOOXML:
                merge(result, office_analyzer_.analyze(file));
                break;
            case FileType::kArchive:
                merge(result, archive_analyzer_.analyze(file));
                break;
            default:
                break;
        }

        auto end = std::chrono::steady_clock::now();
        result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
        result.success = true;
        return result;
    }
};
```

## PE Analyzer (pe-parse)

```cpp
#include <pe-parse/parse.h>

struct PEAnalysis {
    std::vector<Finding> findings;
    nlohmann::json metadata;
};

PEAnalysis analyze_pe(const FileBuffer& file) {
    PEAnalysis result;

    auto pe = peparse::ParsePEFromBuffer(file.data.data(), file.size());
    if (!pe) {
        result.findings.push_back({"Invalid PE", "Failed to parse PE structure",
                                    "info", "file_analysis", {}});
        return result;
    }

    // --- Sections ---
    nlohmann::json sections = nlohmann::json::array();
    peparse::IterSec(pe, [](void* ctx, const peparse::VA&,
                             const std::string& name,
                             const peparse::image_section_header& hdr,
                             const peparse::bounded_buffer* data) -> int {
        auto* secs = static_cast<nlohmann::json*>(ctx);
        double entropy = data ? calculate_entropy(data->buf, data->bufLen) : 0.0;
        secs->push_back({
            {"name", name},
            {"virtual_size", hdr.Misc.VirtualSize},
            {"raw_size", hdr.SizeOfRawData},
            {"entropy", entropy},
            {"characteristics", hdr.Characteristics}
        });

        // High entropy section = likely packed/encrypted
        if (entropy > 7.0 && data && data->bufLen > 1024) {
            // Flag added via context
        }
        return 0;
    }, &sections);
    result.metadata["sections"] = sections;

    // --- Imports ---
    nlohmann::json imports = nlohmann::json::array();
    peparse::IterImpVAString(pe, [](void* ctx, const peparse::VA&,
                                     const std::string& module,
                                     const std::string& func) -> int {
        auto* imps = static_cast<nlohmann::json*>(ctx);
        imps->push_back({{"module", module}, {"function", func}});
        return 0;
    }, &imports);
    result.metadata["imports"] = imports;

    // --- Suspicious import detection ---
    check_suspicious_imports(imports, result.findings);

    // --- Exports ---
    nlohmann::json exports = nlohmann::json::array();
    peparse::IterExpVA(pe, [](void* ctx, const peparse::VA&,
                               const std::string& module,
                               const std::string& func) -> int {
        auto* exps = static_cast<nlohmann::json*>(ctx);
        exps->push_back({{"module", module}, {"function", func}});
        return 0;
    }, &exports);
    result.metadata["exports"] = exports;

    // --- PE Header info ---
    auto& nt = pe->peHeader.nt;
    result.metadata["machine"] = nt.FileHeader.Machine;
    result.metadata["timestamp"] = nt.FileHeader.TimeDateStamp;
    result.metadata["subsystem"] = nt.OptionalHeader.Subsystem;
    result.metadata["entry_point"] = nt.OptionalHeader.AddressOfEntryPoint;
    result.metadata["characteristics"] = nt.FileHeader.Characteristics;
    result.metadata["dll_characteristics"] = nt.OptionalHeader.DllCharacteristics;

    // --- Security checks ---
    bool has_aslr = nt.OptionalHeader.DllCharacteristics & 0x0040;
    bool has_dep = nt.OptionalHeader.DllCharacteristics & 0x0100;
    bool has_cfg = nt.OptionalHeader.DllCharacteristics & 0x4000;

    if (!has_aslr) {
        result.findings.push_back({"No ASLR", "Binary lacks ASLR (DYNAMIC_BASE)",
                                    "medium", "file_analysis", {}});
    }
    if (!has_dep) {
        result.findings.push_back({"No DEP", "Binary lacks DEP (NX_COMPAT)",
                                    "medium", "file_analysis", {}});
    }

    peparse::DestructParsedPE(pe);
    return result;
}
```

### Suspicious Import Patterns

```cpp
void check_suspicious_imports(const nlohmann::json& imports,
                               std::vector<Finding>& findings) {
    // Process injection
    static const std::vector<std::string> injection_apis = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtWriteVirtualMemory", "NtCreateThreadEx", "QueueUserAPC",
        "SetWindowsHookExA", "SetWindowsHookExW"
    };

    // Credential theft
    static const std::vector<std::string> credential_apis = {
        "CredEnumerateA", "CredEnumerateW", "CryptUnprotectData",
        "LsaRetrievePrivateData"
    };

    // Persistence
    static const std::vector<std::string> persistence_apis = {
        "RegSetValueExA", "RegSetValueExW", "CreateServiceA",
        "CreateServiceW", "SetFileAttributesA"
    };

    // Check each category
    auto has_api = [&](const std::string& func) {
        for (auto& imp : imports) {
            if (imp["function"] == func) return true;
        }
        return false;
    };

    int injection_count = 0;
    for (auto& api : injection_apis) {
        if (has_api(api)) injection_count++;
    }
    if (injection_count >= 2) {
        findings.push_back({
            "Process Injection Capability",
            "Binary imports " + std::to_string(injection_count) + " process injection APIs",
            "high", "file_analysis",
            {{"apis_found", injection_count}, {"category", "injection"}}
        });
    }
    // Similar for credential_apis, persistence_apis...
}
```

## PDF Analyzer

```cpp
struct PDFAnalysis {
    bool has_javascript = false;
    bool has_embedded_file = false;
    bool has_openaction = false;
    bool has_launch = false;
    int stream_count = 0;
    std::vector<std::string> urls;
    std::vector<Finding> findings;
};

PDFAnalysis analyze_pdf(const FileBuffer& file) {
    PDFAnalysis result;
    std::string content(file.data.begin(), file.data.end());

    // Count streams
    size_t pos = 0;
    while ((pos = content.find("stream\r\n", pos)) != std::string::npos) {
        result.stream_count++;
        pos++;
    }

    // Check for JavaScript
    if (content.find("/JavaScript") != std::string::npos ||
        content.find("/JS ") != std::string::npos) {
        result.has_javascript = true;
        result.findings.push_back({
            "PDF Contains JavaScript",
            "JavaScript found in PDF — common malware delivery vector",
            "high", "file_analysis",
            {{"indicator", "/JavaScript"}}
        });
    }

    // Check for auto-execution
    if (content.find("/OpenAction") != std::string::npos) {
        result.has_openaction = true;
        result.findings.push_back({
            "PDF Auto-Execute",
            "PDF has /OpenAction — code runs when document opens",
            "high", "file_analysis", {}
        });
    }

    // Check for /Launch (execute external program)
    if (content.find("/Launch") != std::string::npos) {
        result.has_launch = true;
        result.findings.push_back({
            "PDF Launch Action",
            "PDF has /Launch — can execute external programs",
            "critical", "file_analysis", {}
        });
    }

    // Check for embedded files
    if (content.find("/EmbeddedFile") != std::string::npos) {
        result.has_embedded_file = true;
        result.findings.push_back({
            "PDF Embedded File",
            "PDF contains embedded file(s)",
            "medium", "file_analysis", {}
        });
    }

    // Extract URLs
    std::regex url_regex(R"(https?://[^\s\)\]\"'>]+)");
    auto begin = std::sregex_iterator(content.begin(), content.end(), url_regex);
    for (auto it = begin; it != std::sregex_iterator(); ++it) {
        result.urls.push_back(it->str());
    }

    return result;
}
```

## Office Analyzer (OLE/OOXML)

```cpp
// OLE Compound Document (DOC/XLS/PPT) — magic: D0 CF 11 E0
// Check for VBA macros in "Macros" or "_VBA_PROJECT_CUR" storage

struct OfficeAnalysis {
    bool has_macros = false;
    bool has_auto_exec = false;
    std::vector<std::string> macro_names;
    std::vector<std::string> suspicious_strings;
    std::vector<Finding> findings;
};

OfficeAnalysis analyze_office(const FileBuffer& file) {
    OfficeAnalysis result;

    if (is_ooxml(file)) {
        // OOXML (DOCX/XLSX/PPTX) — is a ZIP
        // Extract and check for vbaProject.bin
        analyze_ooxml(file, result);
    } else if (is_ole(file)) {
        // OLE (DOC/XLS/PPT) — compound binary format
        analyze_ole(file, result);
    }

    // Check for suspicious VBA patterns
    static const std::vector<std::pair<std::string, std::string>> suspicious = {
        {"AutoOpen", "Macro auto-executes when document opens"},
        {"Auto_Open", "Excel macro auto-executes"},
        {"Document_Open", "Word macro auto-executes"},
        {"Workbook_Open", "Excel workbook auto-executes"},
        {"Shell(", "VBA Shell command execution"},
        {"WScript.Shell", "VBA script execution"},
        {"PowerShell", "PowerShell invocation from macro"},
        {"CreateObject", "COM object instantiation"},
        {"CallByName", "Dynamic function invocation"},
        {"GetObject", "COM object binding"},
        {"Environ(", "Environment variable access"},
        {"URLDownloadToFile", "File download from URL"},
    };

    // Scan macro content for suspicious patterns
    // ...

    return result;
}

bool is_ole(const FileBuffer& file) {
    return file.size() >= 4 &&
        file.data[0] == 0xD0 && file.data[1] == 0xCF &&
        file.data[2] == 0x11 && file.data[3] == 0xE0;
}

bool is_ooxml(const FileBuffer& file) {
    // OOXML is ZIP — check PK header then look for [Content_Types].xml
    return file.size() >= 4 &&
        file.data[0] == 0x50 && file.data[1] == 0x4B &&
        file.data[2] == 0x03 && file.data[3] == 0x04;
}
```

## Archive Analyzer (libarchive)

```cpp
#include <archive.h>
#include <archive_entry.h>

struct ArchiveAnalysis {
    int total_files = 0;
    int executable_files = 0;
    bool has_nested_archive = false;
    std::vector<std::string> entries;
    std::vector<Finding> findings;
};

ArchiveAnalysis analyze_archive(const FileBuffer& file, int depth = 0) {
    ArchiveAnalysis result;

    if (depth > 5) {
        result.findings.push_back({
            "Deep Archive Nesting",
            "Archive nested " + std::to_string(depth) + " levels deep — possible zip bomb",
            "high", "file_analysis", {{"depth", depth}}
        });
        return result;
    }

    struct archive* a = archive_read_new();
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);

    int r = archive_read_open_memory(a, file.data.data(), file.size());
    if (r != ARCHIVE_OK) {
        archive_read_free(a);
        result.findings.push_back({"Invalid Archive", archive_error_string(a),
                                    "info", "file_analysis", {}});
        return result;
    }

    struct archive_entry* entry;
    size_t total_uncompressed = 0;

    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char* pathname = archive_entry_pathname(entry);
        int64_t size = archive_entry_size(entry);
        result.total_files++;
        result.entries.push_back(pathname);
        total_uncompressed += size;

        // Zip bomb detection: compression ratio > 100:1
        if (file.size() > 0 && total_uncompressed > file.size() * 100) {
            result.findings.push_back({
                "Zip Bomb Detected",
                "Compression ratio exceeds 100:1",
                "critical", "file_analysis",
                {{"compressed", file.size()}, {"uncompressed", total_uncompressed}}
            });
            break;
        }

        // Check for executables
        std::string name(pathname);
        auto ext = name.substr(name.find_last_of('.') + 1);
        static const std::set<std::string> exec_exts = {
            "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs",
            "js", "hta", "msi", "com", "pif"
        };
        if (exec_exts.count(ext)) {
            result.executable_files++;
        }

        // Read entry content for recursive analysis
        if (size > 0 && size < 100 * 1024 * 1024) { // 100MB limit
            std::vector<uint8_t> entry_data(size);
            la_ssize_t bytes_read = archive_read_data(a, entry_data.data(), size);
            if (bytes_read > 0) {
                // Recursive: check if entry is also an archive
                FileBuffer nested{std::move(entry_data), name, "", "", 0};
                if (is_archive_magic(nested)) {
                    result.has_nested_archive = true;
                    auto inner = analyze_archive(nested, depth + 1);
                    result.findings.insert(result.findings.end(),
                        inner.findings.begin(), inner.findings.end());
                }
            }
        }

        archive_read_data_skip(a);
    }

    if (result.executable_files > 0) {
        result.findings.push_back({
            "Archive Contains Executables",
            std::to_string(result.executable_files) + " executable file(s) in archive",
            "high", "file_analysis",
            {{"executable_count", result.executable_files}}
        });
    }

    archive_read_free(a);
    return result;
}
```

## General Analyzer

```cpp
// Shannon entropy calculation
double calculate_entropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    size_t counts[256] = {};
    for (size_t i = 0; i < size; i++) counts[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = static_cast<double>(counts[i]) / size;
        entropy -= p * std::log2(p);
    }
    return entropy;  // 0.0 = uniform, 8.0 = maximum entropy
}

// Magic bytes detection
enum class FileType {
    kPE,        // MZ header
    kPDF,       // %PDF
    kOfficeOLE, // D0 CF 11 E0
    kOfficeOOXML, // PK (ZIP with [Content_Types].xml)
    kArchive,   // PK, 1F 8B (gzip), 37 7A BC AF (7z), Rar!
    kELF,       // 7F ELF
    kMachO,     // CF FA ED FE / CE FA ED FE
    kUnknown
};

FileType detect_type(const FileBuffer& file) {
    if (file.size() < 4) return FileType::kUnknown;
    auto d = file.data.data();

    if (d[0] == 'M' && d[1] == 'Z') return FileType::kPE;
    if (d[0] == '%' && d[1] == 'P' && d[2] == 'D' && d[3] == 'F') return FileType::kPDF;
    if (d[0] == 0xD0 && d[1] == 0xCF && d[2] == 0x11 && d[3] == 0xE0) return FileType::kOfficeOLE;
    if (d[0] == 'P' && d[1] == 'K' && d[2] == 0x03 && d[3] == 0x04) {
        // Could be OOXML or plain ZIP — check for Content_Types.xml
        return is_ooxml(file) ? FileType::kOfficeOOXML : FileType::kArchive;
    }
    if (d[0] == 0x1F && d[1] == 0x8B) return FileType::kArchive; // gzip
    if (d[0] == 0x37 && d[1] == 0x7A && d[2] == 0xBC && d[3] == 0xAF) return FileType::kArchive; // 7z
    if (d[0] == 'R' && d[1] == 'a' && d[2] == 'r' && d[3] == '!') return FileType::kArchive;
    if (d[0] == 0x7F && d[1] == 'E' && d[2] == 'L' && d[3] == 'F') return FileType::kELF;

    return FileType::kUnknown;
}

// String extraction
std::vector<std::string> extract_strings(const uint8_t* data, size_t size,
                                          size_t min_length = 4) {
    std::vector<std::string> strings;
    std::string current;
    for (size_t i = 0; i < size; i++) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) {
            current += static_cast<char>(data[i]);
        } else {
            if (current.size() >= min_length) {
                strings.push_back(current);
            }
            current.clear();
        }
    }
    if (current.size() >= min_length) strings.push_back(current);
    return strings;
}
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Not limiting archive extraction depth | Recursive zip bombs — cap at depth 5 |
| Not checking compression ratio | Zip bombs with 1000:1 ratio — cap at 100:1 |
| Unbounded string extraction | Huge files produce millions of strings — limit output |
| pe-parse: not calling DestructParsedPE | Memory leak — always destruct after analysis |
| libarchive: not calling archive_read_free | Memory leak — always free archive handle |
| Reading entire archive entry into memory | Large entries OOM — skip entries > 100MB |
| Not handling corrupt/truncated files | Every parser must handle malformed input gracefully |
| OLE parsing on non-OLE OOXML | Check magic bytes first — DOCX is ZIP, not OLE |

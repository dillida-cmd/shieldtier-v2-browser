#include "analysis/fileanalysis/file_analyzer.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <regex>
#include <sstream>

#include "analysis/fileanalysis/pe_analyzer.h"
#include "analysis/fileanalysis/pdf_analyzer.h"
#include "analysis/fileanalysis/archive_analyzer.h"
#include "analysis/fileanalysis/office_analyzer.h"
#include "common/json.h"

#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif

namespace shieldtier {

namespace {

const std::regex kIpPattern(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");

}  // namespace

FileType FileAnalyzer::detect_type(const uint8_t* data, size_t size) {
    if (size < 2) return FileType::kUnknown;

    if (data[0] == 0x4D && data[1] == 0x5A) return FileType::kPE;

    if (size >= 4) {
        if (data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 &&
            data[3] == 0x46)
            return FileType::kPDF;

        if (data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 &&
            data[3] == 0x04) {
            // PK archives: check for Office XML (docx/xlsx/pptx) vs plain ZIP
            // Office XML files have "[Content_Types].xml" near the start
            if (size > 30) {
                std::string header(reinterpret_cast<const char*>(data),
                                   std::min(size, size_t(200)));
                if (header.find("[Content_Types].xml") != std::string::npos ||
                    header.find("word/") != std::string::npos ||
                    header.find("xl/") != std::string::npos ||
                    header.find("ppt/") != std::string::npos) {
                    return FileType::kOfficeXml;
                }
            }
            return FileType::kZIP;
        }

        if (data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 &&
            data[3] == 0xE0)
            return FileType::kOfficeDoc;

        if (data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C &&
            data[3] == 0x46)
            return FileType::kELF;

        // Mach-O: CF FA ED FE (64-bit LE), CE FA ED FE (32-bit LE),
        // FE ED FA CF (64-bit BE), FE ED FA CE (32-bit BE)
        if ((data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED &&
             data[3] == 0xFE) ||
            (data[0] == 0xCE && data[1] == 0xFA && data[2] == 0xED &&
             data[3] == 0xFE) ||
            (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA &&
             data[3] == 0xCF) ||
            (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA &&
             data[3] == 0xCE))
            return FileType::kMachO;
    }

    if (data[0] == '#' && data[1] == '!') return FileType::kScript;

    return FileType::kUnknown;
}

std::string FileAnalyzer::file_type_name(FileType type) {
    switch (type) {
        case FileType::kPE: return "PE";
        case FileType::kPDF: return "PDF";
        case FileType::kZIP: return "ZIP";
        case FileType::kOfficeDoc: return "Office (OLE)";
        case FileType::kOfficeXml: return "Office (OOXML)";
        case FileType::kELF: return "ELF";
        case FileType::kMachO: return "Mach-O";
        case FileType::kScript: return "Script";
        case FileType::kUnknown: return "Unknown";
    }
    return "Unknown";
}

double FileAnalyzer::calculate_entropy(const uint8_t* data, size_t size) {
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

std::vector<std::string> FileAnalyzer::extract_strings(const uint8_t* data,
                                                        size_t size,
                                                        size_t min_length,
                                                        size_t max_strings) {
    std::vector<std::string> strings;
    std::string current;

    // ASCII printable runs
    for (size_t i = 0; i < size && strings.size() < max_strings; ++i) {
        uint8_t b = data[i];
        if (b >= 0x20 && b <= 0x7E) {
            current += static_cast<char>(b);
        } else {
            if (current.size() >= min_length) {
                strings.push_back(current);
            }
            current.clear();
        }
    }
    if (current.size() >= min_length && strings.size() < max_strings) {
        strings.push_back(current);
    }

    // UTF-16LE strings (every other byte is null for ASCII range)
    current.clear();
    for (size_t i = 0; i + 1 < size && strings.size() < max_strings;
         i += 2) {
        uint8_t lo = data[i];
        uint8_t hi = data[i + 1];
        if (hi == 0 && lo >= 0x20 && lo <= 0x7E) {
            current += static_cast<char>(lo);
        } else {
            if (current.size() >= min_length) {
                strings.push_back(current);
            }
            current.clear();
        }
    }
    if (current.size() >= min_length && strings.size() < max_strings) {
        strings.push_back(current);
    }

    return strings;
}

std::string FileAnalyzer::compute_md5(const uint8_t* data, size_t size) {
    unsigned char digest[16]{};

#if defined(__APPLE__)
    CC_MD5(data, static_cast<CC_LONG>(size), digest);
#elif defined(_WIN32)
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, nullptr, 0);
    if (hAlg) {
        BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
        if (hHash) {
            BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0);
            BCryptFinishHash(hHash, digest, 16, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::string(32, '0');
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, data, size);
    unsigned int md_len = 0;
    EVP_DigestFinal_ex(ctx, digest, &md_len);
    EVP_MD_CTX_free(ctx);
#endif

    std::ostringstream oss;
    for (int i = 0; i < 16; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(digest[i]);
    }
    return oss.str();
}

std::string FileAnalyzer::compute_sha1(const uint8_t* data, size_t size) {
    unsigned char digest[20]{};

#if defined(__APPLE__)
    CC_SHA1(data, static_cast<CC_LONG>(size), digest);
#elif defined(_WIN32)
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, 0);
    if (hAlg) {
        BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
        if (hHash) {
            BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0);
            BCryptFinishHash(hHash, digest, 20, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::string(40, '0');
    EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
    EVP_DigestUpdate(ctx, data, size);
    unsigned int md_len = 0;
    EVP_DigestFinal_ex(ctx, digest, &md_len);
    EVP_MD_CTX_free(ctx);
#endif

    std::ostringstream oss;
    for (int i = 0; i < 20; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(digest[i]);
    }
    return oss.str();
}

Result<AnalysisEngineResult> FileAnalyzer::analyze(const FileBuffer& file) {
    auto start = std::chrono::steady_clock::now();

    FileInfo info{};
    info.type = detect_type(file.ptr(), file.size());
    info.type_name = file_type_name(info.type);
    info.size = file.size();
    info.entropy = calculate_entropy(file.ptr(), file.size());
    info.sha256 = file.sha256;
    info.md5 = compute_md5(file.ptr(), file.size());
    info.extracted_strings = extract_strings(file.ptr(), file.size());

    info.printable_string_count = info.extracted_strings.size();
    info.url_count = 0;
    info.ip_count = 0;

    for (const auto& s : info.extracted_strings) {
        if (s.find("http://") != std::string::npos ||
            s.find("https://") != std::string::npos) {
            info.url_count++;
        }
        if (std::regex_search(s, kIpPattern)) {
            info.ip_count++;
        }
    }

    AnalysisEngineResult result;
    result.engine = AnalysisEngine::kFileAnalysis;
    result.success = true;

    result.findings = generate_findings(info);

    // If PE, run PE-specific analysis
    if (info.type == FileType::kPE) {
        PeAnalyzer pe_analyzer;
        auto pe_result = pe_analyzer.analyze(file);
        if (pe_result.ok()) {
            auto pe_findings = pe_analyzer.generate_findings(pe_result.value());
            result.findings.insert(result.findings.end(),
                                   pe_findings.begin(), pe_findings.end());

            const auto& pe_info = pe_result.value();
            result.raw_output["pe"] = {
                {"is_64bit", pe_info.is_64bit},
                {"is_dll", pe_info.is_dll},
                {"entry_point", pe_info.entry_point},
                {"subsystem", pe_info.subsystem},
                {"compile_timestamp", pe_info.compile_timestamp},
                {"section_count", pe_info.sections.size()},
                {"import_count", pe_info.imports.size()},
                {"security",
                 {{"aslr", pe_info.security.aslr},
                  {"dep", pe_info.security.dep},
                  {"cfg", pe_info.security.cfg},
                  {"seh", pe_info.security.seh},
                  {"authenticode", pe_info.security.authenticode}}},
                {"suspicious_imports", pe_info.suspicious_imports},
            };
        } else {
            result.raw_output["pe_error"] = pe_result.error().message;
        }
    }

    // If PDF, run PDF-specific analysis
    if (info.type == FileType::kPDF) {
        PdfAnalyzer pdf_analyzer;
        auto pdf_result = pdf_analyzer.analyze(file);
        if (pdf_result.ok()) {
            auto& pdf_res = pdf_result.value();
            result.findings.insert(result.findings.end(),
                                   pdf_res.findings.begin(),
                                   pdf_res.findings.end());
            if (pdf_res.raw_output.contains("pdf")) {
                result.raw_output["pdf"] = pdf_res.raw_output["pdf"];
            }
        } else {
            result.raw_output["pdf_error"] = pdf_result.error().message;
        }
    }

    // If ZIP, run archive-specific analysis
    if (info.type == FileType::kZIP) {
        ArchiveAnalyzer archive_analyzer;
        auto archive_result = archive_analyzer.analyze(file);
        if (archive_result.ok()) {
            auto& arc_res = archive_result.value();
            result.findings.insert(result.findings.end(),
                                   arc_res.findings.begin(),
                                   arc_res.findings.end());
            if (arc_res.raw_output.contains("archive")) {
                result.raw_output["archive"] = arc_res.raw_output["archive"];
            }
        } else {
            result.raw_output["archive_error"] = archive_result.error().message;
        }
    }

    // If Office document (OLE2 or OOXML), run Office-specific analysis
    if (info.type == FileType::kOfficeDoc || info.type == FileType::kOfficeXml) {
        OfficeAnalyzer office_analyzer;
        auto office_result = office_analyzer.analyze(file);
        if (office_result.ok()) {
            auto& off_res = office_result.value();
            result.findings.insert(result.findings.end(),
                                   off_res.findings.begin(),
                                   off_res.findings.end());
            if (off_res.raw_output.contains("office")) {
                result.raw_output["office"] = off_res.raw_output["office"];
            }
        } else {
            result.raw_output["office_error"] = office_result.error().message;
        }
    }

    result.raw_output["file_type"] = info.type_name;
    result.raw_output["size"] = info.size;
    result.raw_output["entropy"] = info.entropy;
    result.raw_output["sha256"] = info.sha256;
    result.raw_output["md5"] = info.md5;
    result.raw_output["string_count"] = info.printable_string_count;
    result.raw_output["url_count"] = info.url_count;
    result.raw_output["ip_count"] = info.ip_count;

    auto end = std::chrono::steady_clock::now();
    result.duration_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    return result;
}

std::vector<Finding> FileAnalyzer::generate_findings(const FileInfo& info) {
    std::vector<Finding> findings;

    if (info.entropy > 7.2) {
        findings.push_back({
            "High file entropy",
            "Overall file entropy is " + std::to_string(info.entropy) +
                " (possible packing, encryption, or compression)",
            Severity::kMedium,
            AnalysisEngine::kFileAnalysis,
            {{"entropy", info.entropy}},
        });
    }

    if (info.url_count > 0) {
        json url_list = json::array();
        for (const auto& s : info.extracted_strings) {
            if (s.find("http://") != std::string::npos ||
                s.find("https://") != std::string::npos) {
                url_list.push_back(s);
            }
        }
        findings.push_back({
            "URLs found in file",
            std::to_string(info.url_count) +
                " URL(s) extracted from strings",
            Severity::kInfo,
            AnalysisEngine::kFileAnalysis,
            {{"count", info.url_count}, {"urls", url_list}},
        });
    }

    if (info.ip_count > 0) {
        findings.push_back({
            "IP addresses found in file",
            std::to_string(info.ip_count) +
                " IP address pattern(s) found in strings",
            Severity::kLow,
            AnalysisEngine::kFileAnalysis,
            {{"count", info.ip_count}},
        });
    }

    // Low string density: very few printable strings relative to file size
    if (info.size > 1024 && info.printable_string_count < 5) {
        findings.push_back({
            "Low string density",
            "File has very few printable strings (" +
                std::to_string(info.printable_string_count) +
                ") relative to size, may be packed or encrypted",
            Severity::kLow,
            AnalysisEngine::kFileAnalysis,
            {{"string_count", info.printable_string_count},
             {"file_size", info.size}},
        });
    }

    return findings;
}

}  // namespace shieldtier

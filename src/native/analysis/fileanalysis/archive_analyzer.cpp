#include "analysis/fileanalysis/archive_analyzer.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>

#include "common/json.h"

namespace shieldtier {

namespace {

// ZIP End of Central Directory signature
constexpr uint32_t kEOCDSignature = 0x06054B50;
// ZIP Central Directory File Header signature
constexpr uint32_t kCentralDirSignature = 0x02014B50;
// ZIP Local File Header signature
constexpr uint32_t kLocalFileSignature = 0x04034B50;

// Maximum total uncompressed size before flagging as zip bomb (1 GB)
constexpr uint64_t kMaxUncompressedSize = 1ULL * 1024 * 1024 * 1024;

// Maximum compression ratio before flagging as zip bomb
constexpr double kMaxCompressionRatio = 100.0;

// Suspicious executable extensions within archives
const std::vector<std::string> kSuspiciousExtensions = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js",  ".hta", ".msi", ".com", ".pif",
    ".wsf", ".wsh", ".cpl",
};

// Archive extensions for nested archive detection
const std::vector<std::string> kArchiveExtensions = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".xz",  ".cab", ".iso", ".tgz",
};

uint32_t read_u32_le(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

uint16_t read_u16_le(const uint8_t* data) {
    return static_cast<uint16_t>(data[0]) |
           (static_cast<uint16_t>(data[1]) << 8);
}

std::string to_lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

}  // namespace

std::string ArchiveAnalyzer::get_extension(const std::string& filename) {
    auto pos = filename.rfind('.');
    if (pos == std::string::npos) return "";
    return to_lower(filename.substr(pos));
}

bool ArchiveAnalyzer::is_suspicious_extension(const std::string& filename) {
    std::string ext = get_extension(filename);
    if (ext.empty()) return false;
    for (const auto& sus : kSuspiciousExtensions) {
        if (ext == sus) return true;
    }
    return false;
}

bool ArchiveAnalyzer::is_archive_extension(const std::string& filename) {
    std::string ext = get_extension(filename);
    if (ext.empty()) return false;
    for (const auto& arc : kArchiveExtensions) {
        if (ext == arc) return true;
    }
    return false;
}

ArchiveInfo ArchiveAnalyzer::parse_zip(const uint8_t* data, size_t size) {
    ArchiveInfo info{};
    info.entry_count = 0;
    info.total_compressed_size = 0;
    info.total_uncompressed_size = 0;
    info.has_password = false;
    info.has_nested_archives = false;
    info.has_path_traversal = false;
    info.is_zip_bomb = false;

    if (size < 4) return info;

    // Strategy: Find End of Central Directory (EOCD) record, then parse
    // Central Directory entries for accurate file listing.

    // Find EOCD by scanning backwards from end of file.
    // EOCD is at least 22 bytes; comment can be up to 65535 bytes.
    size_t eocd_offset = 0;
    bool found_eocd = false;
    size_t search_start =
        (size >= 22 + 65535) ? size - 22 - 65535 : 0;

    for (size_t i = size - 22; i >= search_start && i < size; --i) {
        if (read_u32_le(data + i) == kEOCDSignature) {
            eocd_offset = i;
            found_eocd = true;
            break;
        }
        if (i == 0) break;
    }

    if (!found_eocd) {
        // Fallback: parse local file headers directly
        size_t offset = 0;
        while (offset + 30 < size) {
            if (read_u32_le(data + offset) != kLocalFileSignature) break;

            uint16_t flags = read_u16_le(data + offset + 6);
            uint32_t compressed_size = read_u32_le(data + offset + 18);
            uint32_t uncompressed_size = read_u32_le(data + offset + 22);
            uint16_t filename_len = read_u16_le(data + offset + 26);
            uint16_t extra_len = read_u16_le(data + offset + 28);

            if (offset + 30 + filename_len > size) break;

            std::string filename(
                reinterpret_cast<const char*>(data + offset + 30),
                filename_len);

            bool is_encrypted = (flags & 0x01) != 0;
            bool is_directory = (!filename.empty() && filename.back() == '/');

            ArchiveEntry entry;
            entry.filename = filename;
            entry.compressed_size = compressed_size;
            entry.uncompressed_size = uncompressed_size;
            entry.compression_method = read_u16_le(data + offset + 8);
            entry.is_encrypted = is_encrypted;
            entry.is_directory = is_directory;
            info.entries.push_back(entry);

            info.entry_count++;
            info.total_compressed_size += compressed_size;
            info.total_uncompressed_size += uncompressed_size;

            if (is_encrypted) info.has_password = true;

            if (!is_directory) {
                if (filename.find("../") != std::string::npos ||
                    filename.find("..\\") != std::string::npos) {
                    info.has_path_traversal = true;
                }
                if (is_suspicious_extension(filename)) {
                    std::string ext = get_extension(filename);
                    if (std::find(info.suspicious_extensions.begin(),
                                  info.suspicious_extensions.end(),
                                  ext) == info.suspicious_extensions.end()) {
                        info.suspicious_extensions.push_back(ext);
                    }
                }
                if (is_archive_extension(filename)) {
                    info.has_nested_archives = true;
                }
            }

            size_t data_start =
                offset + 30 + filename_len + extra_len;
            offset = data_start + compressed_size;
        }

        // Check zip bomb conditions
        if (info.total_compressed_size > 0) {
            double ratio =
                static_cast<double>(info.total_uncompressed_size) /
                static_cast<double>(info.total_compressed_size);
            if (ratio > kMaxCompressionRatio ||
                info.total_uncompressed_size > kMaxUncompressedSize) {
                info.is_zip_bomb = true;
            }
        }

        return info;
    }

    // Parse EOCD
    if (eocd_offset + 22 > size) return info;

    uint16_t total_entries = read_u16_le(data + eocd_offset + 10);
    uint32_t cd_size = read_u32_le(data + eocd_offset + 12);
    uint32_t cd_offset = read_u32_le(data + eocd_offset + 16);

    // Validate Central Directory offset and size
    if (cd_offset >= size || cd_offset + cd_size > size) {
        // Invalid CD, fall back to entry_count from EOCD
        info.entry_count = total_entries;
        return info;
    }

    // Parse Central Directory entries
    size_t offset = cd_offset;
    for (uint16_t i = 0; i < total_entries && offset + 46 <= size; ++i) {
        if (read_u32_le(data + offset) != kCentralDirSignature) break;

        uint16_t flags = read_u16_le(data + offset + 8);
        uint16_t compression_method = read_u16_le(data + offset + 10);
        uint32_t compressed_size = read_u32_le(data + offset + 20);
        uint32_t uncompressed_size = read_u32_le(data + offset + 24);
        uint16_t filename_len = read_u16_le(data + offset + 28);
        uint16_t extra_len = read_u16_le(data + offset + 30);
        uint16_t comment_len = read_u16_le(data + offset + 32);

        if (offset + 46 + filename_len > size) break;

        std::string filename(
            reinterpret_cast<const char*>(data + offset + 46), filename_len);

        bool is_encrypted = (flags & 0x01) != 0;
        bool is_directory = (!filename.empty() && filename.back() == '/');

        ArchiveEntry entry;
        entry.filename = filename;
        entry.compressed_size = compressed_size;
        entry.uncompressed_size = uncompressed_size;
        entry.compression_method = compression_method;
        entry.is_encrypted = is_encrypted;
        entry.is_directory = is_directory;
        info.entries.push_back(entry);

        info.entry_count++;
        info.total_compressed_size += compressed_size;
        info.total_uncompressed_size += uncompressed_size;

        if (is_encrypted) info.has_password = true;

        if (!is_directory) {
            // Check for path traversal
            if (filename.find("../") != std::string::npos ||
                filename.find("..\\") != std::string::npos) {
                info.has_path_traversal = true;
            }

            // Check for suspicious extensions
            if (is_suspicious_extension(filename)) {
                std::string ext = get_extension(filename);
                if (std::find(info.suspicious_extensions.begin(),
                              info.suspicious_extensions.end(),
                              ext) == info.suspicious_extensions.end()) {
                    info.suspicious_extensions.push_back(ext);
                }
            }

            // Check for nested archives
            if (is_archive_extension(filename)) {
                info.has_nested_archives = true;
            }
        }

        offset += 46 + filename_len + extra_len + comment_len;
    }

    // Check zip bomb conditions
    if (info.total_compressed_size > 0) {
        double ratio = static_cast<double>(info.total_uncompressed_size) /
                       static_cast<double>(info.total_compressed_size);
        if (ratio > kMaxCompressionRatio ||
            info.total_uncompressed_size > kMaxUncompressedSize) {
            info.is_zip_bomb = true;
        }
    }

    return info;
}

std::vector<Finding> ArchiveAnalyzer::generate_findings(
    const ArchiveInfo& info) {
    std::vector<Finding> findings;

    if (info.has_path_traversal) {
        findings.push_back({
            "Path traversal in archive",
            "Archive contains entries with '../' in filenames — may attempt "
            "to write files outside the extraction directory (Zip Slip)",
            Severity::kHigh,
            AnalysisEngine::kFileAnalysis,
            {{"has_path_traversal", true}},
        });
    }

    if (info.is_zip_bomb) {
        double ratio = 0.0;
        if (info.total_compressed_size > 0) {
            ratio = static_cast<double>(info.total_uncompressed_size) /
                    static_cast<double>(info.total_compressed_size);
        }
        findings.push_back({
            "Potential zip bomb detected",
            "Archive has suspicious compression ratio (" +
                std::to_string(static_cast<int>(ratio)) +
                ":1) or excessive uncompressed size — may be a zip bomb",
            Severity::kHigh,
            AnalysisEngine::kFileAnalysis,
            {{"compression_ratio", ratio},
             {"total_uncompressed_size", info.total_uncompressed_size}},
        });
    }

    if (info.has_password) {
        findings.push_back({
            "Password-protected archive",
            "Archive contains encrypted entries — password protection may "
            "be used to evade scanning",
            Severity::kMedium,
            AnalysisEngine::kFileAnalysis,
            {{"has_password", true}},
        });
    }

    if (!info.suspicious_extensions.empty()) {
        json ext_list = json::array();
        for (const auto& ext : info.suspicious_extensions) {
            ext_list.push_back(ext);
        }
        findings.push_back({
            "Suspicious file extensions in archive",
            "Archive contains files with executable or script extensions: " +
                [&]() {
                    std::string s;
                    for (size_t i = 0; i < info.suspicious_extensions.size();
                         ++i) {
                        if (i > 0) s += ", ";
                        s += info.suspicious_extensions[i];
                    }
                    return s;
                }(),
            Severity::kMedium,
            AnalysisEngine::kFileAnalysis,
            {{"suspicious_extensions", ext_list}},
        });
    }

    if (info.has_nested_archives) {
        findings.push_back({
            "Nested archive detected",
            "Archive contains other archive files — nested archives may be "
            "used for evasion or zip bomb attacks",
            Severity::kMedium,
            AnalysisEngine::kFileAnalysis,
            {{"has_nested_archives", true}},
        });
    }

    return findings;
}

Result<AnalysisEngineResult> ArchiveAnalyzer::analyze(const FileBuffer& file) {
    auto start = std::chrono::steady_clock::now();

    if (file.size() < 4 || file.ptr()[0] != 0x50 || file.ptr()[1] != 0x4B ||
        file.ptr()[2] != 0x03 || file.ptr()[3] != 0x04) {
        return Error("Not a valid ZIP archive: missing PK signature");
    }

    ArchiveInfo info = parse_zip(file.ptr(), file.size());

    AnalysisEngineResult result;
    result.engine = AnalysisEngine::kFileAnalysis;
    result.success = true;

    result.findings = generate_findings(info);

    json suspicious_ext_json = json::array();
    for (const auto& ext : info.suspicious_extensions) {
        suspicious_ext_json.push_back(ext);
    }

    result.raw_output["archive"] = {
        {"entry_count", info.entry_count},
        {"total_compressed_size", info.total_compressed_size},
        {"total_uncompressed_size", info.total_uncompressed_size},
        {"has_password", info.has_password},
        {"has_nested_archives", info.has_nested_archives},
        {"has_path_traversal", info.has_path_traversal},
        {"is_zip_bomb", info.is_zip_bomb},
        {"suspicious_extensions", suspicious_ext_json},
    };

    auto end = std::chrono::steady_clock::now();
    result.duration_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    return result;
}

}  // namespace shieldtier

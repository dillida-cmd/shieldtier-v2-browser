#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

struct ArchiveEntry {
    std::string filename;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t compression_method;
    bool is_encrypted;
    bool is_directory;
};

struct ArchiveInfo {
    size_t entry_count;
    uint64_t total_compressed_size;
    uint64_t total_uncompressed_size;
    bool has_password;
    bool has_nested_archives;
    bool has_path_traversal;
    bool is_zip_bomb;
    std::vector<std::string> suspicious_extensions;
    std::vector<ArchiveEntry> entries;
};

class ArchiveAnalyzer {
public:
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

private:
    ArchiveInfo parse_zip(const uint8_t* data, size_t size);
    std::vector<Finding> generate_findings(const ArchiveInfo& info);
    static bool is_suspicious_extension(const std::string& filename);
    static bool is_archive_extension(const std::string& filename);
    static std::string get_extension(const std::string& filename);
};

}  // namespace shieldtier

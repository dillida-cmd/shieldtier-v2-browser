#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

enum class FileType {
    kPE,
    kPDF,
    kZIP,
    kOfficeDoc,
    kOfficeXml,
    kELF,
    kMachO,
    kScript,
    kUnknown
};

struct FileInfo {
    FileType type;
    std::string type_name;
    size_t size;
    double entropy;
    std::string sha256;
    std::string md5;
    std::vector<std::string> extracted_strings;
    size_t printable_string_count;
    size_t url_count;
    size_t ip_count;
};

class FileAnalyzer {
public:
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);
    static FileType detect_type(const uint8_t* data, size_t size);
    static std::string file_type_name(FileType type);
    static double calculate_entropy(const uint8_t* data, size_t size);
    static std::vector<std::string> extract_strings(const uint8_t* data,
                                                     size_t size,
                                                     size_t min_length = 4,
                                                     size_t max_strings = 1000);
    static std::string compute_md5(const uint8_t* data, size_t size);
    static std::string compute_sha1(const uint8_t* data, size_t size);

private:
    std::vector<Finding> generate_findings(const FileInfo& info);
};

}  // namespace shieldtier

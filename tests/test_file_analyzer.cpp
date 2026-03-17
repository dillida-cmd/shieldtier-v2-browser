#include <gtest/gtest.h>
#include "analysis/fileanalysis/file_analyzer.h"

using namespace shieldtier;

TEST(FileAnalyzer, DetectPE) {
    // MZ header
    std::vector<uint8_t> pe_data = {'M', 'Z', 0x90, 0x00};
    pe_data.resize(256, 0);
    EXPECT_EQ(FileAnalyzer::detect_type(pe_data.data(), pe_data.size()), FileType::kPE);
}

TEST(FileAnalyzer, DetectPDF) {
    std::string pdf = "%PDF-1.4 some content";
    auto data = reinterpret_cast<const uint8_t*>(pdf.data());
    EXPECT_EQ(FileAnalyzer::detect_type(data, pdf.size()), FileType::kPDF);
}

TEST(FileAnalyzer, DetectZIP) {
    std::vector<uint8_t> zip_data = {0x50, 0x4B, 0x03, 0x04};
    zip_data.resize(64, 0);
    EXPECT_EQ(FileAnalyzer::detect_type(zip_data.data(), zip_data.size()), FileType::kZIP);
}

TEST(FileAnalyzer, DetectELF) {
    std::vector<uint8_t> elf_data = {0x7F, 'E', 'L', 'F'};
    elf_data.resize(64, 0);
    EXPECT_EQ(FileAnalyzer::detect_type(elf_data.data(), elf_data.size()), FileType::kELF);
}

TEST(FileAnalyzer, DetectMachO) {
    // 64-bit Mach-O magic
    std::vector<uint8_t> macho_data = {0xFE, 0xED, 0xFA, 0xCF};
    macho_data.resize(64, 0);
    EXPECT_EQ(FileAnalyzer::detect_type(macho_data.data(), macho_data.size()), FileType::kMachO);
}

TEST(FileAnalyzer, DetectUnknown) {
    std::vector<uint8_t> random_data = {0x01, 0x02, 0x03, 0x04};
    EXPECT_EQ(FileAnalyzer::detect_type(random_data.data(), random_data.size()), FileType::kUnknown);
}

TEST(FileAnalyzer, EntropyUniform) {
    // All same bytes = zero entropy
    std::vector<uint8_t> uniform(1024, 0xAA);
    double entropy = FileAnalyzer::calculate_entropy(uniform.data(), uniform.size());
    EXPECT_NEAR(entropy, 0.0, 0.01);
}

TEST(FileAnalyzer, EntropyRandom) {
    // All 256 byte values equally represented = max entropy ~8.0
    std::vector<uint8_t> random_data;
    random_data.reserve(256 * 100);
    for (int i = 0; i < 100; ++i) {
        for (int b = 0; b < 256; ++b) {
            random_data.push_back(static_cast<uint8_t>(b));
        }
    }
    double entropy = FileAnalyzer::calculate_entropy(random_data.data(), random_data.size());
    EXPECT_NEAR(entropy, 8.0, 0.01);
}

TEST(FileAnalyzer, ExtractStrings) {
    // Use explicit byte array to avoid null-termination issues in C++ string literals
    const uint8_t data[] = {
        'A', 'B', 0, 0, 0,
        'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', 0, 0, 0, 0,
        's', 'h', 0, 0, 0,
        'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'l', 'o', 'n', 'g', 'e', 'r', 0
    };
    auto strings = FileAnalyzer::extract_strings(data, sizeof(data), 4, 100);
    // Should find "Hello World" (11 chars) and "This is longer" (14 chars)
    EXPECT_GE(strings.size(), 1u);
}

TEST(FileAnalyzer, FileTypeName) {
    EXPECT_EQ(FileAnalyzer::file_type_name(FileType::kPE), "PE");
    EXPECT_EQ(FileAnalyzer::file_type_name(FileType::kPDF), "PDF");
    EXPECT_EQ(FileAnalyzer::file_type_name(FileType::kUnknown), "Unknown");
}

#pragma once

#include <string>
#include <vector>

#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

struct EmailHeader {
    std::string name;
    std::string value;
};

struct EmailAttachment {
    std::string filename;
    std::string content_type;
    std::vector<uint8_t> data;
    std::string sha256;
};

struct ParsedEmail {
    std::string subject;
    std::string from;
    std::vector<std::string> to;
    std::string date;
    std::string message_id;
    std::string body_text;
    std::string body_html;
    std::vector<EmailHeader> headers;
    std::vector<EmailAttachment> attachments;
    std::vector<std::string> urls_in_body;
};

class EmailAnalyzer {
public:
    EmailAnalyzer();

    Result<ParsedEmail> parse(const uint8_t* data, size_t size);
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

private:
    std::vector<Finding> analyze_headers(const ParsedEmail& email);
    std::vector<Finding> analyze_body(const ParsedEmail& email);
    std::vector<Finding> analyze_attachments(const ParsedEmail& email);
    std::vector<std::string> extract_urls(const std::string& text);

    void parse_mime_part(const std::string& part, const std::string& boundary,
                         ParsedEmail& result, int depth = 0);
};

}  // namespace shieldtier

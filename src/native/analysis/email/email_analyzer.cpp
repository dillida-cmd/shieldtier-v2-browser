#include "analysis/email/email_analyzer.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <regex>
#include <sstream>
#include <unordered_set>

namespace shieldtier {

namespace {

constexpr size_t kMaxEmailSize = 25 * 1024 * 1024;
constexpr size_t kMaxUrls = 500;
constexpr size_t kMaxAttachmentSize = 50 * 1024 * 1024;
constexpr size_t kMaxAttachmentCount = 100;

// Simple SHA-256 -- standalone implementation to avoid adding dependencies.
// Based on the FIPS 180-4 specification.
struct Sha256 {
    std::array<uint32_t, 8> h;
    std::array<uint8_t, 64> block;
    size_t block_len = 0;
    uint64_t total_len = 0;

    static constexpr std::array<uint32_t, 64> k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    static uint32_t rotr(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }

    Sha256() {
        h = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    }

    void process_block() {
        std::array<uint32_t, 64> w{};
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(block[i * 4]) << 24) |
                   (uint32_t(block[i * 4 + 1]) << 16) |
                   (uint32_t(block[i * 4 + 2]) << 8) |
                   uint32_t(block[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        auto [a, b, c, d, e, f, g, hh] = h;
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            hh = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void update(const uint8_t* data, size_t len) {
        total_len += len;
        for (size_t i = 0; i < len; ++i) {
            block[block_len++] = data[i];
            if (block_len == 64) {
                process_block();
                block_len = 0;
            }
        }
    }

    std::string finalize() {
        uint64_t bit_len = total_len * 8;
        block[block_len++] = 0x80;
        if (block_len > 56) {
            while (block_len < 64) block[block_len++] = 0;
            process_block();
            block_len = 0;
        }
        while (block_len < 56) block[block_len++] = 0;
        for (int i = 7; i >= 0; --i) {
            block[block_len++] = static_cast<uint8_t>(bit_len >> (i * 8));
        }
        process_block();

        char hex[65];
        for (int i = 0; i < 8; ++i) {
            std::snprintf(hex + i * 8, 9, "%08x", h[i]);
        }
        return std::string(hex, 64);
    }
};

std::string compute_sha256(const uint8_t* data, size_t size) {
    Sha256 ctx;
    ctx.update(data, size);
    return ctx.finalize();
}

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) ==
                                    std::tolower(static_cast<unsigned char>(b)); }
    );
    return it != haystack.end();
}

// Extract the domain from an email address like "user@example.com"
std::string extract_domain(const std::string& addr) {
    // Strip angle brackets and display name
    std::string clean = addr;
    auto lt = clean.find('<');
    auto gt = clean.find('>');
    if (lt != std::string::npos && gt != std::string::npos && gt > lt) {
        clean = clean.substr(lt + 1, gt - lt - 1);
    }
    auto at = clean.rfind('@');
    if (at == std::string::npos) return "";
    return to_lower(trim(clean.substr(at + 1)));
}

std::string get_header_value(const std::vector<EmailHeader>& headers,
                              const std::string& name) {
    std::string lower_name = to_lower(name);
    for (const auto& h : headers) {
        if (to_lower(h.name) == lower_name) return h.value;
    }
    return "";
}

// Decode base64 data
std::vector<uint8_t> decode_base64(const std::string& input) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::vector<uint8_t> result;
    result.reserve(input.size() * 3 / 4);

    std::array<int, 256> table{};
    table.fill(-1);
    for (int i = 0; i < 64; ++i) {
        table[static_cast<unsigned char>(chars[i])] = i;
    }

    int val = 0;
    int bits = -8;
    for (unsigned char c : input) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        if (table[c] == -1) continue;
        val = (val << 6) + table[c];
        bits += 6;
        if (bits >= 0) {
            result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return result;
}

// Decode quoted-printable encoding
std::string decode_quoted_printable(const std::string& input) {
    std::string result;
    result.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '=' && i + 2 < input.size()) {
            if (input[i + 1] == '\r' || input[i + 1] == '\n') {
                // Soft line break
                if (input[i + 1] == '\r' && i + 2 < input.size() && input[i + 2] == '\n') {
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            char hi = input[i + 1];
            char lo = input[i + 2];
            auto hex_val = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                return -1;
            };
            int h = hex_val(hi);
            int l = hex_val(lo);
            if (h >= 0 && l >= 0) {
                result.push_back(static_cast<char>((h << 4) | l));
                i += 2;
            } else {
                result.push_back(input[i]);
            }
        } else {
            result.push_back(input[i]);
        }
    }
    return result;
}

// Extract boundary from Content-Type header value
std::string extract_boundary(const std::string& content_type) {
    static const std::regex boundary_re(
        R"re(boundary\s*=\s*"?([^";\s]+)"?)re", std::regex::icase);
    std::smatch match;
    if (std::regex_search(content_type, match, boundary_re)) {
        return match[1].str();
    }
    return "";
}

// Extract a specific parameter from a header value
std::string extract_param(const std::string& header_val, const std::string& param) {
    std::string lower_val = to_lower(header_val);
    std::string lower_param = to_lower(param);
    auto pos = lower_val.find(lower_param);
    if (pos == std::string::npos) return "";
    pos += lower_param.size();
    while (pos < lower_val.size() && lower_val[pos] == ' ') ++pos;
    if (pos >= lower_val.size() || lower_val[pos] != '=') return "";
    ++pos;
    while (pos < lower_val.size() && lower_val[pos] == ' ') ++pos;
    if (pos >= lower_val.size()) return "";
    size_t val_start = pos;
    if (header_val[pos] == '"') {
        ++val_start;
        size_t end = header_val.find('"', val_start);
        if (end == std::string::npos) return header_val.substr(val_start);
        return header_val.substr(val_start, end - val_start);
    } else {
        size_t end = val_start;
        while (end < header_val.size() && header_val[end] != ';' &&
               header_val[end] != ' ' && header_val[end] != '\t') ++end;
        return header_val.substr(val_start, end - val_start);
    }
}

// Pre-compiled URL extraction regexes
const std::regex& url_regex() {
    static const std::regex re(R"(https?://[^\s"'<>\]]+)", std::regex::icase);
    return re;
}

const std::regex& href_regex() {
    static const std::regex re(R"re(href\s*=\s*"(https?://[^"]+)")re", std::regex::icase);
    return re;
}

// URL shortener domains
const std::unordered_set<std::string>& url_shorteners() {
    static const std::unordered_set<std::string> s = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl",
        "ow.ly", "cutt.ly", "buff.ly", "rebrand.ly", "shorturl.at",
    };
    return s;
}


// Phishing urgency keywords
const std::vector<std::string>& phishing_keywords() {
    static const std::vector<std::string> kw = {
        "verify your account",
        "within 24 hours",
        "account suspended",
        "unauthorized activity",
        "immediate action",
        "reset your password",
        "wire transfer",
        "invoice attached",
        "confirm your identity",
        "account will be closed",
        "act now",
        "urgent action required",
        "click here to verify",
        "security alert",
        "unusual sign-in activity",
    };
    return kw;
}

// Dangerous file extensions
const std::unordered_set<std::string>& dangerous_extensions() {
    static const std::unordered_set<std::string> ext = {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1",
        ".hta", ".lnk", ".msi", ".dll", ".com", ".wsf",
        ".iso", ".img", ".vhd", ".vhdx",
    };
    return ext;
}

const std::unordered_set<std::string>& macro_extensions() {
    static const std::unordered_set<std::string> ext = {
        ".docm", ".xlsm", ".pptm", ".dotm",
    };
    return ext;
}

const std::unordered_set<std::string>& archive_extensions() {
    static const std::unordered_set<std::string> ext = {
        ".zip", ".rar", ".7z", ".tar.gz", ".tgz", ".tar.bz2",
    };
    return ext;
}

std::string get_extension(const std::string& filename) {
    auto dot = filename.rfind('.');
    if (dot == std::string::npos) return "";
    return to_lower(filename.substr(dot));
}

// Check for double extensions like "document.pdf.exe"
bool has_double_extension(const std::string& filename) {
    auto last_dot = filename.rfind('.');
    if (last_dot == std::string::npos || last_dot == 0) return false;
    auto prev_dot = filename.rfind('.', last_dot - 1);
    if (prev_dot == std::string::npos) return false;
    std::string inner_ext = to_lower(filename.substr(prev_dot, last_dot - prev_dot));
    std::string outer_ext = to_lower(filename.substr(last_dot));
    // Only flag if the inner extension looks like a document/safe type
    // and the outer is an executable
    return (inner_ext == ".pdf" || inner_ext == ".doc" || inner_ext == ".docx" ||
            inner_ext == ".xls" || inner_ext == ".xlsx" || inner_ext == ".txt" ||
            inner_ext == ".jpg" || inner_ext == ".png") &&
           dangerous_extensions().count(outer_ext);
}

// Extract domain from a URL
std::string url_domain(const std::string& url) {
    // Skip scheme
    auto pos = url.find("://");
    if (pos == std::string::npos) return "";
    pos += 3;
    auto end = url.find_first_of(":/? #", pos);
    if (end == std::string::npos) end = url.size();
    return to_lower(url.substr(pos, end - pos));
}

// Check if URL uses an IP address instead of domain name
bool is_ip_url(const std::string& url) {
    std::string domain = url_domain(url);
    if (domain.empty()) return false;
    static const std::regex ip_re(R"(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)");
    return std::regex_match(domain, ip_re);
}

}  // namespace

EmailAnalyzer::EmailAnalyzer() = default;

Result<ParsedEmail> EmailAnalyzer::parse(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return Error{"Empty email data", "EMAIL_EMPTY"};
    }
    if (size > kMaxEmailSize) {
        return Error{"Email exceeds 25MB size limit", "EMAIL_TOO_LARGE"};
    }

    std::string raw(reinterpret_cast<const char*>(data), size);
    ParsedEmail result;

    // Split headers from body at first blank line
    std::string::size_type body_start = std::string::npos;
    auto crlf_split = raw.find("\r\n\r\n");
    auto lf_split = raw.find("\n\n");

    if (crlf_split != std::string::npos &&
        (lf_split == std::string::npos || crlf_split <= lf_split)) {
        body_start = crlf_split + 4;
    } else if (lf_split != std::string::npos) {
        body_start = lf_split + 2;
    }

    std::string header_section;
    std::string body_section;
    if (body_start != std::string::npos) {
        header_section = raw.substr(0, body_start);
        body_section = raw.substr(body_start);
    } else {
        header_section = raw;
    }

    // Parse headers with continuation line unfolding (RFC 5322 2.2.3)
    std::istringstream hstream(header_section);
    std::string line;
    std::string current_name;
    std::string current_value;

    auto commit_header = [&]() {
        if (!current_name.empty()) {
            result.headers.push_back({current_name, trim(current_value)});
        }
    };

    while (std::getline(hstream, line)) {
        // Remove trailing \r
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) break;

        // Continuation line: starts with whitespace
        if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
            current_value += " " + trim(line);
            continue;
        }

        commit_header();
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            current_name = line.substr(0, colon);
            current_value = line.substr(colon + 1);
        } else {
            current_name.clear();
            current_value.clear();
        }
    }
    commit_header();

    // Extract well-known headers
    result.subject = get_header_value(result.headers, "Subject");
    result.from = get_header_value(result.headers, "From");
    result.date = get_header_value(result.headers, "Date");
    result.message_id = get_header_value(result.headers, "Message-ID");

    // Parse To header (may be comma-separated)
    std::string to_raw = get_header_value(result.headers, "To");
    if (!to_raw.empty()) {
        std::istringstream tstream(to_raw);
        std::string addr;
        while (std::getline(tstream, addr, ',')) {
            std::string trimmed = trim(addr);
            if (!trimmed.empty()) {
                result.to.push_back(trimmed);
            }
        }
    }

    // Determine content type and handle body
    std::string content_type = get_header_value(result.headers, "Content-Type");
    std::string boundary = extract_boundary(content_type);

    if (!boundary.empty()) {
        // Multipart MIME
        parse_mime_part(body_section, boundary, result);
    } else {
        // Check transfer encoding for the top-level body
        std::string encoding = to_lower(
            get_header_value(result.headers, "Content-Transfer-Encoding"));
        std::string decoded_body;

        if (encoding == "base64") {
            auto bytes = decode_base64(body_section);
            decoded_body = std::string(bytes.begin(), bytes.end());
        } else if (encoding == "quoted-printable") {
            decoded_body = decode_quoted_printable(body_section);
        } else {
            decoded_body = body_section;
        }

        std::string ct_lower = to_lower(content_type);
        if (ct_lower.find("text/html") != std::string::npos) {
            result.body_html = decoded_body;
        } else {
            result.body_text = decoded_body;
        }
    }

    // Extract URLs from both bodies
    auto text_urls = extract_urls(result.body_text);
    auto html_urls = extract_urls(result.body_html);
    std::unordered_set<std::string> seen;
    for (const auto& u : text_urls) {
        if (seen.insert(u).second) result.urls_in_body.push_back(u);
    }
    for (const auto& u : html_urls) {
        if (seen.insert(u).second) result.urls_in_body.push_back(u);
    }

    return result;
}

void EmailAnalyzer::parse_mime_part(const std::string& part,
                                     const std::string& boundary,
                                     ParsedEmail& result, int depth) {
    constexpr int kMaxMimeDepth = 10;
    if (depth > kMaxMimeDepth) return;

    std::string delimiter = "--" + boundary;
    std::string end_delimiter = delimiter + "--";

    // Split on boundary markers
    std::vector<std::string> sections;
    size_t pos = 0;
    while (pos < part.size()) {
        auto delim_pos = part.find(delimiter, pos);
        if (delim_pos == std::string::npos) break;

        // Skip the preamble (content before first boundary)
        size_t section_start = delim_pos + delimiter.size();
        // Skip CRLF after delimiter
        if (section_start < part.size() && part[section_start] == '\r') section_start++;
        if (section_start < part.size() && part[section_start] == '\n') section_start++;

        // Check for end delimiter
        if (part.substr(delim_pos, end_delimiter.size()) == end_delimiter) break;

        auto next_delim = part.find(delimiter, section_start);
        if (next_delim == std::string::npos) {
            sections.push_back(part.substr(section_start));
        } else {
            // Trim trailing CRLF before next delimiter
            size_t end = next_delim;
            if (end > 0 && part[end - 1] == '\n') end--;
            if (end > 0 && part[end - 1] == '\r') end--;
            sections.push_back(part.substr(section_start, end - section_start));
        }
        pos = (next_delim != std::string::npos) ? next_delim : part.size();
    }

    for (const auto& section : sections) {
        // Split part headers from part body
        std::string::size_type part_body_start = std::string::npos;
        auto crlf_split = section.find("\r\n\r\n");
        auto lf_split = section.find("\n\n");

        if (crlf_split != std::string::npos &&
            (lf_split == std::string::npos || crlf_split <= lf_split)) {
            part_body_start = crlf_split + 4;
        } else if (lf_split != std::string::npos) {
            part_body_start = lf_split + 2;
        }

        std::string part_headers_str;
        std::string part_body;
        if (part_body_start != std::string::npos) {
            part_headers_str = section.substr(0, part_body_start);
            part_body = section.substr(part_body_start);
        } else {
            part_body = section;
        }

        // Parse part headers
        std::vector<EmailHeader> part_headers;
        std::istringstream phstream(part_headers_str);
        std::string line;
        std::string cur_name, cur_value;

        auto commit = [&]() {
            if (!cur_name.empty()) {
                part_headers.push_back({cur_name, trim(cur_value)});
            }
        };

        while (std::getline(phstream, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) break;
            if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
                cur_value += " " + trim(line);
                continue;
            }
            commit();
            auto colon = line.find(':');
            if (colon != std::string::npos) {
                cur_name = line.substr(0, colon);
                cur_value = line.substr(colon + 1);
            } else {
                cur_name.clear();
                cur_value.clear();
            }
        }
        commit();

        // Extract part metadata
        std::string ct, cte, cd;
        for (const auto& ph : part_headers) {
            std::string lower = to_lower(ph.name);
            if (lower == "content-type") ct = ph.value;
            else if (lower == "content-transfer-encoding") cte = ph.value;
            else if (lower == "content-disposition") cd = ph.value;
        }

        std::string ct_lower = to_lower(ct);
        std::string cte_lower = to_lower(trim(cte));

        // Handle nested multipart
        std::string nested_boundary = extract_boundary(ct);
        if (!nested_boundary.empty()) {
            parse_mime_part(part_body, nested_boundary, result, depth + 1);
            continue;
        }

        // Decode content based on transfer encoding
        std::string decoded_text;
        std::vector<uint8_t> decoded_bytes;

        if (cte_lower == "base64") {
            decoded_bytes = decode_base64(part_body);
            decoded_text = std::string(decoded_bytes.begin(), decoded_bytes.end());
        } else if (cte_lower == "quoted-printable") {
            decoded_text = decode_quoted_printable(part_body);
            decoded_bytes.assign(decoded_text.begin(), decoded_text.end());
        } else {
            decoded_text = part_body;
            decoded_bytes.assign(part_body.begin(), part_body.end());
        }

        // Determine if this is an attachment
        bool is_attachment = contains_ci(cd, "attachment");
        std::string filename = extract_param(cd, "filename");
        if (filename.empty()) {
            filename = extract_param(ct, "name");
        }

        if (is_attachment || (!filename.empty() && ct_lower.find("text/") == std::string::npos)) {
            if (result.attachments.size() >= kMaxAttachmentCount) continue;
            if (decoded_bytes.size() > kMaxAttachmentSize) continue;
            EmailAttachment att;
            att.filename = filename;
            att.content_type = trim(ct);
            att.data = std::move(decoded_bytes);
            att.sha256 = compute_sha256(att.data.data(), att.data.size());
            result.attachments.push_back(std::move(att));
        } else if (ct_lower.find("text/html") != std::string::npos) {
            if (result.body_html.empty()) {
                result.body_html = decoded_text;
            }
        } else if (ct_lower.find("text/plain") != std::string::npos || ct.empty()) {
            if (result.body_text.empty()) {
                result.body_text = decoded_text;
            }
        } else {
            // Non-text, non-attachment binary part -- treat as attachment
            if (result.attachments.size() >= kMaxAttachmentCount) continue;
            if (decoded_bytes.size() > kMaxAttachmentSize) continue;
            EmailAttachment att;
            att.filename = filename.empty() ? "unnamed" : filename;
            att.content_type = trim(ct);
            att.data = std::move(decoded_bytes);
            att.sha256 = compute_sha256(att.data.data(), att.data.size());
            result.attachments.push_back(std::move(att));
        }
    }
}

Result<AnalysisEngineResult> EmailAnalyzer::analyze(const FileBuffer& file) {
    auto start = std::chrono::steady_clock::now();

    auto parsed = parse(file.ptr(), file.size());
    if (!parsed.ok()) {
        AnalysisEngineResult err_result;
        err_result.engine = AnalysisEngine::kEmail;
        err_result.success = false;
        err_result.error = parsed.error().message;
        err_result.duration_ms = 0;
        return err_result;
    }

    auto& email = parsed.value();
    std::vector<Finding> findings;

    auto header_findings = analyze_headers(email);
    findings.insert(findings.end(), header_findings.begin(), header_findings.end());

    auto body_findings = analyze_body(email);
    findings.insert(findings.end(), body_findings.begin(), body_findings.end());

    auto attachment_findings = analyze_attachments(email);
    findings.insert(findings.end(), attachment_findings.begin(), attachment_findings.end());

    auto end = std::chrono::steady_clock::now();
    double duration_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    AnalysisEngineResult result;
    result.engine = AnalysisEngine::kEmail;
    result.success = true;
    result.findings = std::move(findings);
    result.duration_ms = duration_ms;
    result.raw_output = {
        {"subject", email.subject},
        {"from", email.from},
        {"to", email.to},
        {"date", email.date},
        {"message_id", email.message_id},
        {"header_count", email.headers.size()},
        {"attachment_count", email.attachments.size()},
        {"url_count", email.urls_in_body.size()},
        {"body_text_length", email.body_text.size()},
        {"body_html_length", email.body_html.size()},
    };

    return result;
}

std::vector<Finding> EmailAnalyzer::analyze_headers(const ParsedEmail& email) {
    std::vector<Finding> findings;

    // SPF/DKIM/DMARC checks from Authentication-Results
    std::string auth_results = get_header_value(email.headers, "Authentication-Results");
    if (!auth_results.empty()) {
        std::string auth_lower = to_lower(auth_results);

        auto check_auth = [&](const std::string& mechanism, const std::string& label) {
            // Look for "mechanism=fail" or "mechanism=softfail" or "mechanism=none"
            std::string fail_pat = mechanism + "=fail";
            std::string softfail_pat = mechanism + "=softfail";
            std::string none_pat = mechanism + "=none";

            if (auth_lower.find(fail_pat) != std::string::npos) {
                findings.push_back({
                    "Email: " + label + " Authentication Failed",
                    label + " check returned 'fail' — the sender may be spoofing the from address",
                    Severity::kHigh,
                    AnalysisEngine::kEmail,
                    {{"mechanism", mechanism}, {"result", "fail"},
                     {"mitre_technique", "T1566.001"}},
                });
            } else if (auth_lower.find(softfail_pat) != std::string::npos) {
                findings.push_back({
                    "Email: " + label + " Soft Fail",
                    label + " check returned 'softfail' — sender authentication is weak",
                    Severity::kMedium,
                    AnalysisEngine::kEmail,
                    {{"mechanism", mechanism}, {"result", "softfail"},
                     {"mitre_technique", "T1566.001"}},
                });
            } else if (auth_lower.find(none_pat) != std::string::npos) {
                findings.push_back({
                    "Email: No " + label + " Record",
                    label + " check returned 'none' — no authentication record configured",
                    Severity::kLow,
                    AnalysisEngine::kEmail,
                    {{"mechanism", mechanism}, {"result", "none"},
                     {"mitre_technique", "T1566.001"}},
                });
            }
        };

        check_auth("spf", "SPF");
        check_auth("dkim", "DKIM");
        check_auth("dmarc", "DMARC");
    }

    // Reply-To domain mismatch
    std::string reply_to = get_header_value(email.headers, "Reply-To");
    if (!reply_to.empty()) {
        std::string from_domain = extract_domain(email.from);
        std::string reply_domain = extract_domain(reply_to);
        if (!from_domain.empty() && !reply_domain.empty() &&
            from_domain != reply_domain) {
            findings.push_back({
                "Email: Reply-To Domain Mismatch",
                "Reply-To domain (" + reply_domain + ") differs from From domain (" +
                    from_domain + ") — possible phishing indicator",
                Severity::kMedium,
                AnalysisEngine::kEmail,
                {{"from_domain", from_domain}, {"reply_to_domain", reply_domain},
                 {"mitre_technique", "T1566.001"}},
            });
        }
    }

    // From / Return-Path domain mismatch
    std::string return_path = get_header_value(email.headers, "Return-Path");
    if (!return_path.empty()) {
        std::string from_domain = extract_domain(email.from);
        std::string rp_domain = extract_domain(return_path);
        if (!from_domain.empty() && !rp_domain.empty() &&
            from_domain != rp_domain) {
            findings.push_back({
                "Email: From/Return-Path Domain Mismatch",
                "Return-Path domain (" + rp_domain + ") differs from From domain (" +
                    from_domain + ")",
                Severity::kLow,
                AnalysisEngine::kEmail,
                {{"from_domain", from_domain}, {"return_path_domain", rp_domain},
                 {"mitre_technique", "T1566.001"}},
            });
        }
    }

    // Received chain timestamp anomalies
    // Collect Received headers and check for backward timestamps
    std::vector<std::string> received_dates;
    for (const auto& h : email.headers) {
        if (to_lower(h.name) == "received") {
            // Received headers contain a date after the semicolon
            auto semi = h.value.rfind(';');
            if (semi != std::string::npos) {
                received_dates.push_back(trim(h.value.substr(semi + 1)));
            }
        }
    }
    // Received headers are in reverse order (most recent first).
    // We check adjacent pairs: if a later hop has an earlier timestamp, flag it.
    // We do a simple comparison by looking for obvious date-ordering issues.
    // Full date parsing is complex; we check for the common pattern of
    // day numbers decreasing when month/year are the same.
    if (received_dates.size() >= 2) {
        // Simple heuristic: look for negative hop delays by checking if
        // any received header references suggest time travel (this is a
        // simplified check — full RFC 2822 date parsing would be more robust).
        static const std::regex date_re(
            R"((\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2}))",
            std::regex::icase);

        struct SimpleDate {
            int year, month, day, hour, min, sec;
            bool valid = false;
        };

        auto parse_date = [&](const std::string& s) -> SimpleDate {
            std::smatch m;
            if (!std::regex_search(s, m, date_re)) return {};
            static const std::vector<std::string> months = {
                "jan", "feb", "mar", "apr", "may", "jun",
                "jul", "aug", "sep", "oct", "nov", "dec"};
            std::string mon = to_lower(m[2].str());
            int month_num = 0;
            for (int i = 0; i < 12; ++i) {
                if (months[i] == mon) { month_num = i + 1; break; }
            }
            return {std::stoi(m[3]), month_num, std::stoi(m[1]),
                    std::stoi(m[4]), std::stoi(m[5]), std::stoi(m[6]), true};
        };

        auto to_seconds = [](const SimpleDate& d) -> int64_t {
            static constexpr int days_before_month[] = {
                0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
            };
            int m = (d.month >= 1 && d.month <= 12) ? d.month : 1;
            int64_t days = int64_t(d.year) * 365 + (d.year / 4) +
                           days_before_month[m] + d.day;
            return days * 86400LL + d.hour * 3600LL + d.min * 60LL + d.sec;
        };

        // Received headers: index 0 = most recent hop, last = origin
        for (size_t i = 0; i + 1 < received_dates.size(); ++i) {
            auto newer = parse_date(received_dates[i]);
            auto older = parse_date(received_dates[i + 1]);
            if (newer.valid && older.valid) {
                if (to_seconds(newer) < to_seconds(older)) {
                    findings.push_back({
                        "Email: Received Chain Timestamp Anomaly",
                        "Mail hop timestamps go backwards — received header ordering is anomalous",
                        Severity::kMedium,
                        AnalysisEngine::kEmail,
                        {{"hop_index", i}, {"mitre_technique", "T1566.001"}},
                    });
                    break;
                }
            }
        }
    }

    // Missing critical headers
    if (email.message_id.empty()) {
        findings.push_back({
            "Email: Missing Message-ID Header",
            "Email lacks a Message-ID header which is unusual for legitimate mail",
            Severity::kLow,
            AnalysisEngine::kEmail,
            {{"missing_header", "Message-ID"}},
        });
    }
    if (email.date.empty()) {
        findings.push_back({
            "Email: Missing Date Header",
            "Email lacks a Date header which is unusual for legitimate mail",
            Severity::kLow,
            AnalysisEngine::kEmail,
            {{"missing_header", "Date"}},
        });
    }

    return findings;
}

std::vector<Finding> EmailAnalyzer::analyze_body(const ParsedEmail& email) {
    std::vector<Finding> findings;
    std::string combined = email.body_text + " " + email.body_html;
    std::string combined_lower = to_lower(combined);

    // IP-based URLs
    for (const auto& url : email.urls_in_body) {
        if (is_ip_url(url)) {
            findings.push_back({
                "Email: IP-Based URL in Body",
                "URL uses a raw IP address instead of a domain name: " +
                    url.substr(0, 120),
                Severity::kHigh,
                AnalysisEngine::kEmail,
                {{"url", url}, {"mitre_technique", "T1566.002"}},
            });
            break;  // one finding is enough
        }
    }

    // URL shorteners
    for (const auto& url : email.urls_in_body) {
        std::string domain = url_domain(url);
        if (url_shorteners().count(domain)) {
            findings.push_back({
                "Email: URL Shortener in Body",
                "Email contains a shortened URL (" + domain + ") which may hide the real destination",
                Severity::kMedium,
                AnalysisEngine::kEmail,
                {{"url", url}, {"shortener_domain", domain},
                 {"mitre_technique", "T1566.002"}},
            });
            break;
        }
    }


    // Homograph detection: URLs with non-ASCII characters (simple check)
    for (const auto& url : email.urls_in_body) {
        std::string domain = url_domain(url);
        bool has_non_ascii = false;
        for (unsigned char c : domain) {
            if (c > 127) { has_non_ascii = true; break; }
        }
        // Also check for xn-- (punycode) which indicates IDN
        if (has_non_ascii || domain.find("xn--") != std::string::npos) {
            findings.push_back({
                "Email: Potential Homograph URL",
                "URL domain contains internationalized characters or punycode, "
                "which could be a homograph attack: " + domain,
                Severity::kHigh,
                AnalysisEngine::kEmail,
                {{"domain", domain}, {"mitre_technique", "T1566.002"}},
            });
            break;
        }
    }

    // Phishing urgency keywords
    std::vector<std::string> matched_keywords;
    for (const auto& kw : phishing_keywords()) {
        if (contains_ci(combined, kw)) {
            matched_keywords.push_back(kw);
        }
    }
    if (!matched_keywords.empty()) {
        findings.push_back({
            "Email: Phishing Urgency Language Detected",
            "Email body contains " + std::to_string(matched_keywords.size()) +
                " urgency/phishing keyword pattern(s)",
            Severity::kMedium,
            AnalysisEngine::kEmail,
            {{"matched_keywords", matched_keywords},
             {"mitre_technique", "T1566.001"}},
        });
    }

    // Hidden content in HTML with links
    if (!email.body_html.empty()) {
        std::string html_lower = to_lower(email.body_html);

        // display:none or visibility:hidden containing links
        static const std::regex hidden_link_re(
            R"((?:display\s*:\s*none|visibility\s*:\s*hidden)[^>]*>[\s\S]{0,500}?<a\s)",
            std::regex::icase);
        if (std::regex_search(email.body_html, hidden_link_re)) {
            findings.push_back({
                "Email: Hidden Content with Links",
                "HTML body contains hidden elements (display:none/visibility:hidden) that include links",
                Severity::kHigh,
                AnalysisEngine::kEmail,
                {{"mitre_technique", "T1566.001"}},
            });
        }

        // External form actions
        static const std::regex form_action_re(
            R"re(<form[^>]+action\s*=\s*"(https?://[^"]+)")re",
            std::regex::icase);
        std::smatch form_match;
        if (std::regex_search(email.body_html, form_match, form_action_re)) {
            std::string action_url = form_match[1].str();
            std::string action_domain = url_domain(action_url);
            std::string from_domain = extract_domain(email.from);
            if (!action_domain.empty() && !from_domain.empty() &&
                action_domain != from_domain) {
                findings.push_back({
                    "Email: External Form Action",
                    "HTML form posts data to external domain (" + action_domain +
                        ") different from sender (" + from_domain + ")",
                    Severity::kHigh,
                    AnalysisEngine::kEmail,
                    {{"action_url", action_url}, {"action_domain", action_domain},
                     {"from_domain", from_domain}, {"mitre_technique", "T1566.001"}},
                });
            }
        }
    }

    // Excessive URLs
    if (email.urls_in_body.size() > 20) {
        findings.push_back({
            "Email: Excessive URLs in Body",
            "Email contains " + std::to_string(email.urls_in_body.size()) +
                " unique URLs which is unusually high",
            Severity::kLow,
            AnalysisEngine::kEmail,
            {{"url_count", email.urls_in_body.size()}},
        });
    }

    return findings;
}

std::vector<Finding> EmailAnalyzer::analyze_attachments(const ParsedEmail& email) {
    std::vector<Finding> findings;

    for (const auto& att : email.attachments) {
        std::string filename_lower = to_lower(att.filename);
        std::string ext = get_extension(att.filename);

        // Double extension check (must be before single extension)
        if (has_double_extension(att.filename)) {
            findings.push_back({
                "Email: Double Extension Attachment",
                "Attachment uses double extension to disguise file type: " + att.filename,
                Severity::kCritical,
                AnalysisEngine::kEmail,
                {{"filename", att.filename}, {"sha256", att.sha256},
                 {"mitre_technique", "T1036.007"}},
            });
            continue;
        }

        // Dangerous executable extensions
        if (dangerous_extensions().count(ext)) {
            findings.push_back({
                "Email: Dangerous Executable Attachment",
                "Attachment has dangerous executable extension: " + att.filename,
                Severity::kCritical,
                AnalysisEngine::kEmail,
                {{"filename", att.filename}, {"extension", ext},
                 {"sha256", att.sha256}, {"mitre_technique", "T1566.001"}},
            });
            continue;
        }

        // Macro-enabled Office documents
        if (macro_extensions().count(ext)) {
            findings.push_back({
                "Email: Macro-Enabled Document Attachment",
                "Attachment is a macro-enabled Office document: " + att.filename,
                Severity::kHigh,
                AnalysisEngine::kEmail,
                {{"filename", att.filename}, {"extension", ext},
                 {"sha256", att.sha256}, {"mitre_technique", "T1566.001"}},
            });
            continue;
        }

        // Archives (potential evasion)
        if (archive_extensions().count(ext)) {
            Severity sev = Severity::kMedium;
            std::string desc = "Attachment is an archive file: " + att.filename;

            // Password-protected archive heuristic (filename pattern)
            if (filename_lower.find("password") != std::string::npos ||
                filename_lower.find("protected") != std::string::npos ||
                filename_lower.find("encrypted") != std::string::npos) {
                sev = Severity::kHigh;
                desc = "Attachment appears to be a password-protected archive: " + att.filename;
            }

            findings.push_back({
                sev == Severity::kHigh
                    ? "Email: Password-Protected Archive Attachment"
                    : "Email: Archive Attachment",
                desc,
                sev,
                AnalysisEngine::kEmail,
                {{"filename", att.filename}, {"extension", ext},
                 {"sha256", att.sha256}, {"mitre_technique", "T1566.001"}},
            });
        }
    }

    return findings;
}

std::vector<std::string> EmailAnalyzer::extract_urls(const std::string& text) {
    if (text.empty()) return {};

    std::unordered_set<std::string> seen;
    std::vector<std::string> urls;

    // Extract bare URLs
    auto begin = std::sregex_iterator(text.begin(), text.end(), url_regex());
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end && urls.size() < kMaxUrls; ++it) {
        std::string url = (*it)[0].str();
        // Trim trailing punctuation that's likely not part of the URL
        while (!url.empty() && (url.back() == '.' || url.back() == ',' ||
                                url.back() == ')' || url.back() == ';')) {
            url.pop_back();
        }
        if (seen.insert(url).second) {
            urls.push_back(url);
        }
    }

    // Extract from href attributes
    begin = std::sregex_iterator(text.begin(), text.end(), href_regex());
    for (auto it = begin; it != end && urls.size() < kMaxUrls; ++it) {
        std::string url = (*it)[1].str();
        if (seen.insert(url).second) {
            urls.push_back(url);
        }
    }

    return urls;
}

}  // namespace shieldtier

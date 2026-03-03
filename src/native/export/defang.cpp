#include "export/defang.h"

#include <algorithm>
#include <regex>
#include <set>
#include <string>

namespace shieldtier {

namespace {

const std::set<std::string> kDangerousExtensions = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".msi", ".scr", ".com", ".hta", ".wsf", ".jar", ".lnk"
};

std::string to_lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

std::string replace_dots(const std::string& s) {
    std::string result;
    result.reserve(s.size() + s.size() / 4);
    for (char c : s) {
        if (c == '.') {
            result += "[.]";
        } else {
            result += c;
        }
    }
    return result;
}

bool is_ip_pattern(const std::string& s) {
    static const std::regex ip_re(
        R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)");
    return std::regex_match(s, ip_re);
}

}  // namespace

std::string Defang::defang_url(const std::string& url) {
    std::string result = url;

    size_t scheme_end = 0;
    if (result.substr(0, 8) == "https://") {
        result = "hxxps://" + result.substr(8);
        scheme_end = 8;
    } else if (result.substr(0, 7) == "http://") {
        result = "hxxp://" + result.substr(7);
        scheme_end = 7;
    } else {
        return result;
    }

    // Find the domain portion: from scheme_end to first / or ? or end
    size_t domain_end = std::string::npos;
    for (size_t i = scheme_end; i < result.size(); i++) {
        if (result[i] == '/' || result[i] == '?') {
            domain_end = i;
            break;
        }
    }

    std::string domain = (domain_end == std::string::npos)
        ? result.substr(scheme_end)
        : result.substr(scheme_end, domain_end - scheme_end);

    std::string defanged_domain = replace_dots(domain);

    std::string tail = (domain_end == std::string::npos)
        ? ""
        : result.substr(domain_end);

    return result.substr(0, scheme_end) + defanged_domain + tail;
}

std::string Defang::defang_ip(const std::string& ip) {
    if (!is_ip_pattern(ip)) {
        return ip;
    }
    return replace_dots(ip);
}

std::string Defang::defang_email(const std::string& email) {
    size_t at_pos = email.find('@');
    if (at_pos == std::string::npos) {
        return email;
    }

    std::string local = email.substr(0, at_pos);
    std::string domain = email.substr(at_pos + 1);
    return local + "[@]" + replace_dots(domain);
}

std::string Defang::defang_filename(const std::string& filename) {
    size_t last_dot = filename.rfind('.');
    if (last_dot == std::string::npos || last_dot == 0) {
        return filename;
    }

    std::string ext = to_lower(filename.substr(last_dot));
    if (kDangerousExtensions.count(ext)) {
        return filename.substr(0, last_dot) + "[.]" + filename.substr(last_dot + 1);
    }
    return filename;
}

std::string Defang::defang_all(const std::string& text) {
    std::string result = text;

    // URLs — match http(s):// followed by non-whitespace characters
    {
        static const std::regex url_re(R"(https?://[^\s"'<>\]]+)");
        std::string out;
        std::sregex_iterator it(result.begin(), result.end(), url_re);
        std::sregex_iterator end;
        size_t last_pos = 0;

        for (; it != end; ++it) {
            out += result.substr(last_pos, it->position() - last_pos);
            out += defang_url(it->str());
            last_pos = it->position() + it->length();
        }
        out += result.substr(last_pos);
        result = std::move(out);
    }

    // Emails — match word@word.word patterns (run before IP to avoid
    // collisions, since email regex won't match IP-only strings)
    {
        static const std::regex email_re(
            R"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})");
        std::string out;
        std::sregex_iterator it(result.begin(), result.end(), email_re);
        std::sregex_iterator end;
        size_t last_pos = 0;

        for (; it != end; ++it) {
            out += result.substr(last_pos, it->position() - last_pos);
            out += defang_email(it->str());
            last_pos = it->position() + it->length();
        }
        out += result.substr(last_pos);
        result = std::move(out);
    }

    // Standalone IPs — match digit groups separated by dots, surrounded by
    // word boundaries (negative lookbehind for :// to skip URLs already handled)
    {
        static const std::regex ip_re(
            R"((?:^|(?<=[\s,;:"'(\[]))(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?=[\s,;:"')\]$]|$))");
        std::string out;
        std::sregex_iterator it(result.begin(), result.end(), ip_re);
        std::sregex_iterator end;
        size_t last_pos = 0;

        for (; it != end; ++it) {
            auto& match = *it;
            out += result.substr(last_pos, match.position() - last_pos);

            // Only defang if this IP isn't already inside a defanged URL
            std::string ip_str = match[1].matched ? match.str(1) : match.str();
            bool inside_url = false;
            if (match.position() >= 6) {
                std::string preceding = result.substr(
                    match.position() > 10 ? match.position() - 10 : 0,
                    match.position() - (match.position() > 10 ? match.position() - 10 : 0));
                if (preceding.find("://") != std::string::npos ||
                    preceding.find("[://]") != std::string::npos) {
                    inside_url = true;
                }
            }

            if (inside_url) {
                out += match.str();
            } else {
                out += defang_ip(match.str());
            }
            last_pos = match.position() + match.length();
        }
        out += result.substr(last_pos);
        result = std::move(out);
    }

    return result;
}

}  // namespace shieldtier

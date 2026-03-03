#pragma once

#include <string>

namespace shieldtier {

class Defang {
public:
    static std::string defang_url(const std::string& url);
    static std::string defang_ip(const std::string& ip);
    static std::string defang_email(const std::string& email);
    static std::string defang_filename(const std::string& filename);
    static std::string defang_all(const std::string& text);
};

}  // namespace shieldtier

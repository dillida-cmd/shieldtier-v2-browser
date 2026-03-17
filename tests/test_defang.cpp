#include <gtest/gtest.h>
#include "export/defang.h"

using namespace shieldtier;

TEST(Defang, DefangURL) {
    EXPECT_EQ(Defang::defang_url("http://evil.com/malware"),
              "hxxp://evil[.]com/malware");
    EXPECT_EQ(Defang::defang_url("https://evil.com/path"),
              "hxxps://evil[.]com/path");
}

TEST(Defang, DefangIP) {
    EXPECT_EQ(Defang::defang_ip("192.168.1.1"), "192[.]168[.]1[.]1");
    EXPECT_EQ(Defang::defang_ip("10.0.0.1"), "10[.]0[.]0[.]1");
}

TEST(Defang, DefangEmail) {
    EXPECT_EQ(Defang::defang_email("user@evil.com"), "user[@]evil[.]com");
}

TEST(Defang, DefangAll) {
    std::string text = "Visit http://evil.com and contact admin@evil.com from 10.0.0.1";
    std::string defanged = Defang::defang_all(text);
    EXPECT_NE(defanged.find("hxxp"), std::string::npos);
    EXPECT_NE(defanged.find("[.]"), std::string::npos);
}

TEST(Defang, EmptyInput) {
    EXPECT_EQ(Defang::defang_url(""), "");
    EXPECT_EQ(Defang::defang_ip(""), "");
    EXPECT_EQ(Defang::defang_email(""), "");
}

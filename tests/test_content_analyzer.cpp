#include <gtest/gtest.h>
#include "analysis/content/content_analyzer.h"

using namespace shieldtier;

TEST(ContentAnalyzer, DetectEval) {
    ContentAnalyzer analyzer;
    std::string html = "<html><script>eval(atob('bWFsd2FyZQ=='))</script></html>";
    FileBuffer fb;
    fb.data.assign(html.begin(), html.end());
    fb.mime_type = "text/html";
    fb.filename = "page.html";

    auto result = analyzer.analyze(fb);
    ASSERT_TRUE(result.ok());
    EXPECT_GT(result.value().findings.size(), 0u);
}

TEST(ContentAnalyzer, DetectDocumentWrite) {
    ContentAnalyzer analyzer;
    std::string html = "<html><script>document.write('<iframe src=\"evil.com\">')</script></html>";
    FileBuffer fb;
    fb.data.assign(html.begin(), html.end());
    fb.mime_type = "text/html";
    fb.filename = "page.html";

    auto result = analyzer.analyze(fb);
    ASSERT_TRUE(result.ok());
    EXPECT_GT(result.value().findings.size(), 0u);
}

TEST(ContentAnalyzer, CleanHTML) {
    ContentAnalyzer analyzer;
    std::string html = "<html><head><title>Hello</title></head><body><p>Safe content</p></body></html>";
    FileBuffer fb;
    fb.data.assign(html.begin(), html.end());
    fb.mime_type = "text/html";
    fb.filename = "page.html";

    auto result = analyzer.analyze(fb);
    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.value().findings.size(), 0u);
}

TEST(ContentAnalyzer, EmptyContent) {
    ContentAnalyzer analyzer;
    FileBuffer fb;
    fb.mime_type = "text/html";
    fb.filename = "empty.html";

    auto result = analyzer.analyze(fb);
    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.value().findings.size(), 0u);
}

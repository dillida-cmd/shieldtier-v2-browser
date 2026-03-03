#pragma once

#include <string>

#include "include/cef_browser.h"

namespace shieldtier {

class Navigation {
public:
    static void go_back(CefRefPtr<CefBrowser> browser);
    static void go_forward(CefRefPtr<CefBrowser> browser);
    static void reload(CefRefPtr<CefBrowser> browser);
    static void stop(CefRefPtr<CefBrowser> browser);
    static void load_url(CefRefPtr<CefBrowser> browser, const std::string& url);

    static std::string get_url(CefRefPtr<CefBrowser> browser);
    static std::string get_title(CefRefPtr<CefBrowser> browser);
    static bool can_go_back(CefRefPtr<CefBrowser> browser);
    static bool can_go_forward(CefRefPtr<CefBrowser> browser);
    static bool is_loading(CefRefPtr<CefBrowser> browser);

    static double get_zoom_level(CefRefPtr<CefBrowser> browser);
    static void set_zoom_level(CefRefPtr<CefBrowser> browser, double level);
};

}  // namespace shieldtier

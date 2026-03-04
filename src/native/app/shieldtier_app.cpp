#include "app/shieldtier_app.h"
#include "app/shieldtier_client.h"
#include "browser/scheme_handler.h"

#include "include/cef_browser.h"
#include "include/cef_command_line.h"
#include "include/cef_scheme.h"

#include <cstdlib>
#include <filesystem>

void ShieldTierApp::OnRegisterCustomSchemes(
        CefRawPtr<CefSchemeRegistrar> registrar) {
    registrar->AddCustomScheme(
        "shieldtier",
        CEF_SCHEME_OPTION_STANDARD | CEF_SCHEME_OPTION_SECURE |
        CEF_SCHEME_OPTION_CORS_ENABLED | CEF_SCHEME_OPTION_FETCH_ENABLED);
}

void ShieldTierApp::OnContextInitialized() {
    const std::string root_cache_path = "/tmp/shieldtier/cache";

    const char* renderer_path = std::getenv("SHIELDTIER_RENDERER_PATH");
    std::string renderer_dist = renderer_path
        ? std::string(renderer_path)
        : (std::filesystem::current_path() / "src" / "renderer" / "dist").string();

    CefRegisterSchemeHandlerFactory(
        "shieldtier", "app",
        new shieldtier::SchemeHandlerFactory(renderer_dist));

    CefRefPtr<ShieldTierClient> client(
        new ShieldTierClient(root_cache_path));

    const char* dev_url = std::getenv("SHIELDTIER_DEV_URL");
    std::string initial_url = dev_url ? std::string(dev_url) : "shieldtier://app/";

    client->session_manager()->create_tab(initial_url, true, client);
}

#include "app/shieldtier_app.h"
#include "app/shieldtier_client.h"
#include "browser/scheme_handler.h"
#include "config/paths.h"

#include "include/cef_browser.h"
#include "include/cef_command_line.h"
#include "include/cef_scheme.h"

#include <cstdlib>
#include <filesystem>

#if defined(OS_MAC) || defined(OS_MACOS)
#include "app/app_mac.h"
#include <mach-o/dyld.h>
#endif

static std::filesystem::path get_executable_dir() {
#if defined(OS_MAC) || defined(OS_MACOS)
    char buf[4096];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        return std::filesystem::path(buf).parent_path();
    }
#endif
    return std::filesystem::current_path();
}

void ShieldTierApp::OnBeforeCommandLineProcessing(
        const CefString& /*process_type*/,
        CefRefPtr<CefCommandLine> command_line) {
    command_line->AppendSwitchWithValue(
        "force-webrtc-ip-handling-policy", "disable_non_proxied_udp");
    command_line->AppendSwitch("disable-webrtc-hide-local-ips-with-mdns");
    command_line->AppendSwitch("use-mock-keychain");
    if (!command_line->HasSwitch("lang")) {
        command_line->AppendSwitchWithValue("lang", "en-US");
    }
}

void ShieldTierApp::OnRegisterCustomSchemes(
        CefRawPtr<CefSchemeRegistrar> registrar) {
    registrar->AddCustomScheme(
        "shieldtier",
        CEF_SCHEME_OPTION_STANDARD | CEF_SCHEME_OPTION_SECURE |
        CEF_SCHEME_OPTION_CORS_ENABLED | CEF_SCHEME_OPTION_FETCH_ENABLED);
}

void ShieldTierApp::OnContextInitialized() {
    const std::string root_cache_path = shieldtier::paths::get_cache_path();

    namespace fs = std::filesystem;

    const char* renderer_path = std::getenv("SHIELDTIER_RENDERER_PATH");
    std::string renderer_dist;
    std::string shim_dir;

    if (renderer_path) {
        renderer_dist = renderer_path;
    }

    auto exe_dir = get_executable_dir();

    // Strategy: check multiple locations in priority order:
    // 1. Environment variable override (SHIELDTIER_RENDERER_PATH)
    // 2. Bundle Resources (production macOS: Contents/Resources/renderer)
    // 3. Adjacent to executable (production Linux/Windows)
    // 4. Source tree relative to exe (development)
    // 5. Source tree relative to cwd (fallback)

    std::error_code ec;  // reusable error code for weakly_canonical

    auto try_renderer = [&](const fs::path& base) -> bool {
        auto dist_path = fs::weakly_canonical(base / "renderer", ec);
        if (fs::exists(dist_path / "index.html")) {
            renderer_dist = dist_path.string();
            return true;
        }
        return false;
    };

    auto try_shim = [&](const fs::path& base) -> bool {
        auto sp = fs::weakly_canonical(base / "shim", ec);
        if (fs::exists(sp / "preload-shim.js")) {
            shim_dir = sp.string();
            return true;
        }
        return false;
    };

    if (renderer_dist.empty()) {
#if defined(OS_MAC) || defined(OS_MACOS)
        // macOS bundle: Contents/MacOS/../Resources/
        auto resources = fs::weakly_canonical(exe_dir / ".." / "Resources", ec);
        try_renderer(resources);
#endif
        // Adjacent to executable (Linux/Windows production, or macOS fallback)
        if (renderer_dist.empty()) try_renderer(exe_dir);

        // Development: source tree relative to build output
        if (renderer_dist.empty()) {
            auto project_root = fs::weakly_canonical(
                exe_dir / ".." / ".." / ".." / ".." / ".." / "..", ec);
            auto src_dist = project_root / "src" / "renderer" / "dist";
            if (fs::exists(src_dist / "index.html")) {
                renderer_dist = src_dist.string();
            }
        }

        // Last resort: cwd
        if (renderer_dist.empty()) {
            auto cwd_dist = fs::current_path() / "src" / "renderer" / "dist";
            if (fs::exists(cwd_dist / "index.html")) {
                renderer_dist = cwd_dist.string();
            }
        }
    }

    // Resolve shim directory with same priority chain
    {
#if defined(OS_MAC) || defined(OS_MACOS)
        auto resources = fs::weakly_canonical(exe_dir / ".." / "Resources", ec);
        try_shim(resources);
#endif
        if (shim_dir.empty()) try_shim(exe_dir);

        if (shim_dir.empty()) {
            auto project_root = fs::weakly_canonical(
                exe_dir / ".." / ".." / ".." / ".." / ".." / "..", ec);
            auto src_shim = project_root / "src" / "renderer" / "shim";
            if (fs::exists(src_shim / "preload-shim.js")) {
                shim_dir = src_shim.string();
            }
        }

        if (shim_dir.empty()) {
            auto cwd_shim = fs::current_path() / "src" / "renderer" / "shim";
            if (fs::exists(cwd_shim / "preload-shim.js")) {
                shim_dir = cwd_shim.string();
            }
        }
    }

    fprintf(stderr, "[ShieldTier] renderer_dist=%s exists=%d shim_dir=%s\n",
            renderer_dist.c_str(),
            fs::exists(fs::path(renderer_dist) / "index.html") ? 1 : 0,
            shim_dir.c_str());

    CefRefPtr<CefSchemeHandlerFactory> factory(
        new shieldtier::SchemeHandlerFactory(renderer_dist, shim_dir));

    CefRegisterSchemeHandlerFactory("shieldtier", "app", factory);
    fprintf(stderr, "[ShieldTier] SchemeHandlerFactory registered on global context\n");

    CefRefPtr<ShieldTierClient> client(
        new ShieldTierClient(root_cache_path));
    client->session_manager()->set_scheme_handler("shieldtier", "app", factory);

#if defined(OS_MAC) || defined(OS_MACOS)
    void* content_view = shieldtier_mac_get_content_view();
    int view_w = 0, view_h = 0;
    shieldtier_mac_get_content_bounds(&view_w, &view_h);
    client->session_manager()->set_parent_view(content_view, view_w, view_h);
#endif

    const char* dev_url = std::getenv("SHIELDTIER_DEV_URL");
    std::string initial_url = dev_url ? std::string(dev_url) : "shieldtier://app/";

    client->session_manager()->create_tab(initial_url, true, client);
}

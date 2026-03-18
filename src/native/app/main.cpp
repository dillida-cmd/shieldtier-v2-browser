#include "app/shieldtier_app.h"
#include "app/shieldtier_renderer_app.h"
#include "config/paths.h"

#include "include/cef_app.h"
#include "include/cef_command_line.h"

#if defined(OS_MAC)
#include "app/app_mac.h"
#include "include/wrapper/cef_library_loader.h"
#include <mach-o/dyld.h>
#include <filesystem>
#endif

#if defined(OS_WIN)
#include <windows.h>
#endif

#if defined(OS_WIN)

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/,
                      LPWSTR /*lpCmdLine*/, int /*nCmdShow*/) {
    CefMainArgs main_args(hInstance);

#else

int main(int argc, char* argv[]) {
    CefMainArgs main_args(argc, argv);

#endif

#if defined(OS_MAC)
    CefScopedLibraryLoader library_loader;
    if (!library_loader.LoadInMain()) {
        return 1;
    }
#endif

    CefRefPtr<ShieldTierRendererApp> renderer_app(new ShieldTierRendererApp());
    int exit_code = CefExecuteProcess(main_args, renderer_app.get(), nullptr);
    if (exit_code >= 0) {
        return exit_code;
    }

#if defined(OS_MAC)
    shieldtier_mac_init();
#endif

    CefSettings settings;
    settings.no_sandbox = true;
    settings.multi_threaded_message_loop = false;
    CefString(&settings.root_cache_path) = shieldtier::paths::get_cache_path();
    CefString(&settings.locale) = "en-US";
    settings.log_severity = LOGSEVERITY_WARNING;
    settings.remote_debugging_port = 9222;

#if defined(OS_MAC)
    {
        char exe_buf[4096];
        uint32_t exe_size = sizeof(exe_buf);
        if (_NSGetExecutablePath(exe_buf, &exe_size) == 0) {
            namespace fs = std::filesystem;
            auto exe_dir = fs::canonical(fs::path(exe_buf).parent_path());
            auto frameworks = exe_dir / ".." / "Frameworks";
            auto fw_path = fs::canonical(frameworks / "Chromium Embedded Framework.framework");
            CefString(&settings.framework_dir_path) = fw_path.string();
            // Don't set browser_subprocess_path — CEF auto-discovers variant
            // helpers (Renderer, GPU, etc.) from the Frameworks directory.
        }
    }
#endif

    CefRefPtr<ShieldTierApp> app(new ShieldTierApp());

    if (!CefInitialize(main_args, settings, app.get(), nullptr)) {
        return 1;
    }
    CefRunMessageLoop();
    CefShutdown();

    return 0;
}

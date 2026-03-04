#include "app/shieldtier_app.h"
#include "app/shieldtier_renderer_app.h"

#include "include/cef_app.h"
#include "include/cef_command_line.h"

#if defined(OS_MAC)
#include "include/wrapper/cef_library_loader.h"
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

    CefSettings settings;
    settings.no_sandbox = true;
    settings.multi_threaded_message_loop = false;
    CefString(&settings.root_cache_path) = "/tmp/shieldtier/cache";

#if defined(OS_MAC)
    // CEF framework path relative to the app bundle.
    // Resolves to: ShieldTier.app/Contents/Frameworks/Chromium Embedded Framework.framework
    CefString(&settings.framework_dir_path) =
        "../Frameworks/Chromium Embedded Framework.framework";
#endif

    CefRefPtr<ShieldTierApp> app(new ShieldTierApp());

    if (!CefInitialize(main_args, settings, app.get(), nullptr)) {
        return 1;
    }

    // Append WebRTC privacy switches after CEF is initialized
    CefRefPtr<CefCommandLine> command_line =
        CefCommandLine::GetGlobalCommandLine();
    if (command_line) {
        command_line->AppendSwitchWithValue(
            "force-webrtc-ip-handling-policy", "disable_non_proxied_udp");
        command_line->AppendSwitch("disable-webrtc-hide-local-ips-with-mdns");
    }
    CefRunMessageLoop();
    CefShutdown();

    return 0;
}

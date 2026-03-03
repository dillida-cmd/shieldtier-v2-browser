#include "app/shieldtier_app.h"

#include "include/cef_app.h"
#include "include/cef_command_line.h"

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

    int exit_code = CefExecuteProcess(main_args, nullptr, nullptr);
    if (exit_code >= 0) {
        return exit_code;
    }

    CefSettings settings;
    settings.no_sandbox = true;
    settings.multi_threaded_message_loop = false;

#if defined(OS_MAC)
    // CEF framework path relative to the app bundle.
    // Resolves to: ShieldTier.app/Contents/Frameworks/Chromium Embedded Framework.framework
    CefString(&settings.framework_dir_path) =
        "../Frameworks/Chromium Embedded Framework.framework";
#endif

    CefRefPtr<ShieldTierApp> app(new ShieldTierApp());

    CefInitialize(main_args, settings, app.get(), nullptr);
    CefRunMessageLoop();
    CefShutdown();

    return 0;
}

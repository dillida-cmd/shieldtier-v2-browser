#include "app/shieldtier_renderer_app.h"

#include "include/cef_app.h"
#include "include/wrapper/cef_library_loader.h"

#include <cstdio>
#include <unistd.h>

int main(int argc, char* argv[]) {
    // Debug: dump command-line args to temp file
    {
        char path[128];
        snprintf(path, sizeof(path), "/tmp/shieldtier_helper_%d.log", getpid());
        FILE* f = fopen(path, "w");
        if (f) {
            fprintf(f, "pid=%d ppid=%d\n", getpid(), getppid());
            for (int i = 0; i < argc; i++)
                fprintf(f, "argv[%d]=%s\n", i, argv[i]);
            fclose(f);
        }
    }

    CefScopedLibraryLoader library_loader;
    if (!library_loader.LoadInHelper()) {
        return 1;
    }

    CefMainArgs main_args(argc, argv);
    CefRefPtr<ShieldTierRendererApp> app(new ShieldTierRendererApp());

    return CefExecuteProcess(main_args, app.get(), nullptr);
}

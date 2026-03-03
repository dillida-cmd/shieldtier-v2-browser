#include "app/shieldtier_app.h"
#include "app/shieldtier_client.h"

#include "include/cef_browser.h"
#include "include/cef_command_line.h"

void ShieldTierApp::OnContextInitialized() {
    const std::string root_cache_path = "/tmp/shieldtier/cache";

    CefRefPtr<ShieldTierClient> client(
        new ShieldTierClient(root_cache_path));

    client->session_manager()->create_tab("about:blank", true, client);
}

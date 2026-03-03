#include "app/shieldtier_renderer_app.h"

void ShieldTierRendererApp::OnWebKitInitialized() {
    CefMessageRouterConfig config;
    message_router_ = CefMessageRouterRendererSide::Create(config);
}

void ShieldTierRendererApp::OnContextCreated(CefRefPtr<CefBrowser> browser,
                                             CefRefPtr<CefFrame> frame,
                                             CefRefPtr<CefV8Context> context) {
    message_router_->OnContextCreated(browser, frame, context);
}

void ShieldTierRendererApp::OnContextReleased(CefRefPtr<CefBrowser> browser,
                                              CefRefPtr<CefFrame> frame,
                                              CefRefPtr<CefV8Context> context) {
    message_router_->OnContextReleased(browser, frame, context);
}

bool ShieldTierRendererApp::OnProcessMessageReceived(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> frame,
        CefProcessId source_process,
        CefRefPtr<CefProcessMessage> message) {
    return message_router_->OnProcessMessageReceived(
        browser, frame, source_process, message);
}

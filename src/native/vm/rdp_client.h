#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "common/result.h"

namespace shieldtier {

/// Embeds an RDP client (MsRdpClient ActiveX control) inside a parent HWND.
/// Used to display Windows Sandbox desktop inside ShieldTier.
///
/// The ActiveX control MUST live on an STA thread with a message pump.
/// create() spawns a dedicated thread that runs CoInitializeEx(COINIT_APARTMENTTHREADED),
/// creates the control, and enters a GetMessage/DispatchMessage loop.
/// connect() posts a custom message to that thread to initiate the RDP connection.
/// destroy() posts WM_QUIT to exit the pump and joins the thread.
class RdpClient {
public:
    RdpClient();
    ~RdpClient();

    /// Create the RDP ActiveX control inside the given parent window.
    /// Spawns a dedicated STA thread with a message pump.
    Result<bool> create(void* parent_hwnd, int x, int y, int w, int h);

    /// Connect to an RDP server (posts WM_RDP_CONNECT to the STA thread).
    Result<bool> connect(const std::string& host, int port,
                         const std::string& username,
                         const std::string& password);

    /// Disconnect the RDP session.
    void disconnect();

    /// Resize the embedded RDP view.
    void resize(int x, int y, int w, int h);

    /// Whether the RDP session is connected.
    bool is_connected() const;

    /// Destroy the control and release COM objects.
    void destroy();

private:
#ifdef _WIN32
    void* host_hwnd_ = nullptr;      // HWND - child window that hosts the ActiveX control
    void* rdp_unknown_ = nullptr;    // IUnknown*
    void* rdp_client_ = nullptr;     // IDispatch* (IMsTscAx)
    void* ole_object_ = nullptr;     // IOleObject*
    void* container_site_ = nullptr; // MinimalSite (IOleClientSite impl)
    std::atomic<bool> connected_{false};

    // STA thread with message pump for the ActiveX control
    std::thread rdp_thread_;
    std::atomic<bool> creation_done_{false};
    std::atomic<bool> creation_ok_{false};
    std::string creation_error_;

    // Pending connection params (set before posting WM_RDP_CONNECT)
    std::string pending_host_;
    std::string pending_user_;
    std::string pending_pass_;
    int pending_port_ = 3389;
    std::atomic<bool> connect_done_{false};
    std::atomic<bool> connect_ok_{false};
    std::string connect_error_;
#endif
};

}  // namespace shieldtier

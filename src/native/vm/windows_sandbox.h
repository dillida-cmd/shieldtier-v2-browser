#pragma once

#include <atomic>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "common/json.h"
#include "common/result.h"
#include "common/types.h"
#include "vm/rdp_client.h"
#include "vm/vm_protocol.h"
#include "vm/vm_scoring.h"
#include "vm/vm_types.h"

namespace shieldtier {

/// Windows Sandbox provider — an alternative to QEMU for dynamic analysis.
/// Uses the built-in Windows Sandbox feature (.wsb config files) to run
/// samples in an ephemeral, isolated environment.  On non-Windows platforms
/// every method returns an appropriate error so the code compiles cleanly.
class WindowsSandbox {
public:
    explicit WindowsSandbox(const std::string& base_dir);
    ~WindowsSandbox();

    /// Returns true if Windows Sandbox is available on this machine.
    static bool is_available();

    /// Launch a sandbox session.  Creates a .wsb config, copies the agent
    /// script, and starts WindowsSandbox.exe.  Returns a session id.
    Result<std::string> launch(const VmConfig& config);

    /// Launch a pre-prepared session (created by prepare_session).
    Result<std::string> launch(const std::string& prepared_session_id,
                               const VmConfig& config);

    /// Prepare a session with the sample file already staged.
    /// Creates session dirs, deploys agent, writes sample.  Does NOT start
    /// the sandbox — call launch(session_id, config) after this.
    Result<std::string> prepare_session(const FileBuffer& file,
                                        bool enable_networking = true,
                                        const std::string& network_mode = "internet");

    /// Submit a file for analysis inside the running sandbox.
    /// The sample is written to the shared folder and the agent picks it up.
    Result<VmAnalysisResult> submit_sample(
        const std::string& session_id,
        const FileBuffer& file,
        int timeout_seconds = 300);

    /// Stop / destroy a running sandbox session.
    Result<bool> stop(const std::string& session_id);

    /// Check whether a session is still running.
    bool is_running(const std::string& session_id) const;

    /// Get the state of a session.
    VmState get_state(const std::string& session_id) const;

    /// Get the results directory for a session.
    std::string get_results_dir(const std::string& session_id) const;

    /// List active sessions.
    std::vector<VmInstance> list_sessions() const;

    /// Embed the sandbox window as an owned window of parent HWND.
    /// Finds the Windows Sandbox window, strips decorations, sets owner
    /// (not parent — avoids breaking RDP), and starts a reposition thread.
    Result<bool> embed_in_window(const std::string& session_id,
                                  void* parent_hwnd,
                                  int x, int y, int w, int h);

    /// Resize the embedded sandbox window.
    Result<bool> resize_embedded(const std::string& session_id,
                                  int x, int y, int w, int h);

    /// Connect an RDP client to the sandbox and embed it in parent_hwnd.
    /// This is the preferred embedding method — creates an actual RDP
    /// connection to the sandbox guest OS and renders it inside ShieldTier.
    Result<bool> connect_rdp(const std::string& session_id,
                              void* parent_hwnd,
                              int x, int y, int w, int h);

    /// Resize the RDP client view.
    void resize_rdp(const std::string& session_id,
                    int x, int y, int w, int h);

private:
    /// Generate the .wsb XML configuration file.
    std::string generate_wsb_config(
        const std::string& samples_dir,
        const std::string& results_dir,
        bool enable_networking) const;

    /// Deploy the PowerShell agent into the samples folder.
    Result<bool> deploy_agent(const std::string& samples_dir) const;

    /// Collect JSON-line events from the results folder.
    Result<std::vector<json>> collect_events(
        const std::string& results_dir) const;

    /// Wait for the agent to signal readiness.
    Result<bool> wait_for_ready(
        const std::string& results_dir, int timeout_ms) const;

    std::string generate_session_id() const;

    /// Read the sandbox IP from the results directory (written by LogonCommand).
    std::string get_sandbox_ip(const std::string& results_dir, int timeout_ms = 30000) const;

    struct Session {
        std::string id;
        VmState state = VmState::kStopped;
        VmConfig config;
        std::string session_dir;   // base dir for this session
        std::string samples_dir;   // mapped into sandbox
        std::string results_dir;   // mapped read-write, agent writes here
        std::string wsb_path;      // path to the .wsb config file
#ifdef _WIN32
        void* process_handle = nullptr;  // HANDLE
        void* sandbox_hwnd = nullptr;    // HWND of the sandbox window (for embedding)
        void* owner_hwnd = nullptr;      // HWND of ShieldTier (owner, not parent)
        long  original_style = 0;        // original window style
        long  original_exstyle = 0;      // original extended style
        std::jthread reposition_thread;  // tracks owner window position
        std::unique_ptr<RdpClient> rdp_client;  // embedded RDP view
#else
        int pid = -1;
#endif
    };

    std::string base_dir_;
    std::unordered_map<std::string, Session> sessions_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier

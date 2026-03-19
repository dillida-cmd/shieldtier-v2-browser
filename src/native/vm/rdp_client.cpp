#include "vm/rdp_client.h"

#ifdef _WIN32
#include <windows.h>
#include <ole2.h>
#include <oleidl.h>

// MsRdpClient CLSIDs — from mstscax.dll
// CLSID_MsRdpClient9NotSafeForScripting (Windows 10+)
static const CLSID CLSID_MsRdpClient9 = {
    0x8B918B82, 0x7985, 0x4C24,
    {0x89, 0xDF, 0xC3, 0x3A, 0xD2, 0xBB, 0xFB, 0xCD}
};
// Fallback: CLSID_MsRdpClientNotSafeForScripting (v2)
static const CLSID CLSID_MsRdpClient2 = {
    0x3523C2FB, 0x4031, 0x44E4,
    {0x9A, 0x3B, 0xF1, 0xE9, 0x48, 0x86, 0xEE, 0x7F}
};

// IID_IMsTscNonScriptable
static const IID IID_IMsTscNonScriptable = {
    0xC1E6743A, 0x41C1, 0x4A74,
    {0x83, 0x2A, 0x0D, 0xD0, 0x6C, 0x1C, 0x7A, 0x0E}
};

// Custom message: posted to the RDP STA thread to trigger Connect()
#define WM_RDP_CONNECT  (WM_USER + 100)
#define WM_RDP_DISCONNECT (WM_USER + 101)

// Convenience: cast void* member to typed COM pointer
#define AS_UNKNOWN  (static_cast<IUnknown*>(rdp_unknown_))
#define AS_DISP     (static_cast<IDispatch*>(rdp_client_))
#define AS_OLE      (static_cast<IOleObject*>(ole_object_))
#define AS_HWND     (static_cast<HWND>(host_hwnd_))

// ---------------------------------------------------------------------------
// Minimal OLE container — just enough to host an ActiveX control in an HWND.
// ---------------------------------------------------------------------------
class MinimalSite : public IOleClientSite, public IOleInPlaceSite, public IOleInPlaceFrame {
public:
    MinimalSite(HWND hwnd) : hwnd_(hwnd), ref_(1) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IOleClientSite)
            *ppv = static_cast<IOleClientSite*>(this);
        else if (riid == IID_IOleInPlaceSite || riid == IID_IOleWindow)
            *ppv = static_cast<IOleInPlaceSite*>(this);
        else if (riid == IID_IOleInPlaceFrame)
            *ppv = static_cast<IOleInPlaceFrame*>(this);
        else { *ppv = nullptr; return E_NOINTERFACE; }
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++ref_; }
    ULONG STDMETHODCALLTYPE Release() override {
        auto r = --ref_;
        if (r == 0) delete this;
        return r;
    }

    // IOleClientSite
    HRESULT STDMETHODCALLTYPE SaveObject() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetMoniker(DWORD, DWORD, IMoniker**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetContainer(IOleContainer** pp) override { *pp = nullptr; return E_NOINTERFACE; }
    HRESULT STDMETHODCALLTYPE ShowObject() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnShowWindow(BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RequestNewObjectLayout() override { return E_NOTIMPL; }

    // IOleWindow
    HRESULT STDMETHODCALLTYPE GetWindow(HWND* phwnd) override { *phwnd = hwnd_; return S_OK; }
    HRESULT STDMETHODCALLTYPE ContextSensitiveHelp(BOOL) override { return E_NOTIMPL; }

    // IOleInPlaceSite
    HRESULT STDMETHODCALLTYPE CanInPlaceActivate() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnInPlaceActivate() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnUIActivate() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetWindowContext(
        IOleInPlaceFrame** ppFrame, IOleInPlaceUIWindow** ppDoc,
        LPRECT prc, LPRECT prcClip, LPOLEINPLACEFRAMEINFO pfi) override {
        *ppFrame = static_cast<IOleInPlaceFrame*>(this); AddRef();
        *ppDoc = nullptr;
        GetClientRect(hwnd_, prc);
        *prcClip = *prc;
        pfi->cb = sizeof(OLEINPLACEFRAMEINFO);
        pfi->fMDIApp = FALSE;
        pfi->hwndFrame = hwnd_;
        pfi->haccel = nullptr;
        pfi->cAccelEntries = 0;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Scroll(SIZE) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE OnUIDeactivate(BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnInPlaceDeactivate() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE DiscardUndoState() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DeactivateAndUndo() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE OnPosRectChange(LPCRECT) override { return S_OK; }

    // IOleInPlaceFrame
    HRESULT STDMETHODCALLTYPE InsertMenus(HMENU, LPOLEMENUGROUPWIDTHS) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetMenu(HMENU, HOLEMENU, HWND) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE RemoveMenus(HMENU) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetStatusText(LPCOLESTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE EnableModeless(BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE TranslateAccelerator(LPMSG, WORD) override { return S_FALSE; }
    HRESULT STDMETHODCALLTYPE GetBorder(LPRECT r) override { GetClientRect(hwnd_, r); return S_OK; }
    HRESULT STDMETHODCALLTYPE RequestBorderSpace(LPCBORDERWIDTHS) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetBorderSpace(LPCBORDERWIDTHS) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetActiveObject(IOleInPlaceActiveObject*, LPCOLESTR) override { return S_OK; }

private:
    HWND hwnd_;
    std::atomic<ULONG> ref_;
};

// ---------------------------------------------------------------------------
// IDispatch helpers — call MsRdpClient methods by name (avoids .tlh import).
// ---------------------------------------------------------------------------
namespace {

HRESULT put_bstr(IDispatch* d, LPCOLESTR name, const wchar_t* val) {
    DISPID id;
    HRESULT hr = d->GetIDsOfNames(IID_NULL, const_cast<LPOLESTR*>(&name), 1, LOCALE_SYSTEM_DEFAULT, &id);
    if (FAILED(hr)) return hr;
    VARIANT v; VariantInit(&v); v.vt = VT_BSTR; v.bstrVal = SysAllocString(val);
    DISPID put = DISPID_PROPERTYPUT;
    DISPPARAMS p = {&v, &put, 1, 1};
    hr = d->Invoke(id, IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYPUT, &p, nullptr, nullptr, nullptr);
    SysFreeString(v.bstrVal);
    return hr;
}

HRESULT put_long(IDispatch* d, LPCOLESTR name, long val) {
    DISPID id;
    HRESULT hr = d->GetIDsOfNames(IID_NULL, const_cast<LPOLESTR*>(&name), 1, LOCALE_SYSTEM_DEFAULT, &id);
    if (FAILED(hr)) return hr;
    VARIANT v; VariantInit(&v); v.vt = VT_I4; v.lVal = val;
    DISPID put = DISPID_PROPERTYPUT;
    DISPPARAMS p = {&v, &put, 1, 1};
    return d->Invoke(id, IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYPUT, &p, nullptr, nullptr, nullptr);
}

HRESULT call(IDispatch* d, LPCOLESTR name) {
    DISPID id;
    HRESULT hr = d->GetIDsOfNames(IID_NULL, const_cast<LPOLESTR*>(&name), 1, LOCALE_SYSTEM_DEFAULT, &id);
    if (FAILED(hr)) return hr;
    DISPPARAMS p = {};
    return d->Invoke(id, IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_METHOD, &p, nullptr, nullptr, nullptr);
}

HRESULT get_disp(IDispatch* d, LPCOLESTR name, IDispatch** out) {
    DISPID id;
    HRESULT hr = d->GetIDsOfNames(IID_NULL, const_cast<LPOLESTR*>(&name), 1, LOCALE_SYSTEM_DEFAULT, &id);
    if (FAILED(hr)) return hr;
    VARIANT v; VariantInit(&v); DISPPARAMS p = {};
    hr = d->Invoke(id, IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYGET, &p, &v, nullptr, nullptr);
    if (SUCCEEDED(hr) && v.vt == VT_DISPATCH) { *out = v.pdispVal; return S_OK; }
    VariantClear(&v); return E_FAIL;
}

static const wchar_t* kHostClass = L"ShieldTierRdpHost";
static bool g_class_registered = false;

// Store a back-pointer to the RdpClient in GWLP_USERDATA so that the
// WndProc can handle WM_RDP_CONNECT on the correct STA thread.
struct RdpHostData {
    void* rdp_client;  // shieldtier::RdpClient*
};

}  // namespace

// Forward declare the WndProc (needs access to RdpClient internals via friend
// or — simpler — we handle it via a static helper called from the proc).
static LRESULT CALLBACK RdpHostProc(HWND h, UINT m, WPARAM w, LPARAM l);

namespace {

void ensure_class(HINSTANCE hi) {
    if (g_class_registered) return;
    WNDCLASSEXW wc = {}; wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = RdpHostProc; wc.hInstance = hi; wc.lpszClassName = kHostClass;
    wc.cbWndExtra = sizeof(void*);  // space for RdpClient*
    RegisterClassExW(&wc);
    g_class_registered = true;
}

std::wstring utf8_to_wide(const std::string& s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring ws(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), len);
    return ws;
}

}  // namespace

// ---------------------------------------------------------------------------
// RdpHostProc — handles WM_RDP_CONNECT on the STA thread.
// ---------------------------------------------------------------------------
static LRESULT CALLBACK RdpHostProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_RDP_CONNECT) {
        // The RdpClient* was stored in GWLP_USERDATA during create().
        auto* self = reinterpret_cast<shieldtier::RdpClient*>(
            GetWindowLongPtrW(h, GWLP_USERDATA));
        if (!self) return 0;

        // Access pending connection params via the opaque pointer.
        // We use a small trick: cast to a struct that mirrors the private
        // layout.  Instead, we use a static helper function declared as
        // a friend — but the simplest approach is to do the actual COM
        // connect work right here using the void* members.
        //
        // Since we can't easily access private members from a free function,
        // we post a lambda-like approach: the LPARAM carries a pointer to
        // a callable.  See connect() below.
        auto* fn = reinterpret_cast<std::function<void()>*>(l);
        if (fn) {
            (*fn)();
            delete fn;
        }
        return 0;
    }
    if (m == WM_RDP_DISCONNECT) {
        auto* fn = reinterpret_cast<std::function<void()>*>(l);
        if (fn) {
            (*fn)();
            delete fn;
        }
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}
#endif  // _WIN32

namespace shieldtier {

RdpClient::RdpClient() = default;
RdpClient::~RdpClient() { destroy(); }

// ---------------------------------------------------------------------------
// create — spawn a dedicated STA thread with a message pump
// ---------------------------------------------------------------------------
Result<bool> RdpClient::create(void* parent_hwnd, int x, int y, int w, int h) {
#ifndef _WIN32
    (void)parent_hwnd; (void)x; (void)y; (void)w; (void)h;
    return Error{"RDP client only available on Windows", "UNSUPPORTED"};
#else
    if (host_hwnd_) return Error{"Already created", "ALREADY_CREATED"};

    creation_done_.store(false);
    creation_ok_.store(false);
    creation_error_.clear();

    HWND parent = static_cast<HWND>(parent_hwnd);

    rdp_thread_ = std::thread([this, parent, x, y, w, h]() {
        // Initialize COM as STA on this thread — required for ActiveX.
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        HINSTANCE hi = GetModuleHandleW(nullptr);
        ensure_class(hi);

        // Create the host child window on THIS thread so its message pump
        // is on this thread.
        HWND hwnd = CreateWindowExW(0, kHostClass, L"",
            WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
            x, y, w, h, parent, nullptr, hi, nullptr);
        if (!hwnd) {
            creation_error_ = "Failed to create host window";
            creation_done_.store(true);
            CoUninitialize();
            return;
        }
        host_hwnd_ = hwnd;

        // Store this pointer in GWLP_USERDATA for WndProc access.
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));

        // Create MsRdpClient COM object.
        IUnknown* unk = nullptr;
        HRESULT hr = CoCreateInstance(CLSID_MsRdpClient9, nullptr,
            CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
            IID_IUnknown, reinterpret_cast<void**>(&unk));
        if (FAILED(hr)) {
            hr = CoCreateInstance(CLSID_MsRdpClient2, nullptr,
                CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
                IID_IUnknown, reinterpret_cast<void**>(&unk));
        }
        if (FAILED(hr)) {
            fprintf(stderr, "[RDP] CoCreateInstance failed: 0x%08lX\n", hr);
            DestroyWindow(hwnd); host_hwnd_ = nullptr;
            creation_error_ = "CoCreateInstance MsRdpClient failed";
            creation_done_.store(true);
            CoUninitialize();
            return;
        }
        rdp_unknown_ = unk;

        // Get IOleObject and set our container site.
        IOleObject* ole = nullptr;
        hr = unk->QueryInterface(IID_IOleObject, reinterpret_cast<void**>(&ole));
        if (FAILED(hr)) {
            fprintf(stderr, "[RDP] QI(IOleObject) failed: 0x%08lX\n", hr);
            unk->Release(); rdp_unknown_ = nullptr;
            DestroyWindow(hwnd); host_hwnd_ = nullptr;
            creation_error_ = "QI IOleObject failed";
            creation_done_.store(true);
            CoUninitialize();
            return;
        }
        ole_object_ = ole;

        auto* site = new MinimalSite(hwnd);
        container_site_ = site;
        ole->SetClientSite(site);

        // In-place activate the control.
        RECT rc; GetClientRect(hwnd, &rc);
        hr = ole->DoVerb(OLEIVERB_INPLACEACTIVATE, nullptr, site, 0, hwnd, &rc);
        fprintf(stderr, "[RDP] DoVerb(INPLACEACTIVATE) hr=0x%08lX\n", hr);

        // Get IDispatch for property access.
        IDispatch* disp = nullptr;
        unk->QueryInterface(IID_IDispatch, reinterpret_cast<void**>(&disp));
        rdp_client_ = disp;

        fprintf(stderr, "[RDP] ActiveX control created on STA thread, HWND=%p\n", host_hwnd_);

        // Signal success to the calling thread.
        creation_ok_.store(true);
        creation_done_.store(true);

        // ====== MESSAGE PUMP — the critical missing piece ======
        // Without this loop, the ActiveX control can't process WM_PAINT,
        // mouse/keyboard input, or our custom WM_RDP_CONNECT messages.
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        // Cleanup COM objects on this thread (where they were created).
        if (ole_object_) {
            static_cast<IOleObject*>(ole_object_)->Close(OLECLOSE_NOSAVE);
            static_cast<IOleObject*>(ole_object_)->Release();
            ole_object_ = nullptr;
        }
        if (rdp_client_) {
            static_cast<IDispatch*>(rdp_client_)->Release();
            rdp_client_ = nullptr;
        }
        if (rdp_unknown_) {
            static_cast<IUnknown*>(rdp_unknown_)->Release();
            rdp_unknown_ = nullptr;
        }
        if (container_site_) {
            static_cast<MinimalSite*>(container_site_)->Release();
            container_site_ = nullptr;
        }
        if (host_hwnd_) {
            DestroyWindow(static_cast<HWND>(host_hwnd_));
            host_hwnd_ = nullptr;
        }

        CoUninitialize();
        fprintf(stderr, "[RDP] STA thread exiting\n");
    });

    // Wait for the STA thread to finish creating the control.
    while (!creation_done_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (!creation_ok_.load()) {
        if (rdp_thread_.joinable()) rdp_thread_.join();
        return Error{creation_error_, "CREATE_FAILED"};
    }

    return true;
#endif
}

// ---------------------------------------------------------------------------
// connect — post WM_RDP_CONNECT to the STA thread
// ---------------------------------------------------------------------------
Result<bool> RdpClient::connect(const std::string& host, int port,
                                 const std::string& username,
                                 const std::string& password) {
#ifndef _WIN32
    (void)host; (void)port; (void)username; (void)password;
    return Error{"Not supported", "UNSUPPORTED"};
#else
    if (!rdp_client_ || !host_hwnd_) return Error{"Not created", "NOT_CREATED"};

    connect_done_.store(false);
    connect_ok_.store(false);
    connect_error_.clear();

    // Store connection params — the STA thread will read them.
    pending_host_ = host;
    pending_port_ = port;
    pending_user_ = username;
    pending_pass_ = password;

    // Capture pointers for the lambda that will run on the STA thread.
    auto* fn = new std::function<void()>([this]() {
        IDispatch* disp = static_cast<IDispatch*>(rdp_client_);
        IUnknown* unk = static_cast<IUnknown*>(rdp_unknown_);

        auto wh = utf8_to_wide(pending_host_);
        auto wu = utf8_to_wide(pending_user_);

        HRESULT hr = put_bstr(disp, L"Server", wh.c_str());
        fprintf(stderr, "[RDP] Server='%s' hr=0x%08lX\n", pending_host_.c_str(), hr);

        hr = put_bstr(disp, L"UserName", wu.c_str());
        fprintf(stderr, "[RDP] UserName='%s' hr=0x%08lX\n", pending_user_.c_str(), hr);

        // AdvancedSettings
        IDispatch* adv = nullptr;
        if (SUCCEEDED(get_disp(disp, L"AdvancedSettings", &adv)) && adv) {
            put_long(adv, L"RDPPort", pending_port_);
            put_long(adv, L"EnableCredSspSupport", 1);
            put_long(adv, L"AuthenticationLevel", 0);
            adv->Release();
        }

        // Password via IMsTscNonScriptable vtable.
        IUnknown* ns = nullptr;
        hr = unk->QueryInterface(IID_IMsTscNonScriptable, reinterpret_cast<void**>(&ns));
        if (SUCCEEDED(hr) && ns) {
            typedef HRESULT(STDMETHODCALLTYPE* PutPassFn)(IUnknown*, BSTR);
            void** vt = *reinterpret_cast<void***>(ns);
            auto pfn = reinterpret_cast<PutPassFn>(vt[3]);
            auto wp = utf8_to_wide(pending_pass_);
            BSTR bp = SysAllocString(wp.c_str());
            hr = pfn(ns, bp);
            SysFreeString(bp);
            fprintf(stderr, "[RDP] ClearTextPassword hr=0x%08lX\n", hr);
            ns->Release();
        } else {
            fprintf(stderr, "[RDP] No IMsTscNonScriptable hr=0x%08lX\n", hr);
        }

        hr = call(disp, L"Connect");
        fprintf(stderr, "[RDP] Connect() hr=0x%08lX\n", hr);

        if (SUCCEEDED(hr)) {
            connected_.store(true);
            connect_ok_.store(true);
        } else {
            connect_error_ = "Connect failed";
        }
        connect_done_.store(true);
    });

    // Post to the STA thread — the WndProc will invoke the lambda.
    PostMessage(AS_HWND, WM_RDP_CONNECT, 0, reinterpret_cast<LPARAM>(fn));

    // Wait for the connection to complete (with timeout).
    int waited = 0;
    while (!connect_done_.load() && waited < 30000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        waited += 50;
    }

    if (!connect_done_.load()) {
        return Error{"Connect timed out", "CONNECT_TIMEOUT"};
    }
    if (!connect_ok_.load()) {
        return Error{connect_error_, "CONNECT_FAILED"};
    }
    return true;
#endif
}

void RdpClient::disconnect() {
#ifdef _WIN32
    if (rdp_client_ && host_hwnd_ && connected_.load()) {
        auto* fn = new std::function<void()>([this]() {
            call(static_cast<IDispatch*>(rdp_client_), L"Disconnect");
            connected_.store(false);
        });
        PostMessage(AS_HWND, WM_RDP_DISCONNECT, 0, reinterpret_cast<LPARAM>(fn));
        // Wait briefly for disconnect to complete.
        for (int i = 0; i < 100 && connected_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
#endif
}

void RdpClient::resize(int x, int y, int w, int h) {
#ifdef _WIN32
    if (host_hwnd_) MoveWindow(AS_HWND, x, y, w, h, TRUE);
#endif
}

bool RdpClient::is_connected() const { return connected_.load(); }

void RdpClient::destroy() {
#ifdef _WIN32
    // Disconnect first.
    if (connected_.load()) {
        disconnect();
    }

    // Post WM_QUIT to exit the message pump, then join the thread.
    if (host_hwnd_ && rdp_thread_.joinable()) {
        PostMessage(AS_HWND, WM_QUIT, 0, 0);
        rdp_thread_.join();
        // The STA thread handles all COM cleanup in its exit path.
    } else if (rdp_thread_.joinable()) {
        rdp_thread_.join();
    }

    // Clear member pointers (already released by the STA thread).
    ole_object_ = nullptr;
    rdp_client_ = nullptr;
    rdp_unknown_ = nullptr;
    container_site_ = nullptr;
    host_hwnd_ = nullptr;
#endif
}

}  // namespace shieldtier

#include <windows.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <iomanip>
#include <shlwapi.h>
#include <sstream>
#include <string>
#include <vector>
#include <wincrypt.h>

// MainWindow.cpp — minimal, didactic example showing NineAuth C++ SDK usage
#include "MainWindow.hpp"
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <algorithm>
#include <windows.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <iomanip>
#include <shlwapi.h>
#include <sstream>
#include <string>
#include <vector>
#include <wincrypt.h>

#include "MainWindow.hpp"

#include "../NineAuth-CPP-EXAMPLE/client.hpp"
#include "../NineAuth-CPP-EXAMPLE/options.hpp"


#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// Helpers: wide <-> UTF-8 conversion
static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty())
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr,
        nullptr);
    std::string s(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), len, nullptr,
        nullptr);
    return s;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty())
        return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), len);
    return w;
}

// Device fingerprint (reads MachineGuid and hashes it)
std::string MainWindow::CreateDeviceFingerprint() {
    // Read MachineGuid from registry (stable across reboots and user sessions)
    char guidBuf[128]{};
    DWORD guidSize = sizeof(guidBuf);
    RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography",
        "MachineGuid", RRF_RT_REG_SZ, nullptr, guidBuf, &guidSize);

    const std::string input =
        (guidBuf[0] != '\0') ? std::string(guidBuf)
        : std::string(MAX_COMPUTERNAME_LENGTH + 1, '\0');

    if (guidBuf[0] == '\0') {
        DWORD sz = MAX_COMPUTERNAME_LENGTH + 1;
        GetComputerNameA(const_cast<char*>(input.c_str()), &sz);
    }

    // SHA-256 via Windows Cryptography Next Generation (CNG) — zero external deps
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD cbHashObj = 0, cbData = 0;
    DWORD cbHash = 0;
    std::vector<BYTE> hashObj, hashBuf;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObj,
        sizeof(DWORD), &cbData, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD),
        &cbData, 0);

    hashObj.resize(cbHashObj);
    hashBuf.resize(cbHash);

    BCryptCreateHash(hAlg, &hHash, hashObj.data(), cbHashObj, nullptr, 0, 0);
    BCryptHashData(hHash, (PBYTE)input.c_str(), (ULONG)input.size(), 0);
    BCryptFinishHash(hHash, hashBuf.data(), cbHash, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (BYTE b : hashBuf)
        ss << std::setw(2) << (int)b;
    return ss.str();
}

// ============================================================================
// Constructor
// ============================================================================
MainWindow::MainWindow(HINSTANCE hInstance)
    : m_hInstance(hInstance),
    m_client(nineauth::Options{
        APPLICATION_ID,             // application_id (set in MainWindow.hpp)
        "https://api.nineauth.xyz", // api_url
        "production",               // environment
        30                          // timeout_seconds
        }),
    m_deviceFingerprint(CreateDeviceFingerprint()) {
}

// ============================================================================
// Create window + register class
// ============================================================================
bool MainWindow::Create() {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = m_hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"NineAuthCppExampleClass";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    m_hwnd = CreateWindowExW(
        0, L"NineAuthCppExampleClass", L"NineAuth — Acesso por licenca  [C++]",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT,
        CW_USEDEFAULT, 680, 420, nullptr, nullptr, m_hInstance, this);

    return m_hwnd != nullptr;
}

void MainWindow::Show(int nCmdShow) {
    ShowWindow(m_hwnd, nCmdShow);
    UpdateWindow(m_hwnd);
}

// ============================================================================
// WndProc — static dispatcher
// ============================================================================
LRESULT CALLBACK MainWindow::WndProc(HWND hwnd, UINT msg, WPARAM wp,
    LPARAM lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        auto* self = reinterpret_cast<MainWindow*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->m_hwnd = hwnd;
    }
    auto* self =
        reinterpret_cast<MainWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (self)
        return self->HandleMessage(msg, wp, lp);
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ============================================================================
// Message handler
// ============================================================================
LRESULT MainWindow::HandleMessage(UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        OnCreate(m_hwnd);
        // Initialize NineAuth after window is up so the status label is visible
        DoInitialize();
        return 0;

    case WM_COMMAND:
        OnCommand(LOWORD(wp));
        return 0;

    case WM_NOTIFY: {
        auto* hdr = reinterpret_cast<NMHDR*>(lp);
        if (hdr->idFrom == ID_TAB && hdr->code == TCN_SELCHANGE)
            OnTabChange();
        return 0;
    }

    case WM_DESTROY:
        // Revoke server-side session on close if authenticated
        if (m_client.IsAuthenticated()) {
            m_client.Logout(); // best-effort; ignore result
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(m_hwnd, msg, wp, lp);
}

// ============================================================================
// OnCreate — build all controls
// ============================================================================
void MainWindow::OnCreate(HWND hwnd) {
    HFONT hFontTitle =
        CreateFontW(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH, L"Segoe UI");
    HFONT hFontNormal =
        CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH, L"Segoe UI");

    // Title
    m_hTitleLabel = CreateWindowW(L"STATIC", L"NineAuth — Acesso por licença",
        WS_CHILD | WS_VISIBLE, 20, 16, 600, 30, hwnd,
        nullptr, m_hInstance, nullptr);
    SendMessageW(m_hTitleLabel, WM_SETFONT, (WPARAM)hFontTitle, TRUE);

    // Status bar
    m_hStatusLabel = CreateWindowW(L"STATIC", L"A inicializar NineAuth…",
        WS_CHILD | WS_VISIBLE, 23, 52, 620, 20, hwnd,
        nullptr, m_hInstance, nullptr);
    SendMessageW(m_hStatusLabel, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

    // Tab control
    m_hTabCtrl = CreateWindowW(
        WC_TABCONTROLW, nullptr,
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_FIXEDWIDTH, 16, 80, 636,
        286, hwnd, (HMENU)(UINT_PTR)ID_TAB, m_hInstance, nullptr);
    SendMessageW(m_hTabCtrl, WM_SETFONT, (WPARAM)hFontNormal, TRUE);
    SendMessageW(m_hTabCtrl, TCM_SETITEMSIZE, 0, MAKELPARAM(210, 28));

    auto AddTab = [&](const wchar_t* label) {
        TCITEMW item{};
        item.mask = TCIF_TEXT;
        item.pszText = const_cast<wchar_t*>(label);
        SendMessageW(m_hTabCtrl, TCM_INSERTITEMW,
            SendMessageW(m_hTabCtrl, TCM_GETITEMCOUNT, 0, 0),
            (LPARAM)&item);
        };
    AddTab(L"Conta");
    AddTab(L"Licença");
    AddTab(L"Área Protegida");

    // -------------------------------------------------------------------------
    // Tab 0 — Account controls
    // -------------------------------------------------------------------------
    m_hEmailEdit = CreateWindowW(
        L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 36,
        120, 380, 28, hwnd, nullptr, m_hInstance, nullptr);
    SendMessageW(m_hEmailEdit, EM_SETCUEBANNER, TRUE, (LPARAM)L"Email");
    SendMessageW(m_hEmailEdit, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

    m_hPasswordEdit = CreateWindowW(
        L"EDIT", nullptr,
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, 36, 160,
        380, 28, hwnd, nullptr, m_hInstance, nullptr);
    SendMessageW(m_hPasswordEdit, EM_SETCUEBANNER, TRUE,
        (LPARAM)L"Palavra-passe");
    SendMessageW(m_hPasswordEdit, EM_SETPASSWORDCHAR, 0x25CF, 0); // ●
    SendMessageW(m_hPasswordEdit, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

    m_hLoginBtn = CreateWindowW(
        L"BUTTON", L"Entrar", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 36, 204,
        182, 34, hwnd, (HMENU)(UINT_PTR)ID_LOGIN, m_hInstance, nullptr);
    SendMessageW(m_hLoginBtn, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

    m_hRegisterBtn = CreateWindowW(
        L"BUTTON", L"Criar conta", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 230,
        204, 186, 34, hwnd, (HMENU)(UINT_PTR)ID_REGISTER, m_hInstance, nullptr);
    SendMessageW(m_hRegisterBtn, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

    // -------------------------------------------------------------------------
    // Tab 1 — License controls (hidden initially)
    // -------------------------------------------------------------------------
    m_hLicenseEdit =
        CreateWindowW(L"EDIT", nullptr, WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 36,
            120, 380, 28, hwnd, nullptr, m_hInstance, nullptr);
    SendMessageW(m_hLicenseEdit, EM_SETCUEBANNER, TRUE,
        (LPARAM)L"Chave de licença (ex: XXXX-YYYY-ZZZZ-WWWW)");
    SendMessageW(m_hLicenseEdit, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

    m_hActivateBtn = CreateWindowW(
        L"BUTTON", L"Ativar neste dispositivo", WS_CHILD | BS_DEFPUSHBUTTON, 36,
        160, 380, 34, hwnd, (HMENU)(UINT_PTR)ID_ACTIVATE, m_hInstance, nullptr);
    SendMessageW(m_hActivateBtn, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

    m_hLogoutBtn = CreateWindowW(
        L"BUTTON", L"Terminar sessão", WS_CHILD | BS_PUSHBUTTON, 36, 208, 380, 30,
        hwnd, (HMENU)(UINT_PTR)ID_LOGOUT, m_hInstance, nullptr);
    SendMessageW(m_hLogoutBtn, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

    // -------------------------------------------------------------------------
    // Tab 2 — Protected area label (hidden initially)
    // -------------------------------------------------------------------------
    m_hAccessLabel = CreateWindowW(
        L"STATIC", L"Área protegida\r\n\r\nAtive uma licença para continuar.",
        WS_CHILD | SS_CENTER, 36, 110, 590, 220, hwnd, nullptr, m_hInstance,
        nullptr);
    SendMessageW(m_hAccessLabel, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

    // Show tab 0 controls by default
    ShowWindow(m_hEmailEdit, SW_SHOW);
    ShowWindow(m_hPasswordEdit, SW_SHOW);
    ShowWindow(m_hLoginBtn, SW_SHOW);
    ShowWindow(m_hRegisterBtn, SW_SHOW);
}

// ============================================================================
// Tab switching
// ============================================================================
void MainWindow::OnTabChange() {
    int tab = (int)SendMessageW(m_hTabCtrl, TCM_GETCURSEL, 0, 0);

    // Hide everything first
    ShowWindow(m_hEmailEdit, SW_HIDE);
    ShowWindow(m_hPasswordEdit, SW_HIDE);
    ShowWindow(m_hLoginBtn, SW_HIDE);
    ShowWindow(m_hRegisterBtn, SW_HIDE);
    ShowWindow(m_hLicenseEdit, SW_HIDE);
    ShowWindow(m_hActivateBtn, SW_HIDE);
    ShowWindow(m_hLogoutBtn, SW_HIDE);
    ShowWindow(m_hAccessLabel, SW_HIDE);

    switch (tab) {
    case 0:
        ShowWindow(m_hEmailEdit, SW_SHOW);
        ShowWindow(m_hPasswordEdit, SW_SHOW);
        ShowWindow(m_hLoginBtn, SW_SHOW);
        ShowWindow(m_hRegisterBtn, SW_SHOW);
        break;
    case 1:
        ShowWindow(m_hLicenseEdit, SW_SHOW);
        ShowWindow(m_hActivateBtn, SW_SHOW);
        ShowWindow(m_hLogoutBtn, SW_SHOW);
        break;
    case 2:
        ShowWindow(m_hAccessLabel, SW_SHOW);
        break;
    }
    m_activeTab = tab;
}

// ============================================================================
// Button dispatcher
// ============================================================================
void MainWindow::OnCommand(WORD id) {
    switch (id) {
    case ID_LOGIN:
        DoLogin();
        break;
    case ID_REGISTER:
        DoRegister();
        break;
    case ID_ACTIVATE:
        DoActivateLicense();
        break;
    case ID_LOGOUT:
        DoLogout();
        break;
    }
}

// NineAuth SDK calls — UI → SDK → update UI

// ---------------------------------------------------------------------------
// Initialize — verifies the Application ID and loads metadata.
// Called automatically on window creation.
// ---------------------------------------------------------------------------
void MainWindow::DoInitialize() {
    SetAllEnabled(false);

    auto result = m_client.Initialize();

    if (!result.success) {
        // Common error: APPLICATION_ID is empty or wrong
        SetStatus(L"Falha ao inicializar: " + Utf8ToWide(result.error_message) +
            L" [" + Utf8ToWide(result.error_code) + L"]",
            false);
        return;
    }

    SetStatus(L"Pronto. Entre para ativar a sua licença.  (" +
        Utf8ToWide(m_client.GetApplicationInfo().name) + L")");
    SetAllEnabled(true);
}

// ---------------------------------------------------------------------------
// Login — authenticates user with email + password.
// The SDK automatically attaches a cryptographic nonce and timestamp
// to prevent replay attacks. You never handle this yourself.
// ---------------------------------------------------------------------------
void MainWindow::DoLogin() {
    const std::string email = GetTextA(m_hEmailEdit);
    const std::string password = GetTextA(m_hPasswordEdit);

    if (email.empty() || password.empty()) {
        SetStatus(L"Preencha o email e a palavra-passe.", false);
        return;
    }

    SetAllEnabled(false);
    SetStatus(L"A autenticar…");

    // STEP 2: Call Login with email, password, and device fingerprint
    auto result = m_client.Login(email, password, m_deviceFingerprint);

    if (!result.success) {
        SetStatus(L"[" + Utf8ToWide(result.error_code) + L"] " +
            Utf8ToWide(result.error_message),
            false);
        SetAllEnabled(true);
        return;
    }

    SetStatus(L"Sessão iniciada. Introduza a sua chave de licença.");
    SetAllEnabled(true);

    // Navigate to the License tab
    SendMessageW(m_hTabCtrl, TCM_SETCURSEL, 1, 0);
    OnTabChange();
}

// ---------------------------------------------------------------------------
// Register — creates a new user account for this application.
// ---------------------------------------------------------------------------
void MainWindow::DoRegister() {
    const std::string email = GetTextA(m_hEmailEdit);
    const std::string password = GetTextA(m_hPasswordEdit);

    if (email.empty() || password.empty()) {
        SetStatus(L"Preencha o email e a palavra-passe.", false);
        return;
    }

    SetAllEnabled(false);
    SetStatus(L"A criar conta…");

    auto result = m_client.Register(email, password);

    if (!result.success) {
        SetStatus(L"[" + Utf8ToWide(result.error_code) + L"] " +
            Utf8ToWide(result.error_message),
            false);
        SetAllEnabled(true);
        return;
    }

    SetStatus(L"Conta criada. Agora entre com as mesmas credenciais.");
    SetAllEnabled(true);
}

// ---------------------------------------------------------------------------
// ActivateLicense — binds a license key to this device.
// After activation, ValidateSession is called to confirm the session
// and retrieve the granted entitlements (feature flags).
// ---------------------------------------------------------------------------
void MainWindow::DoActivateLicense() {
    const std::string licenseKey = GetTextA(m_hLicenseEdit);

    if (licenseKey.empty()) {
        SetStatus(L"Introduza a chave de licença.", false);
        return;
    }

    SetAllEnabled(false);
    SetStatus(L"A ativar licença…");

    // STEP 2: Activate license — automatically cryptographically signed
    auto actResult = m_client.ActivateLicense(licenseKey, m_deviceFingerprint);

    if (!actResult.success) {
        SetStatus(L"[" + Utf8ToWide(actResult.error_code) + L"] " +
            Utf8ToWide(actResult.error_message),
            false);
        SetAllEnabled(true);
        return;
    }

    // STEP 3: Validate session to get current entitlements
    auto valResult = m_client.ValidateSession();

    if (!valResult.success || !valResult.value.valid) {
        SetStatus(L"Licença ativa mas sessão inválida. Tente novamente.", false);
        SetAllEnabled(true);
        return;
    }

    // STEP 4: Check a specific entitlement (zero network latency — reads local
    // cache)
    bool hasPro = m_client.HasEntitlement("pro_access");

    // Build the info string for the protected area
    std::wstring info = L"✓ Acesso autorizado\r\n\r\n";
    info += L"Licença: " + Utf8ToWide(actResult.value.license.status) + L"\r\n";
    if (!actResult.value.license.expires_at.empty())
        info +=
        L"Expira: " + Utf8ToWide(actResult.value.license.expires_at) + L"\r\n";
    info += L"\r\nPermissões: ";
    for (size_t i = 0; i < valResult.value.entitlements.size(); ++i) {
        if (i > 0)
            info += L", ";
        info += Utf8ToWide(valResult.value.entitlements[i]);
    }
    if (hasPro)
        info += L"\r\n\r\n[pro_access] confirmado localmente (0ms)";

    SetWindowTextW(m_hAccessLabel, info.c_str());

    SetStatus(L"Licença ativa neste dispositivo.");
    SetAllEnabled(true);

    m_licenseActivated = true;

    // Navigate to Protected tab
    SendMessageW(m_hTabCtrl, TCM_SETCURSEL, 2, 0);
    OnTabChange();
}

// ---------------------------------------------------------------------------
// Logout — revokes the session on the server and clears local state.
// ---------------------------------------------------------------------------
void MainWindow::DoLogout() {
    SetAllEnabled(false);
    SetStatus(L"A terminar sessão…");

    m_client.Logout(); // best-effort — clear local state even if network fails

    SetWindowTextW(m_hAccessLabel,
        L"Área protegida\r\n\r\nAtive uma licença para continuar.");
    m_licenseActivated = false;

    SetStatus(L"Sessão terminada.");
    SetAllEnabled(true);

    // Return to Account tab
    SendMessageW(m_hTabCtrl, TCM_SETCURSEL, 0, 0);
    OnTabChange();
}

// ============================================================================
// UI helpers
// ============================================================================
std::wstring MainWindow::GetText(HWND ctrl) const {
    int len = GetWindowTextLengthW(ctrl);
    if (len <= 0)
        return {};
    std::wstring buf(len + 1, L'\0');
    GetWindowTextW(ctrl, buf.data(), len + 1);
    buf.resize(len);
    return buf;
}

std::string MainWindow::GetTextA(HWND ctrl) const {
    return WideToUtf8(GetText(ctrl));
}

void MainWindow::SetStatus(const std::wstring& msg, bool success) {
    SetWindowTextW(m_hStatusLabel, msg.c_str());
    // Green for success, red for error — same visual convention as the C# example
    COLORREF color = success ? RGB(46, 125, 50) : RGB(198, 40, 40);
    // Subclass static to custom-paint color (simple SetTextColor approach via
    // WM_CTLCOLORSTATIC)
    SetPropW(m_hStatusLabel, L"StatusColor", (HANDLE)(LONG_PTR)color);
    InvalidateRect(m_hStatusLabel, nullptr, TRUE);
}

void MainWindow::SetAllEnabled(bool enabled) {
    EnableWindow(m_hEmailEdit, enabled);
    EnableWindow(m_hPasswordEdit, enabled);
    EnableWindow(m_hLoginBtn, enabled);
    EnableWindow(m_hRegisterBtn, enabled);
    EnableWindow(m_hLicenseEdit, enabled);
    EnableWindow(m_hActivateBtn, enabled);
    EnableWindow(m_hLogoutBtn, enabled);
}

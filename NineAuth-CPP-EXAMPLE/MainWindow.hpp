// =============================================================================
// MainWindow.hpp — NineAuth C++ SDK Example
// Declares the main window class: all controls, state, and handlers.
// =============================================================================
#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <string>

#include "../NineAuth-CPP-EXAMPLE/client.hpp"
#include "../NineAuth-CPP-EXAMPLE/options.hpp"

// ---------------------------------------------------------------------------
// STEP 1: Set your Application ID here.
// Get it from the NineAuth dashboard → Applications → your app → App ID.
// ---------------------------------------------------------------------------
static constexpr const char* APPLICATION_ID = "APPLICATION_ID AQUI";  // ← coloca aqui o teu Application ID

class MainWindow {
public:
    explicit MainWindow(HINSTANCE hInstance);

    bool   Create();
    void   Show(int nCmdShow);
    HWND   GetHandle() const { return m_hwnd; }

private:
    // -------------------------------------------------------------------------
    // Win32 plumbing
    // -------------------------------------------------------------------------
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
    LRESULT HandleMessage(UINT msg, WPARAM wp, LPARAM lp);

    void OnCreate(HWND hwnd);
    void OnCommand(WORD id);
    void OnTabChange();

    // -------------------------------------------------------------------------
    // NineAuth handlers — one per SDK operation
    // -------------------------------------------------------------------------
    void DoInitialize();
    void DoLogin();
    void DoRegister();
    void DoActivateLicense();
    void DoLogout();

    // -------------------------------------------------------------------------
    // UI helpers
    // -------------------------------------------------------------------------
    std::wstring GetText(HWND ctrl) const;
    std::string  GetTextA(HWND ctrl) const;
    void         SetStatus(const std::wstring& msg, bool success = true);
    void         SetAllEnabled(bool enabled);
    void         ShowProtectedTab();
    void         HideProtectedTab();

    // Compute a stable device fingerprint from the Windows MachineGuid.
    // SHA-256 of the GUID → 64 hex chars.
    static std::string CreateDeviceFingerprint();

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------
    HINSTANCE           m_hInstance{};
    HWND                m_hwnd{};

    // Controls
    HWND m_hTabCtrl{};
    HWND m_hStatusLabel{};
    HWND m_hTitleLabel{};

    // Tab 0 — Account
    HWND m_hEmailEdit{};
    HWND m_hPasswordEdit{};
    HWND m_hLoginBtn{};
    HWND m_hRegisterBtn{};

    // Tab 1 — License
    HWND m_hLicenseEdit{};
    HWND m_hActivateBtn{};
    HWND m_hLogoutBtn{};

    // Tab 2 — Protected area
    HWND m_hAccessLabel{};

    // Control IDs
    enum : WORD {
        ID_TAB = 100,
        ID_LOGIN = 201,
        ID_REGISTER = 202,
        ID_ACTIVATE = 203,
        ID_LOGOUT = 204,
    };

    // NineAuth client
    nineauth::NineAuthClient m_client;
    std::string              m_deviceFingerprint;

    // Track active tab (0 = Account, 1 = License, 2 = Protected)
    int m_activeTab{ 0 };
    bool m_licenseActivated{ false };
};

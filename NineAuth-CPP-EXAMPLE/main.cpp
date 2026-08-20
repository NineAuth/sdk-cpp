// =============================================================================
// main.cpp — NineAuth C++ SDK Example
// Entry point: registers the window class and starts the message loop.
// =============================================================================
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commctrl.h>

#include "MainWindow.hpp"

#pragma comment(lib, "comctl32.lib")

// Enable Common Controls v6 (visual styles — rounded buttons, modern font)
#pragma comment(linker, \
    "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' " \
    "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    // Initialise Common Controls so tab controls and modern buttons render correctly.
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_TAB_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    MainWindow window(hInstance);
    if (!window.Create()) {
        MessageBoxW(nullptr, L"Falha ao criar janela.", L"Erro", MB_ICONERROR);
        return 1;
    }

    window.Show(nCmdShow);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        // IsDialogMessage lets Tab/Enter/Escape work naturally across controls.
        if (!IsDialogMessage(window.GetHandle(), &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    return static_cast<int>(msg.wParam);
}

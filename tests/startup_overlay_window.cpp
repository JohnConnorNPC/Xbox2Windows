#include "startup_stubs/overlay_window.h"

#include <cstdio>

int main()
{
    WNDCLASSW wc{};
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpfnWndProc = DefWindowProcW;
    wc.lpszClassName = x2w_startup::presenter_class;
    if (!RegisterClassW(&wc)) return 1;
    // Offscreen, unactivated windows exercise the real z-order enumerator.
    const auto make = [&](const wchar_t* name, HWND owner, bool visible) {
        HWND hwnd = CreateWindowExW(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, name, L"", WS_POPUP,
                                    -32000, -32000, 8, 8, owner, nullptr, wc.hInstance, nullptr);
        if (hwnd && visible) ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        return hwnd;
    };
    HWND output = make(wc.lpszClassName, nullptr, true);
    HWND hidden = make(L"STATIC", nullptr, false);
    HWND owned = make(L"STATIC", output, true);
    if (!output || !hidden || !owned || x2w_startup::overlay_window()) return 2;
    HWND guest = make(L"STATIC", nullptr, true);
    if (!guest || x2w_startup::overlay_window() != guest) return 3;
    if (!SetWindowPos(output, HWND_TOP, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE) ||
        x2w_startup::overlay_window() != guest) return 4;
    // With two guests the enumeration stops at the first match, so the upper one is selected
    // in either order. Continuing to the end would select the lower one.
    HWND second = make(L"STATIC", nullptr, true);
    const auto raise = [](HWND hwnd) {
        return SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
    };
    if (!second || !raise(guest) || x2w_startup::overlay_window() != guest) return 6;
    if (!raise(second) || x2w_startup::overlay_window() != second) return 7;
    DestroyWindow(second);
    DestroyWindow(guest);
    if (x2w_startup::overlay_window()) return 5;
    // X2W_HIDE_TITLE_WINDOW: the switch is off unless it is 1 (negative controls first).
    SetEnvironmentVariableA("X2W_HIDE_TITLE_WINDOW", nullptr);
    if (x2w_startup::hide_title_window_requested()) return 8;
    SetEnvironmentVariableA("X2W_HIDE_TITLE_WINDOW", "0");
    if (x2w_startup::hide_title_window_requested()) return 9;
    SetEnvironmentVariableA("X2W_HIDE_TITLE_WINDOW", "1");
    if (!x2w_startup::hide_title_window_requested()) return 10;
    // Only the guest is hidden: the presenter, a window it owns and a dialog stay visible.
    HWND title = make(L"STATIC", nullptr, true);
    HWND dialog = make(x2w_startup::dialog_class, nullptr, true);
    if (!title || !dialog || !IsWindowVisible(title) || !IsWindowVisible(dialog)) return 11;
    if (x2w_startup::hide_title_windows() != 1 || IsWindowVisible(title)) return 12;
    if (!IsWindowVisible(output) || !IsWindowVisible(owned) || !IsWindowVisible(dialog)) return 13;
    // Shown again by the title, hidden again by the next call; nothing left to hide after that.
    ShowWindow(title, SW_SHOWNOACTIVATE);
    if (x2w_startup::hide_title_windows() != 1 || IsWindowVisible(title)) return 14;
    if (x2w_startup::hide_title_windows() != 0) return 15;
    DestroyWindow(dialog);
    DestroyWindow(title);
    DestroyWindow(owned);
    DestroyWindow(hidden);
    DestroyWindow(output);
    std::puts("GDI overlay selected the guest below or above the presenter and the upper of two guests; "
              "no target after guest destruction; X2W_HIDE_TITLE_WINDOW=1 only: hid the guest twice, "
              "kept the presenter, its owned window and a dialog visible");
    return 0;
}

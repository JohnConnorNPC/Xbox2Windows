#pragma once

#include <windows.h>

#include <vector>

namespace x2w_startup {
inline constexpr wchar_t presenter_class[] = L"X2WOutputWindow";
inline constexpr wchar_t dialog_class[] = L"#32770";  // message boxes and assert dialogs

// A top-level window the title made: visible, unowned, in this process, not the presenter.
inline bool is_title_window(HWND candidate, wchar_t (&name)[256])
{
    DWORD process = 0;
    GetWindowThreadProcessId(candidate, &process);
    if (process != GetCurrentProcessId() || !IsWindowVisible(candidate) || GetWindow(candidate, GW_OWNER))
        return false;
    return GetClassNameW(candidate, name, 256) && lstrcmpW(name, presenter_class) != 0;
}

inline HWND overlay_window()
{
    HWND window = nullptr;
    EnumWindows([](HWND candidate, LPARAM out) -> BOOL {
        wchar_t name[256]{};
        if (!is_title_window(candidate, name))
            return TRUE;
        *reinterpret_cast<HWND*>(out) = candidate;
        return FALSE;
    }, reinterpret_cast<LPARAM>(&window));
    return window;
}

// X2W_HIDE_TITLE_WINDOW=1 (docs/startup-runtime.md#switches). Read on each call.
inline bool hide_title_window_requested()
{
    char value[8]{};
    return GetEnvironmentVariableA("X2W_HIDE_TITLE_WINDOW", value, sizeof(value)) && value[0] == '1';
}

// Hides the title's own top-level windows, except dialogs, which must stay where they can be seen
// and answered. Returns how many were hidden; *had_foreground tells whether one of them was the
// foreground window, so the caller can hand keyboard focus to a window of this process.
inline int hide_title_windows(bool* had_foreground = nullptr)
{
    std::vector<HWND> found;
    EnumWindows([](HWND candidate, LPARAM out) -> BOOL {
        wchar_t name[256]{};
        if (is_title_window(candidate, name) && lstrcmpW(name, dialog_class) != 0)
            reinterpret_cast<std::vector<HWND>*>(out)->push_back(candidate);
        return TRUE;
    }, reinterpret_cast<LPARAM>(&found));
    const HWND foreground = GetForegroundWindow();
    if (had_foreground) *had_foreground = false;
    for (HWND window : found) {
        if (had_foreground && window == foreground) *had_foreground = true;
        ShowWindow(window, SW_HIDE);
    }
    return static_cast<int>(found.size());
}
}  // namespace x2w_startup

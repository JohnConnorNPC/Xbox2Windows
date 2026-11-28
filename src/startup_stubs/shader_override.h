// Shader overrides of a patch manifest (docs/experiments/patch-manifests.md#shader-overrides): which translation
// lookups go to X2W_PATCH_SHADER_DIR instead of the shader cache. tools/startup/debug_launch.py copies a manifest's
// checked files into one directory as <key><ext> and names it to the child in that variable. No device:
// tests/startup_shader_override_lookup_check.cpp drives it; d3d12_draw.inl's cache_path asks it first.
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <iterator>
#include <unordered_map>

namespace x2w_startup {

enum class ShaderOverride { none, overridden, refused };

// One lookup's answer and what the caller logs. Each (key, extension) of an overridden key is logged at its first
// lookup; the directory that does not fit MAX_PATH is logged once per ShaderOverrides.
struct ShaderOverrideLookup {
    ShaderOverride result = ShaderOverride::none;
    bool log_found = false;     // first lookup of this (key, extension), and the file is there
    bool log_missing = false;   // first lookup of this (key, extension), and the file is not: the load fails
    bool log_unusable = false;  // first refusal because "<dir>\<key>.mesh86.txt" does not fit MAX_PATH
};

// A key is overridden when <key>.txt or <key>.mesh86.txt is in the directory at the key's first lookup. That answer
// is kept for the rest of the process: every later lookup of the key, of any extension, goes to the same place, even
// if the directory changes in between, so one key's files never come from both. A file missing from an overridden
// key stays missing (no cache fallback). The file bytes are not checked here: debug_launch.py hashes each copy when
// it writes it, and nothing checks them again during the run.
class ShaderOverrides {
public:
    // out: a MAX_PATH buffer. overridden: out names <dir>\<key><extension>, which may not exist. none: use the cache
    // (out is then scratch). refused: the directory path is too long; the lookup fails without the cache.
    ShaderOverrideLookup lookup(wchar_t* out, std::uint64_t key, const wchar_t* extension)
    {
        ShaderOverrideLookup found;
        wchar_t dir[MAX_PATH];
        const DWORD n = GetEnvironmentVariableW(L"X2W_PATCH_SHADER_DIR", dir, MAX_PATH);
        if (!n) return found;
        const auto name = [&](const wchar_t* ext) {
            return n < MAX_PATH &&
                   swprintf(out, MAX_PATH, L"%ls\\%016llx%ls", dir, static_cast<unsigned long long>(key), ext) >= 0;
        };
        const auto refuse = [&] {
            found.result = ShaderOverride::refused;
            found.log_unusable = InterlockedExchange(&unusable_logged_, 1) == 0;
            return found;
        };
        // The longest name of a key decides for every extension (tools/startup/patch_manifest.py SHADER_DIR_MAX).
        if (!name(L".mesh86.txt")) return refuse();
        static const wchar_t* const extensions[] = {L".txt", L".vs.cso", L".ps.cso", L".cs.cso", L".mesh86.txt", L".ms.cso"};
        unsigned bit = static_cast<unsigned>(std::size(extensions));
        for (unsigned i = 0; i < std::size(extensions); ++i)
            if (!wcscmp(extension, extensions[i])) bit = i;
        bool owned = false, first = false;
        {
            Guard guard(lock_);
            auto [entry, fresh] = keys_.try_emplace(key);
            if (fresh)  // out holds <dir>\<key>.mesh86.txt
                entry->second.owned = GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES ||
                                      (name(L".txt") && GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES);
            owned = entry->second.owned;
            if (owned) {
                first = !(entry->second.logged & (1u << bit));
                entry->second.logged |= 1u << bit;
            }
        }
        if (!owned) return found;
        if (!name(extension)) return refuse();
        const bool present = GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES;
        found.result = ShaderOverride::overridden;
        found.log_found = first && present;
        found.log_missing = first && !present;
        return found;
    }

private:
    struct Key {
        bool owned = false;
        unsigned logged = 0;  // one bit per extension (the last for any other extension)
    };
    class Guard {
    public:
        explicit Guard(SRWLOCK& lock) noexcept : lock_(lock) { AcquireSRWLockExclusive(&lock_); }
        ~Guard() { ReleaseSRWLockExclusive(&lock_); }
        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;

    private:
        SRWLOCK& lock_;
    };
    SRWLOCK lock_ = SRWLOCK_INIT;
    std::unordered_map<std::uint64_t, Key> keys_;
    LONG unusable_logged_ = 0;
};

}  // namespace x2w_startup

// Checks src/startup_stubs/shader_override.h without a device: which translation lookups X2W_PATCH_SHADER_DIR takes
// from the shader cache's place (#3037, docs/experiments/patch-manifests.md#shader-overrides). Files are written to a
// fresh directory under %TEMP%, and the directory is changed between lookups of one key. Cases:
// - without the variable, no lookup is redirected;
// - <key>.txt overrides the key: every extension is looked up in the directory, each (key, extension) logged once,
//   and a missing file stays missing instead of coming from the cache;
// - the answer is kept for the process: an overridden key stays overridden after its .txt is removed, and a key
//   that was not overridden at its first lookup stays with the cache after override files appear;
// - <key>.mesh86.txt overrides a key too, a stage file alone does not;
// - a directory of 231 characters fits (the longest name, <dir>\<key>.mesh86.txt, is 259); 232 characters and a
//   value longer than MAX_PATH refuse every lookup, logged once.
#include "startup_stubs/shader_override.h"

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <string>
#include <vector>

namespace {
int failures, lookups;
std::wstring root;
std::vector<std::wstring> written;

void check(const char* name, bool condition)
{
    if (condition) return;
    ++failures;
    std::printf("FAIL %s\n", name);
}

std::wstring file_name(std::uint64_t key, const wchar_t* extension)
{
    wchar_t name[64];
    std::swprintf(name, 64, L"%016llx%ls", static_cast<unsigned long long>(key), extension);
    return root + L"\\" + name;
}

void put(std::uint64_t key, const wchar_t* extension)
{
    const std::wstring path = file_name(key, extension);
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD wrote = 0;
    const bool ok = file != INVALID_HANDLE_VALUE && WriteFile(file, "x", 1, &wrote, nullptr) && wrote == 1;
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (!ok) {
        std::printf("FAIL setup: cannot write %ls\n", path.c_str());
        std::exit(1);
    }
    written.push_back(path);
}

void erase_file(std::uint64_t key, const wchar_t* extension)
{
    if (!DeleteFileW(file_name(key, extension).c_str())) {
        std::printf("FAIL setup: cannot delete %ls\n", file_name(key, extension).c_str());
        std::exit(1);
    }
}

// One lookup against the expected answer, path and log flags.
void expect(const char* name, x2w_startup::ShaderOverrides& overrides, std::uint64_t key, const wchar_t* extension,
            x2w_startup::ShaderOverride result, bool logged = false, bool missing = false, bool unusable = false)
{
    ++lookups;
    wchar_t out[MAX_PATH] = L"";
    const x2w_startup::ShaderOverrideLookup found = overrides.lookup(out, key, extension);
    bool ok = found.result == result && found.log_found == logged && found.log_missing == missing &&
              found.log_unusable == unusable;
    if (result == x2w_startup::ShaderOverride::overridden) ok = ok && file_name(key, extension) == out;
    if (!ok)
        std::printf("  %s: %016llx%ls -> result %d found %d missing %d unusable %d path %ls\n", name,
                    static_cast<unsigned long long>(key), extension, static_cast<int>(found.result), found.log_found,
                    found.log_missing, found.log_unusable, out);
    check(name, ok);
}
}  // namespace

int main()
{
    using x2w_startup::ShaderOverride;
    wchar_t temp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp)) return std::printf("FAIL setup: no temporary directory\n"), 1;
    root = std::wstring(temp) + L"x2w_shader_override_" + std::to_wstring(GetCurrentProcessId());
    if (!CreateDirectoryW(root.c_str(), nullptr)) return std::printf("FAIL setup: cannot create %ls\n", root.c_str()), 1;
    const std::uint64_t txt_key = 0x00c0ffee0badf00dull, gone_key = 0x0123456789abcdefull, late_key = 0xfedcba9876543210ull,
                        mesh_key = 0x1111222233334444ull, stage_key = 0x5555666677778888ull;
    put(txt_key, L".txt");
    put(txt_key, L".cs.cso");
    put(gone_key, L".txt");
    put(gone_key, L".cs.cso");
    put(mesh_key, L".mesh86.txt");
    put(mesh_key, L".ms.cso");
    put(stage_key, L".cs.cso");

    SetEnvironmentVariableW(L"X2W_PATCH_SHADER_DIR", nullptr);
    {
        x2w_startup::ShaderOverrides overrides;
        expect("no variable: the cache", overrides, txt_key, L".txt", ShaderOverride::none);
    }

    SetEnvironmentVariableW(L"X2W_PATCH_SHADER_DIR", root.c_str());
    x2w_startup::ShaderOverrides overrides;
    expect(".txt overrides: .txt found", overrides, txt_key, L".txt", ShaderOverride::overridden, true);
    expect(".txt overrides: logged once", overrides, txt_key, L".txt", ShaderOverride::overridden);
    expect(".txt overrides: .cs.cso found", overrides, txt_key, L".cs.cso", ShaderOverride::overridden, true);
    expect(".txt overrides: a missing .vs.cso is not taken from the cache", overrides, txt_key, L".vs.cso",
           ShaderOverride::overridden, false, true);
    expect(".txt overrides: the missing file logged once", overrides, txt_key, L".vs.cso", ShaderOverride::overridden);

    expect("kept: first lookup of an overridden key", overrides, gone_key, L".txt", ShaderOverride::overridden, true);
    erase_file(gone_key, L".txt");
    expect("kept: still overridden after its .txt is removed", overrides, gone_key, L".cs.cso", ShaderOverride::overridden,
           true);
    expect("kept: the removed .txt is missing, not cached", overrides, gone_key, L".txt", ShaderOverride::overridden);
    expect("kept: first lookup of a key without overrides", overrides, late_key, L".txt", ShaderOverride::none);
    put(late_key, L".txt");
    put(late_key, L".cs.cso");
    expect("kept: override files that appear later are not used", overrides, late_key, L".cs.cso", ShaderOverride::none);
    expect("kept: nor its later .txt", overrides, late_key, L".txt", ShaderOverride::none);

    expect(".mesh86.txt overrides: .ms.cso found first", overrides, mesh_key, L".ms.cso", ShaderOverride::overridden, true);
    expect("a stage file alone does not override", overrides, stage_key, L".cs.cso", ShaderOverride::none);

    const std::wstring fits(231, L'd'), too_long(232, L'd'), past(MAX_PATH + 40, L'd');
    {
        x2w_startup::ShaderOverrides lengths;
        SetEnvironmentVariableW(L"X2W_PATCH_SHADER_DIR", fits.c_str());
        expect("a directory of 231 characters fits", lengths, txt_key, L".mesh86.txt", ShaderOverride::none);
        SetEnvironmentVariableW(L"X2W_PATCH_SHADER_DIR", too_long.c_str());
        expect("a directory of 232 characters refuses, logged", lengths, txt_key, L".txt", ShaderOverride::refused, false,
               false, true);
        expect("a directory of 232 characters refuses, logged once", lengths, txt_key, L".txt", ShaderOverride::refused);
    }
    {
        x2w_startup::ShaderOverrides lengths;
        SetEnvironmentVariableW(L"X2W_PATCH_SHADER_DIR", past.c_str());
        expect("a value past MAX_PATH refuses, logged", lengths, txt_key, L".txt", ShaderOverride::refused, false, false,
               true);
    }

    SetEnvironmentVariableW(L"X2W_PATCH_SHADER_DIR", nullptr);
    for (const std::wstring& path : written) DeleteFileW(path.c_str());
    if (!RemoveDirectoryW(root.c_str())) std::printf("note: %ls was not removed\n", root.c_str());
    if (lookups != 18) check("every lookup case ran (18)", false);
    if (failures) {
        std::printf("startup_shader_override_lookup: FAIL (%d of %d lookups)\n", failures, lookups);
        return 1;
    }
    std::printf("startup_shader_override_lookup: PASS (18 lookups: no variable; <key>.txt overrides every extension, "
                "logged once each, a missing file not taken from the cache; the answer kept per key when the directory "
                "changes; <key>.mesh86.txt overrides, a stage file alone does not; 231 characters fit, 232 and past "
                "MAX_PATH refuse, logged once)\n");
    return 0;
}

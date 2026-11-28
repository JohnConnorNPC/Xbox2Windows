// Input for tests/startup_patch_memory_check.py (stage 2 memory patches; docs/experiments/patch-manifests.md).
// x2w_patch_marker is a 16-byte array in .rdata. A TLS callback, the first code of this image that the
// loader runs, copies it at DLL_PROCESS_ATTACH. main then prints that copy and the live array as hex,
// and whether X2W_DATA_PATCH_MAP reached the process, and exits 0. No other input is involved.
#include <windows.h>

#include <cstdio>

extern "C" const volatile unsigned char x2w_patch_marker[16] = {'X', '2', 'W', '-', 'P', 'A', 'T', 'C',
                                                                'H', '-', 'M', 'A', 'R', 'K', '0', '1'};

namespace {
unsigned char tls_copy[16];
volatile bool tls_ran;

void NTAPI on_tls(PVOID, DWORD reason, PVOID)
{
    if (reason != DLL_PROCESS_ATTACH)
        return;
    for (int i = 0; i < 16; ++i)
        tls_copy[i] = x2w_patch_marker[i];
    tls_ran = true;
}

void print_hex(const char* label, const volatile unsigned char* bytes)
{
    std::printf("patch-probe %s ", label);
    for (int i = 0; i < 16; ++i)
        std::printf("%02x", bytes[i]);
    std::printf("\n");
}
}  // namespace

// The TLS directory (_tls_used, from the C runtime) lists the callbacks placed in .CRT$XL*.
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:x2w_patch_tls")
#pragma const_seg(".CRT$XLB")
extern "C" const PIMAGE_TLS_CALLBACK x2w_patch_tls = on_tls;
#pragma const_seg()

int main()
{
    if (!tls_ran) {
        std::printf("patch-probe the TLS callback did not run\n");
        return 1;
    }
    print_hex("tls", tls_copy);
    print_hex("live", x2w_patch_marker);
    const bool map = GetEnvironmentVariableA("X2W_DATA_PATCH_MAP", nullptr, 0) != 0;
    std::printf("patch-probe data-patch map %s\n", map ? "present" : "absent");
    std::fflush(stdout);
    return 0;
}

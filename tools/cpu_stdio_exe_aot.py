"""Translate a return-based PE32+ console entry and its reachable functions with UCRT stdio imports."""
import argparse
import hashlib
from pathlib import Path

import pefile

from cpu_leaf_aot import export_rva
from cpu_switch_aot import HostImport, PRELUDE, Program, load_bindings


STDIO = "api-ms-win-crt-stdio-l1-1-0.dll"
IMPORTS = {
    (STDIO, b"getchar"): HostImport("host_getchar", (), 4),
    (STDIO, b"putchar"): HostImport("host_putchar", (4,), 4),
    (STDIO, b"fflush"): HostImport("host_fflush", (8,), 4),
}
# Called only by the shared native startup wrapper, which stays outside a lifted entry export.
STARTUP_ONLY = ("cpu_exe_io.dll", b"finish_exe")
HOST = """
#include <cstdio>
static word host_getchar() { return static_cast<unsigned>(std::getchar()); }
static word host_putchar(word ch) { return static_cast<unsigned>(std::putchar(static_cast<int>(ch))); }
static word host_fflush(word stream) {
    return static_cast<unsigned>(std::fflush(reinterpret_cast<std::FILE*>(stream)));
}
"""


def record_reads(pe, reads):
    """Appends (rva, end) to reads for every read of pe's section bytes (pefile's SectionStructure.get_data,
    behind pe.get_data, cpu_ranges.image_bytes and get_string_at_rva) from now on."""
    def recorder(section, get_data):
        def get(start=None, length=None, ignore_padding=False):
            found = get_data(start, length, ignore_padding)
            rva = section.get_VirtualAddress_adj() if start is None else start
            reads.append((rva, rva + len(found)))
            return found
        return get
    for section in pe.sections:
        section.get_data = recorder(section, section.get_data)


def translate(image, bindings=IMPORTS, host=HOST, *, allow_process_exit=False, entry_export=None,
              data=None, ranges=None, image_sha256=None, reads=None):
    """data, when given, is lifted instead of the bytes at image (a patched copy, tools/exe_aot.py
    --patches); image_sha256 then names the original input. A range manifest (ranges, as for
    cpu_switch_aot.py --bind-ranges) and aot_source_sha256 both refer to that original. reads, a list,
    collects the (rva, end) of every section read of the translation (record_reads)."""
    if data is None:
        data = Path(image).read_bytes()
    with pefile.PE(data=data, fast_load=True) as pe:
        if reads is not None:
            record_reads(pe, reads)
        opt = pe.OPTIONAL_HEADER
        if (pe.FILE_HEADER.Machine != 0x8664 or opt.Magic != 0x20b or opt.Subsystem != 3
                or not pe.FILE_HEADER.Characteristics & 2 or pe.FILE_HEADER.Characteristics & 0x2000):
            raise ValueError("expected an AMD64 console EXE")
        for index, name in ((9, "TLS startup"), (13, "delay imports")):
            if len(opt.DATA_DIRECTORY) > index and opt.DATA_DIRECTORY[index].VirtualAddress:
                raise ValueError(f"unsupported {name} in console EXE")
        pe.parse_data_directories(directories=[1])
        imports = {}
        seen_slots = set()
        for module in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = module.dll.decode("ascii").lower()
            for imp in module.imports:
                slot = imp.address - opt.ImageBase
                if slot in seen_slots:
                    raise ValueError(f"duplicate import slot {slot:#x}")
                seen_slots.add(slot)
                key = (dll, imp.name)
                binding = bindings.get(key)
                # The native startup wrapper is outside the lifted body. A call
                # from the body still fails when this slot has no binding.
                if binding is None and entry_export is not None and key == STARTUP_ONLY:
                    continue
                if binding is None:
                    symbol = imp.name.decode("ascii") if imp.name else f"#{imp.ordinal}"
                    raise ValueError(f"unbound console import {dll}!{symbol}")
                imports[slot] = binding
        program = Program(pe, None if ranges is None else load_bindings(ranges), imports=imports,
                          image_sha256=image_sha256)
        entry = opt.AddressOfEntryPoint if entry_export is None else export_rva(pe, entry_export)
        if entry not in program.entries:
            raise ValueError(f"unverified process entry at RVA {entry:#x}")
        source, function = program.lift(entry, "process_entry", ())
        reaches_exit = allow_process_exit and any(call.noreturn for call in function.host_calls.values())
        if (function.return_width is None and not reaches_exit
                or function.return_width is not None and function.return_width < 4):
            raise ValueError("process entry must define its 32-bit exit code")
        provenance = []
        if entry_export is not None:
            digest = image_sha256 or hashlib.sha256(data).hexdigest()
            provenance.append(f'extern "C" __declspec(dllexport) const char aot_source_sha256[] = "{digest}";')
        return "\n".join([PRELUDE, host, *program.sources, source, *provenance,
                          "int main() { return static_cast<int>(process_entry()); }", ""])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--entry-export", help="Lift a returning entry exported separately from PE startup")
    args = parser.parse_args(argv)
    try:
        args.output.write_text(translate(args.image, entry_export=args.entry_export), encoding="ascii")
    except (ValueError, OSError, pefile.PEFormatError) as exc:
        parser.exit(1, f"{exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

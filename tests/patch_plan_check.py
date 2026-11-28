"""Checks tools/startup/patch_plan.py: a manifest loaded through tools/patch_manifest.py (every loader
refusal raised as a PatchError with its reason), the planner's own rules (id form, kinds, byte and
patch caps), the input hash gate, and the stage 2 memory-patch plan, apply, report and environment
rules. tests/patch_manifest_check.py checks the loader itself.

The schema input is a synthetic PE32+ built here (headers, .text, .data, .reloc with one DIR64 entry
and one ABSOLUTE pad); the first case parses it back and checks that layout. The plan input is a
second synthetic PE32+ with an import table, a TLS directory, a load configuration, a section whose
file bytes run past its VirtualSize, one whose VirtualSize runs past its file bytes, and two base
relocation blocks (DIR64, HIGHLOW, ABSOLUTE); its own case parses it back too. Manifests are written
to a temporary directory. Every refusal case is a negative control: the manifest must be refused
whole, with the reason named. The hash gate is checked with a hash that differs from the right one
only in its last hex digit and only in its first, so a gate that compares a prefix or a suffix
fails here. Fixture hashes contain letters, so the loader's lowercase-only rule is reached.
apply_memory runs against a fake process (bytes in a bytearray) whose writes are counted. Needs
Python 3.11+ (tomllib).
"""
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "tools", "startup")
LOADER = os.path.normpath(os.path.join(HERE, "..", "tools", "patch_manifest.py"))
sys.path.insert(0, TOOLS)
import patch_plan as pm  # noqa: E402

# Every case below is counted; a case that is removed or never reached fails the check.
EXPECTED_CASES = 54 + 71
IMAGE_BASE = 0x140000000
DIR64, HIGHLOW, ABSOLUTE = 10, 3, 0
LOADED_BASE = 0x7FF6_1234_0000


def build_pe(sections, directories, size_of_image=None):
    """A minimal AMD64 PE32+ image. sections: (name, rva, body, flags[, virtual size[, raw size]]);
    the raw size defaults to the body rounded up to the file alignment, the virtual size to the body.
    directories: {index: (rva, size)}."""
    file_align, section_align = 0x200, 0x1000
    opt = 0x98
    size_of_headers = -(-(opt + 0xF0 + 40 * len(sections)) // file_align) * file_align
    headers = bytearray(size_of_headers)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", headers, 0x84, 0x8664, len(sections), 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<HBBIIIII", headers, opt, 0x20B, 14, 0, 0x200, 0x400, 0, 0x1000, 0x1000)
    struct.pack_into("<QII", headers, opt + 24, IMAGE_BASE, section_align, file_align)
    struct.pack_into("<HHHHHH", headers, opt + 40, 6, 0, 0, 0, 6, 0)
    last = sections[-1]
    if size_of_image is None:
        size_of_image = -(-(last[1] + (last[4] if len(last) > 4 else len(last[2]))) // section_align) * section_align
    struct.pack_into("<IIII", headers, opt + 52, 0, size_of_image, size_of_headers, 0)
    struct.pack_into("<HH", headers, opt + 68, 3, 0x0160)  # console; ASLR, high-entropy VA, NX
    struct.pack_into("<QQQQII", headers, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    for index, (rva, size) in directories.items():
        struct.pack_into("<II", headers, opt + 112 + 8 * index, rva, size)
    image = bytearray(headers)
    for i, (name, rva, body, flags, *sizes) in enumerate(sections):
        vsize = sizes[0] if sizes else len(body)
        raw_size = sizes[1] if len(sizes) > 1 else max(file_align, -(-len(body) // file_align) * file_align)
        raw = len(image)
        image += body.ljust(raw_size, b"\0")
        struct.pack_into("<8sIIIIIIHHI", image, opt + 0xF0 + 40 * i, name, vsize, rva, raw_size, raw,
                         0, 0, 0, 0, flags)
    return bytes(image)


def synthetic_pe():
    """The A1 input: .text (ret), .data (16 marker bytes, one pointer), .reloc (DIR64 + pad)."""
    return build_pe([(b".text", 0x1000, b"\xc3" + b"\xcc" * 15, 0x60000020),
                     (b".data", 0x2000, bytes(range(0x40, 0x50)) + struct.pack("<Q", IMAGE_BASE + 0x2000), 0xC0000040),
                     (b".reloc", 0x3000, struct.pack("<IIHH", 0x2000, 12, (DIR64 << 12) | 0x10, ABSOLUTE << 12),
                      0x42000040)], {5: (0x3000, 12)})


def check_synthetic_pe(data):
    """Parses the fixture back with offsets from the PE/COFF specification and checks its layout."""
    assert data[:2] == b"MZ", "no MZ signature"
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0", "no PE signature at e_lfanew"
    machine, count, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
    assert (machine, count, opt_size) == (0x8664, 3, 0xF0), (machine, count, opt_size)
    opt = pe + 24
    assert struct.unpack_from("<H", data, opt)[0] == 0x20B, "not PE32+"
    image_base, section_align, file_align = struct.unpack_from("<QII", data, opt + 24)
    size_of_image, size_of_headers = struct.unpack_from("<II", data, opt + 56)
    assert (image_base, size_of_headers) == (IMAGE_BASE, 0x200)
    assert struct.unpack_from("<I", data, opt + 108)[0] == 16, "NumberOfRvaAndSizes"
    sections = {}
    end = size_of_headers
    for i in range(count):
        name, vsize, va, raw_size, raw = struct.unpack_from("<8sIIII", data, opt + opt_size + 40 * i)
        assert va % section_align == 0 and raw % file_align == 0 and raw_size % file_align == 0, name
        assert raw >= end and raw + raw_size <= len(data) and 0 < vsize <= raw_size, name
        end = raw + raw_size
        sections[name.rstrip(b"\0")] = (va, vsize, raw)
    assert list(sections) == [b".text", b".data", b".reloc"], list(sections)
    assert size_of_image == sections[b".reloc"][0] + section_align, "SizeOfImage"
    reloc_rva, reloc_size = struct.unpack_from("<II", data, opt + 112 + 8 * 5)
    va, vsize, raw = sections[b".reloc"]
    assert (reloc_rva, reloc_size) == (va, vsize), "base relocation directory is not the .reloc section"
    page, block = struct.unpack_from("<II", data, raw)
    entries = [(e >> 12, e & 0xFFF) for e in struct.unpack_from("<HH", data, raw + 8)]
    assert (page, block, entries) == (0x2000, 12, [(DIR64, 0x10), (ABSOLUTE, 0)]), (page, block, entries)
    va, _, raw = sections[b".data"]
    pointer = struct.unpack_from("<Q", data, raw + page + 0x10 - va)[0]
    assert pointer == IMAGE_BASE + 0x2000, "the DIR64 slot does not hold an image address"


def loader_pe(reloc_type=ABSOLUTE, delay=False, config_size=0x140, reloc=None, second_import=False, import_size=40,
              tls_size=40, config_dir_size=None, delay_size=64):
    """The plan input. .text: 0x40 bytes in a 0x200 raw block, a DIR64 slot at 0x1020.
    .rdata (0x1000 bytes, so it ends where .data starts): import descriptor at 0x2000 (name table
    0x2040, address table 0x2060, one import), TLS directory at 0x2100 (index slot 0x3000), free
    bytes 0x2300-0x23ff, load configuration at 0x2400 (`config_size` bytes; security cookie 0x3008,
    guard check 0x3010, guard dispatch 0x3018, XFG check/dispatch/table dispatch 0x3060/0x3068/0x3070,
    CastGuard mode 0x3078, guard memcpy 0x3080). .data: 0x300 virtual over 0x200 raw, DIR64 slot
    0x3020, HIGHLOW 0x3028, free bytes 0x3040-0x305f. .reloc: block 1 page 0x3000 (DIR64, HIGHLOW,
    two ABSOLUTE), block 2 page 0x1000 (DIR64 at 0x1020, then `reloc_type` at page+0: ABSOLUTE
    padding by default); `reloc` replaces the whole directory. `second_import` adds a second descriptor at
    0x2014 (name table 0x2040, address table 0x20c0) before the null one at 0x2028; `import_size` is the
    import directory's Size; `tls_size`, `config_dir_size` (default `config_size`) and `delay_size` are the
    other directories' Size fields."""
    text = bytearray(b"\xc3" + b"\xcc" * 0x3F)
    struct.pack_into("<Q", text, 0x20, IMAGE_BASE + 0x1000)
    rdata = bytearray(bytes(range(256)) * 16)
    rdata[0:0x300] = bytes(0x300)
    struct.pack_into("<5I", rdata, 0, 0x2040, 0, 0, 0x2080, 0x2060)
    struct.pack_into("<QQ", rdata, 0x40, 0x20A0, 0)
    struct.pack_into("<QQ", rdata, 0x60, 0x20A0, 0)
    rdata[0x80:0x86] = b"x.dll\0"
    rdata[0xA0:0xA4] = b"\0\0f\0"
    if second_import:
        struct.pack_into("<5I", rdata, 0x14, 0x2040, 0, 0, 0x2080, 0x20C0)
        struct.pack_into("<QQ", rdata, 0xC0, 0x20A0, 0)
    struct.pack_into("<QQQQII", rdata, 0x100, IMAGE_BASE + 0x3040, IMAGE_BASE + 0x3048, IMAGE_BASE + 0x3000, 0, 0, 0)
    rdata[0x400:0x540] = bytes(0x140)
    struct.pack_into("<I", rdata, 0x400, config_size)
    for field, slot in CONFIG_SLOTS:  # written in full; only `config_size` bytes are the directory
        struct.pack_into("<Q", rdata, 0x400 + field, IMAGE_BASE + slot)
    data = bytearray(bytes(range(0x80, 0x100)) * 4)
    data[0:0x40] = bytes(0x40)
    struct.pack_into("<QQQQQI", data, 0, 0, 0x2B992DDFA232, 0, 0, IMAGE_BASE + 0x2000, 0x40002000)
    if reloc is None:
        reloc = struct.pack("<IIHHHH", 0x3000, 16, (DIR64 << 12) | 0x20, (HIGHLOW << 12) | 0x28, 0, 0)
        reloc += struct.pack("<IIHH", 0x1000, 12, (DIR64 << 12) | 0x20, reloc_type << 12)
    directories = {1: (0x2000, import_size), 5: (0x4000, len(reloc)), 9: (0x2100, tls_size),
                   10: (0x2400, config_size if config_dir_size is None else config_dir_size)}
    if delay:
        directories[13] = (0x2300, delay_size)
    return build_pe([(b".text", 0x1000, bytes(text), 0x60000020, 0x40, 0x200),
                     (b".rdata", 0x2000, bytes(rdata), 0x40000040, 0x1000, 0x1000),
                     (b".data", 0x3000, bytes(data), 0xC0000040, 0x300, 0x200),
                     (b".reloc", 0x4000, reloc, 0x42000040)], directories)


# Load-config field offset -> .data slot it points at (IMAGE_LOAD_CONFIG_DIRECTORY64 offsets, winnt.h).
CONFIG_SLOTS = ((0x58, 0x3008), (0x70, 0x3010), (0x78, 0x3018), (0x118, 0x3060), (0x120, 0x3068), (0x128, 0x3070),
                (0x130, 0x3078), (0x138, 0x3080))


def check_loader_pe(data):
    """Parses the plan input back (independently of patch_plan) and returns its section map."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe + 24
    count = struct.unpack_from("<H", data, pe + 6)[0]
    layout = {}
    for i in range(count):
        name, vsize, va, raw_size, raw = struct.unpack_from("<8sIIII", data, opt + 0xF0 + 40 * i)
        layout[name.rstrip(b"\0")] = (va, vsize, raw_size, raw)
    assert layout[b".text"][:3] == (0x1000, 0x40, 0x200), layout[b".text"]
    assert layout[b".rdata"][:3] == (0x2000, 0x1000, 0x1000), layout[b".rdata"]
    assert layout[b".data"][:3] == (0x3000, 0x300, 0x200), layout[b".data"]
    dirs = {i: struct.unpack_from("<II", data, opt + 112 + 8 * i) for i in (1, 5, 9, 10, 13)}
    assert dirs == {1: (0x2000, 40), 5: (0x4000, 28), 9: (0x2100, 40), 10: (0x2400, 0x140), 13: (0, 0)}, dirs

    def at(rva, size):
        for va, vsize, raw_size, raw in layout.values():
            if va <= rva and rva + size <= va + min(vsize, raw_size):
                return data[raw + rva - va:raw + rva - va + size]
        raise AssertionError(f"{rva:#x} is not file-backed")

    assert struct.unpack("<5I", at(0x2000, 20)) == (0x2040, 0, 0, 0x2080, 0x2060)
    assert struct.unpack("<QQ", at(0x2060, 16)) == (0x20A0, 0), "import address table"
    assert struct.unpack("<Q", at(0x2110, 8))[0] == IMAGE_BASE + 0x3000, "TLS AddressOfIndex"
    assert struct.unpack("<I", at(0x2400, 4))[0] == 0x140, "load configuration Size"
    slots = [(f, struct.unpack("<Q", at(0x2400 + f, 8))[0] - IMAGE_BASE) for f in (0x58, 0x70, 0x78, 0x118, 0x120, 0x128, 0x130, 0x138)]
    assert slots == [(0x58, 0x3008), (0x70, 0x3010), (0x78, 0x3018), (0x118, 0x3060), (0x120, 0x3068), (0x128, 0x3070),
                     (0x130, 0x3078), (0x138, 0x3080)], slots
    blocks = [struct.unpack("<IIHHHH", at(0x4000, 16)), struct.unpack("<IIHH", at(0x4010, 12))]
    assert blocks == [(0x3000, 16, 0xA020, 0x3028, 0, 0), (0x1000, 12, 0xA020, 0)], blocks
    assert struct.unpack("<Q", at(0x1020, 8))[0] == IMAGE_BASE + 0x1000, "DIR64 slot in .text"
    assert struct.unpack("<Q", at(0x3020, 8))[0] == IMAGE_BASE + 0x2000, "DIR64 slot in .data"
    return at


class FakeProcess:
    """The plan input mapped at LOADED_BASE in a bytearray; read() and write() as debug_launch has them."""

    def __init__(self, data, at):
        self.memory = bytearray(0x5000)
        for rva, size in ((0x1000, 0x40), (0x2000, 0x1000), (0x3000, 0x200)):
            self.memory[rva:rva + size] = at(rva, size)
        self.writes = 0
        self.short = None  # rva whose read returns one byte less
        self.drop = False  # writes leave out their last byte and still report success
        self.fail = False  # writes report failure

    def read(self, address, size):
        rva = address - LOADED_BASE
        found = bytes(self.memory[rva:rva + size])
        return found[:-1] if rva == self.short else found

    def write(self, address, data):
        self.writes += 1
        if self.fail:
            return False
        rva = address - LOADED_BASE
        data = data[:-1] if self.drop else data
        self.memory[rva:rva + len(data)] = data
        return True


class Fixture:
    def __init__(self, root):
        self.root = root
        self.input = os.path.join(root, "input.exe")
        with open(self.input, "wb") as handle:
            handle.write(synthetic_pe())
        with open(self.input, "rb") as handle:
            self.sha = hashlib.sha256(handle.read()).hexdigest()
        self.loader = os.path.join(root, "loader.exe")
        with open(self.loader, "wb") as handle:
            handle.write(loader_pe())
        with open(self.loader, "rb") as handle:
            self.loader_bytes = handle.read()
        self.loader_sha = hashlib.sha256(self.loader_bytes).hexdigest()
        self.count = 0

    def write(self, text, raw=None):
        self.count += 1
        path = os.path.join(self.root, f"m{self.count}.toml")
        with open(path, "wb") as handle:
            handle.write(raw if raw is not None else text.encode("utf-8"))
        return path


# Hashes with letters, so that upper and lower case differ.
H1 = "ab" * 32
H2 = "cd" * 32
MEMORY = f'''
[[patch]]
id = "p001"
kind = "memory"
rva = 0x2000
expect_sha256 = "{H1}"
bytes = "9090"
why = "synthetic fixture"
remove_when = "never; test input"
'''
MEMORY2 = f'''
[[patch]]
id = "p002"
kind = "memory"
rva = 0x2008
expect_sha256 = "{H2}"
bytes = "c3"
why = "synthetic fixture"
remove_when = "never; test input"
'''


# A shader patch the loader accepts (shape only; it opens no file).
SHADER = f'''
[[patch]]
id = "s001"
kind = "shader"
key = "0123456789abcdef"
pipeline = "compute"
revision = "x2w-startup-shader-29cs"
files = [{{ ext = ".txt", file = "s001.txt", sha256 = "{H1}" }},
         {{ ext = ".cs.cso", file = "s001.cs.cso", sha256 = "{H2}" }}]
why = "synthetic fixture"
remove_when = "never; test input"
'''


def target(sha):
    return f'[target]\ninput_sha256 = "{sha}"\n'


def edit(text, old, new):
    assert text.count(old) == 1, f"fixture anchor {old!r} is not unique"
    return text.replace(old, new)


def refused(fx, text, fragment, raw=None):
    path = fx.write(text, raw)
    try:
        pm.check(path, fx.input)
    except pm.PatchError as error:
        assert fragment in str(error), f"refused for another reason: {error} (expected {fragment!r})"
        return
    raise AssertionError(f"accepted a manifest that must be refused ({fragment!r})")


def refused_input(fx, input_path, fragment):
    try:
        pm.check(fx.write(target(fx.sha) + MEMORY), input_path)
    except pm.PatchError as error:
        assert fragment in str(error), error
        return
    raise AssertionError(f"the gate passed {input_path!r}")


def run_cli(*args):
    done = subprocess.run([sys.executable, "-B", os.path.join(TOOLS, "patch_plan.py"), *args],
                          capture_output=True, text=True, timeout=60)
    return done.returncode, done.stdout.strip()


def mem(pid, rva, data, expect=None):
    return (f'[[patch]]\nid = "{pid}"\nkind = "memory"\nrva = {rva:#x}\nexpect_sha256 = "{expect}"\n'
            f'bytes = "{data.hex()}"\nwhy = "synthetic fixture"\nremove_when = "never; test input"\n')


def write_input(fx, name, data):
    path = os.path.join(fx.root, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path, hashlib.sha256(data).hexdigest()


def memory_cases(fx, case):
    """Stage 2: plan_memory, prepare, apply_memory, verify_applied, report_line, child_env, launch.py."""
    case("plan input is well-formed")
    at = check_loader_pe(fx.loader_bytes)

    def patch(pid, rva, data, expect=None):
        return mem(pid, rva, data, expect or hashlib.sha256(at(rva, len(data))).hexdigest())

    def plan(*patches, input_path=None, sha=None):
        path = fx.write(target(sha or fx.loader_sha) + "".join(patches))
        return pm.prepare({pm.ENV: path}, input_path or fx.loader)

    def plan_refused(fragment, *patches, input_path=None, sha=None):
        try:
            plan(*patches, input_path=input_path, sha=sha)
        except pm.PatchError as error:
            assert fragment in str(error), f"refused for another reason: {error} (expected {fragment!r})"
            return
        raise AssertionError(f"planned a manifest that must be refused ({fragment!r})")

    good = [patch("rd", 0x2300, b"\x90\x90\x90\x90"), patch("dt", 0x3040, b"\xeb\xfe")]
    case("plan ok")
    manifest, plans = plan(*good)
    assert [(p.id, p.rva, p.data) for p in plans] == [("rd", 0x2300, b"\x90" * 4), ("dt", 0x3040, b"\xeb\xfe")], plans
    case("wrong original bytes (expect_sha256 wrong in its last digit)")
    right = hashlib.sha256(at(0x2300, 4)).hexdigest()
    plan_refused("do not match expect_sha256", patch("rd", 0x2300, b"\x90" * 4, right[:-1] + ("0" if right[-1] != "0" else "1")))

    # Section bounds: file-backed bytes only, one section, no headers, no wrap.
    case("rva 0 (headers)")
    plan_refused("is in the headers", patch("h", 0, b"\x00\x00", "ab" * 32))
    case("range after SizeOfHeaders, before the first section")
    plan_refused("is in the headers", patch("h", 0x400, b"\x00", "ab" * 32))
    case("range in [VirtualSize, SizeOfRawData)")
    plan_refused("outside every section's file-backed bytes", patch("v", 0x1100, b"\x00", "ab" * 32))
    case("range past SizeOfRawData (virtual-only bytes)")
    plan_refused("outside every section's file-backed bytes", patch("v", 0x3200, b"\x00", "ab" * 32))
    case("range running past the section's file-backed bytes")
    plan_refused("runs past the file-backed bytes of section .data", patch("v", 0x31FE, b"\x00" * 4, "ab" * 32))
    case("range crossing two sections")
    plan_refused("crosses from section .rdata into .data", patch("x", 0x2FFE, b"\x00" * 4, "ab" * 32))
    case("rva 0xffffffff with two bytes")
    plan_refused("span [0xffffffff, 0x100000001) does not fit in 32-bit RVAs",
                 patch("w", 0xFFFFFFFF, b"\x00\x00", "ab" * 32))

    # Base relocations.
    case("ABSOLUTE padding at page+0 is not a relocation")
    plan(patch("a", 0x1000, b"\x90\x90"))
    case("range ending at a DIR64 entry")
    plan(patch("a", 0x1018, b"\x90" * 8))
    case("range starting at a DIR64 entry's last byte")
    plan_refused("overlaps a base relocation (base relocation DIR64 at 0x1020)", patch("a", 0x1027, b"\x90"))
    case("range starting right after a DIR64 entry")
    plan(patch("a", 0x1028, b"\x90\x90"))
    case("DIR64 overlap in the second block")
    plan_refused("overlaps a base relocation (base relocation DIR64 at 0x1020)", patch("a", 0x101C, b"\x90" * 8))
    case("HIGHLOW overlap in the first block")
    plan_refused("overlaps a base relocation (base relocation HIGHLOW at 0x3028)", patch("a", 0x302A, b"\x90\x90"))
    case("range right after a HIGHLOW entry")
    plan(patch("a", 0x302C, b"\x90\x90"))
    case("unsupported base relocation type")
    path, sha = write_input(fx, "highadj.exe", loader_pe(reloc_type=4))
    plan_refused("unsupported base relocation type 4 at 0x1000", patch("a", 0x2300, b"\x90"), input_path=path, sha=sha)

    # Bytes the loader writes.
    case("import address table terminator slot")
    plan_refused("overlaps a loader-written range (import address table at 0x2060)", patch("i", 0x2068, b"\x90" * 4))
    case("import descriptors past the directory's Size")
    two = loader_pe(second_import=True, import_size=20)
    assert two[two.index(b"x.dll\0") - 0x80 + 0x14:][:20] == struct.pack("<5I", 0x2040, 0, 0, 0x2080, 0x20C0)
    path, sha = write_input(fx, "imports20.exe", two)
    plan_refused("overlaps a loader-written range (import address table at 0x20c0)",
                 mem("i2", 0x20C0, b"\x90", hashlib.sha256(struct.pack("<Q", 0x20A0)[:1]).hexdigest()), input_path=path, sha=sha)
    path, sha = write_input(fx, "imports0.exe", loader_pe(import_size=0))  # RVA set, Size 0: still walked
    plan_refused("overlaps a loader-written range (import address table at 0x2060)", patch("i", 0x2060, b"\x90"),
                 input_path=path, sha=sha)
    case("TLS index slot")
    plan_refused("overlaps a loader-written range (TLS index at 0x3000)", patch("t", 0x3002, b"\x90"))
    case("security cookie slot")
    plan_refused("overlaps a loader-written range (security cookie at 0x3008)", patch("c", 0x3008, b"\x90" * 8))
    case("guard check function pointer slot")
    plan_refused("overlaps a loader-written range (guard check function pointer at 0x3010)", patch("g", 0x3010, b"\x90"))
    case("guard dispatch function pointer slot")
    plan_refused("overlaps a loader-written range (guard dispatch function pointer at 0x3018)", patch("g", 0x301F, b"\x90"))
    for label, slot in (("XFG check function pointer", 0x3060), ("XFG dispatch function pointer", 0x3068),
                        ("XFG table dispatch function pointer", 0x3070), ("CastGuard failure mode", 0x3078),
                        ("guard memcpy function pointer", 0x3080)):
        case(f"{label} slot")
        plan_refused(f"overlaps a loader-written range ({label} at {slot:#x})", patch("x", slot + 4, b"\x90"))
    case("load configuration too short for the guard fields")
    path, sha = write_input(fx, "shortcfg.exe", loader_pe(config_size=0x60))
    plan(patch("g", 0x3010, b"\x90"), input_path=path, sha=sha)
    case("load configuration of 0x118 bytes has no XFG check slot")
    path, sha = write_input(fx, "cfg118.exe", loader_pe(config_size=0x118))
    plan(patch("g", 0x3060, b"\x90"), input_path=path, sha=sha)
    case("delay-load imports")
    path, sha = write_input(fx, "delay.exe", loader_pe(delay=True))
    plan_refused("delay-load imports", patch("a", 0x2300, b"\x90"), input_path=path, sha=sha)
    # The TLS, load-configuration and delay-import directories count by their RVA, whatever their Size says.
    case("TLS directory with Size 0 still read")
    path, sha = write_input(fx, "tls0.exe", loader_pe(tls_size=0))
    plan_refused("overlaps a loader-written range (TLS index at 0x3000)", patch("t", 0x3002, b"\x90"), input_path=path, sha=sha)
    case("load configuration directory with Size 0 still read")
    path, sha = write_input(fx, "cfgdir0.exe", loader_pe(config_dir_size=0))
    plan_refused("overlaps a loader-written range (security cookie at 0x3008)", patch("c", 0x3008, b"\x90"),
                 input_path=path, sha=sha)
    case("load configuration directory Size past the structure's Size field")
    path, sha = write_input(fx, "cfgdir140.exe", loader_pe(config_size=0x60, config_dir_size=0x140))
    plan_refused("overlaps a loader-written range (guard check function pointer at 0x3010)", patch("g", 0x3010, b"\x90"),
                 input_path=path, sha=sha)
    case("delay-load directory with Size 0")
    path, sha = write_input(fx, "delay0.exe", loader_pe(delay=True, delay_size=0))
    plan_refused("delay-load imports", patch("a", 0x2300, b"\x90"), input_path=path, sha=sha)

    # Patches against each other: refused by the loader, whatever the order.
    case("two patches at the same rva")
    plan_refused("patches a and b overlap", patch("a", 0x2300, b"\x90"), patch("b", 0x2300, b"\x90"))
    case("overlapping patches listed in reverse order")
    plan_refused("patches b and a overlap", patch("a", 0x2302, b"\x90" * 4), patch("b", 0x2300, b"\x90" * 4))
    case("adjacent patches")
    plan(patch("a", 0x2304, b"\x90" * 4), patch("b", 0x2300, b"\x90" * 4))

    # prepare(): the switch, the gate on the exact EXE, a non-PE input.
    case("prepare without X2W_PATCHES")
    assert pm.prepare({}, fx.loader) == (None, ()) and pm.prepare({pm.ENV: ""}, fx.loader) == (None, ())
    case("prepare gates the EXE it is given")
    plan_refused("manifest is for another input", *good, input_path=fx.input)
    case("input that is not a PE image")
    path, sha = write_input(fx, "text.exe", b"not an image\n")
    plan_refused("not a PE image", patch("a", 0x2300, b"\x90"), input_path=path, sha=sha)
    case("section past the end of the input")
    path, sha = write_input(fx, "truncated.exe", fx.loader_bytes[:0x800])
    plan_refused("section 1 runs past the end of the input", patch("a", 0x1000, b"\x90"), input_path=path, sha=sha)
    case("section past SizeOfImage (the section ends at 2**32)")
    top = build_pe([(b".text", 0x1000, b"\xc3" * 16, 0x60000020), (b".top", 0xFFFFF000, bytes(0x1000), 0xC0000040, 0x1000, 0x1000)],
                   {}, size_of_image=0x2000)
    path, sha = write_input(fx, "top.exe", top)
    plan_refused("section 1 ends past SizeOfImage", mem("w", 0xFFFFF000, b"\x90", hashlib.sha256(b"\0").hexdigest()),
                 input_path=path, sha=sha)
    case("section ending exactly at SizeOfImage plans")
    edge = build_pe([(b".text", 0x1000, b"\xc3" * 16, 0x60000020), (b".data", 0x2000, bytes(0x1000), 0xC0000040)], {})
    edge_image = pm.parse_pe(edge)
    assert (edge_image.size_of_image, edge_image.sections[-1].end) == (0x3000, 0x3000), edge_image
    path, sha = write_input(fx, "edge.exe", edge)
    manifest_path = fx.write(target(sha) + mem("e", 0x2FFF, b"\x01", hashlib.sha256(b"\0").hexdigest()))
    assert [p.id for p in pm.prepare({pm.ENV: manifest_path}, path)[1]] == ["e"]
    case("section at a file offset that is not a multiple of 0x200")
    aligned = build_pe([(b".text", 0x1000, b"\xc3" * 16, 0x60000020), (b".data", 0x2000, bytes(range(0x40)), 0xC0000040)], {})
    table = struct.unpack_from("<I", aligned, 0x3C)[0] + 24 + 0xF0
    raw = struct.unpack_from("<I", aligned, table + 40 + 20)[0]  # .data's PointerToRawData
    assert raw == 0x400 and aligned[raw:raw + 4] == bytes(range(4)), raw
    path, sha = write_input(fx, "aligned.exe", aligned)
    manifest_path = fx.write(target(sha) + mem("d", 0x2000, b"\x90" * 4, hashlib.sha256(bytes(range(4))).hexdigest()))
    assert [p.id for p in pm.prepare({pm.ENV: manifest_path}, path)[1]] == ["d"]
    shifted = bytearray(aligned + bytes(0x10))
    struct.pack_into("<I", shifted, table + 40 + 20, raw + 0x10)  # pefile maps 0x400 here, the plan would hash 0x410
    path, sha = write_input(fx, "shifted.exe", bytes(shifted))
    plan_refused("section 1 starts at file offset 0x410, not a multiple of 0x200: readers disagree on its bytes",
                 mem("d", 0x2000, b"\x90" * 4, hashlib.sha256(bytes(range(0x10, 0x14))).hexdigest()), input_path=path, sha=sha)
    case("relocation directory ending inside a block header")
    path, sha = write_input(fx, "relochdr.exe", loader_pe(reloc=struct.pack("<IIHH", 0x1000, 12, 0, 0) + bytes(4)))
    plan_refused("ends inside a block header", patch("a", 0x2300, b"\x90"), input_path=path, sha=sha)
    case("relocation block of size 0")
    path, sha = write_input(fx, "reloc0.exe", loader_pe(reloc=struct.pack("<II", 0x1000, 0)))
    plan_refused("has size 0", patch("a", 0x2300, b"\x90"), input_path=path, sha=sha)

    # apply_memory and verify_applied on a fake process.
    case("apply all patches")
    process = FakeProcess(fx.loader_bytes, at)
    pm.apply_memory(plans, LOADED_BASE, process.read, process.write)
    assert process.writes == 2 and process.memory[0x2300:0x2304] == b"\x90" * 4 and process.memory[0x3040:0x3042] == b"\xeb\xfe"
    case("apply: first patch good, second differs in memory -> no write")
    process = FakeProcess(fx.loader_bytes, at)
    process.memory[0x3041] ^= 0xFF
    try:
        pm.apply_memory(plans, LOADED_BASE, process.read, process.write)
        raise AssertionError("applied over bytes that differ from expect_sha256")
    except pm.PatchError as error:
        assert "patch dt: the bytes in memory at +0x3040 do not match" in str(error), error
    assert process.writes == 0, f"{process.writes} write(s) before every range was verified"
    case("apply: short read -> no write")
    process = FakeProcess(fx.loader_bytes, at)
    process.short = 0x3040
    try:
        pm.apply_memory(plans, LOADED_BASE, process.read, process.write)
        raise AssertionError("applied after a short read")
    except pm.PatchError as error:
        assert "patch dt: read 1 of 2 bytes at +0x3040" in str(error), error
    assert process.writes == 0, process.writes
    case("apply: a failed write refuses")
    process = FakeProcess(fx.loader_bytes, at)
    process.fail = True
    try:
        pm.apply_memory(plans, LOADED_BASE, process.read, process.write)
        raise AssertionError("a failed write was accepted")
    except pm.PatchError as error:
        assert "patch rd: writing +0x2300 failed" in str(error), error
    case("apply: a write that drops a byte fails the read-back")
    process = FakeProcess(fx.loader_bytes, at)
    process.drop = True
    try:
        pm.apply_memory(plans, LOADED_BASE, process.read, process.write)
        raise AssertionError("a short write passed the read-back")
    except pm.PatchError as error:
        assert "does not hold the replacement after the write" in str(error), error
    case("verify at the loader breakpoint")
    process = FakeProcess(fx.loader_bytes, at)
    pm.apply_memory(plans, LOADED_BASE, process.read, process.write)
    pm.verify_applied(plans, LOADED_BASE, process.read, "at the loader breakpoint")
    process.memory[0x2303] = 0
    try:
        pm.verify_applied(plans, LOADED_BASE, process.read, "at the loader breakpoint")
        raise AssertionError("a patch overwritten after the write passed")
    except pm.PatchError as error:
        assert "patch rd: memory at +0x2300 does not hold the replacement at the loader breakpoint" in str(error), error
    # gate_image: the file the process was created from, read through a handle (here: bytes in chunks).
    def reader(data, most=1 << 20):
        return lambda offset, size: data[offset:offset + min(size, most)]
    case("gate_image passes the gated file, read whole or 100 bytes at a time")
    for most in (1 << 20, 100):
        pm.gate_image(manifest, reader(fx.loader_bytes, most))
    case("gate_image refuses a file that differs from the gated one")
    swapped = bytearray(fx.loader_bytes)
    swapped[0x500] ^= 0xFF  # outside every patch range: apply and verify alone would pass
    assert pm.patch_at(plans, 0x500) is None and len(swapped) == len(fx.loader_bytes)
    for data in (bytes(swapped), fx.loader_bytes + b"\0", fx.loader_bytes[:-1]):
        try:
            pm.gate_image(manifest, reader(data))
            raise AssertionError("gate_image passed a file that is not the manifest's input")
        except pm.PatchError as error:
            assert "the image the process was created from is not the manifest's target input_sha256" in str(error), error
    case("gate_image passes a failed read on")
    def failing(offset, size):
        raise pm.PatchError("cannot read the image the process was created from (error 6)")
    try:
        pm.gate_image(manifest, failing)
        raise AssertionError("gate_image passed a failed read")
    except pm.PatchError as error:
        assert "(error 6)" in str(error), error
    case("gate_image with the test fault refuses the gated file")
    try:
        pm.gate_image(manifest, pm.faulty_read(reader(fx.loader_bytes)))
        raise AssertionError("the image fault let the gated file through")
    except pm.PatchError as error:
        assert "is not the manifest's target input_sha256" in str(error), error
    case("breakpoint inside a patch range")
    assert [pm.patch_at(plans, r) for r in (0x22FF, 0x2300, 0x2303, 0x2304, 0x3041)] == [None, "rd", "rd", None, "dt"]

    # The test-only fault switch can make a compare fail, never pass.
    case("test fault switch values")
    assert [pm.test_fault({}), pm.test_fault({pm.TEST_FAULT: "apply"}), pm.test_fault({pm.TEST_FAULT: "verify"}),
            pm.test_fault({pm.TEST_FAULT: "image"})] == [None, "apply", "verify", "image"]
    try:
        pm.test_fault({pm.TEST_FAULT: "skip"})
        raise AssertionError("an unknown test fault was accepted")
    except pm.PatchError as error:
        assert "must be apply, verify or image" in str(error), error
    case("apply with the test fault refuses a matching manifest")
    process = FakeProcess(fx.loader_bytes, at)
    expected = [p.data for p in plans]
    try:
        pm.apply_memory(plans, LOADED_BASE, pm.faulty_read(process.read), process.write)
        raise AssertionError("the apply fault let the patches through")
    except pm.PatchError as error:
        assert "patch rd: read 3 of 4 bytes at +0x2300" in str(error), error
    assert process.writes == 0 and [p.data for p in plans] == expected, "the fault changed expected bytes or wrote"
    # Whatever memory holds, the fault never lets a step pass: here memory differs from the original only in
    # its first byte, which a fault that inverted that byte would have turned back into a match.
    case("apply with the test fault refuses memory that differs only in its first byte")
    process = FakeProcess(fx.loader_bytes, at)
    process.memory[0x2300] ^= 0xFF
    try:
        pm.apply_memory(plans, LOADED_BASE, pm.faulty_read(process.read), process.write)
        raise AssertionError("the apply fault passed")
    except pm.PatchError as error:
        assert "patch rd: read 3 of 4 bytes at +0x2300" in str(error), error
    assert process.writes == 0, process.writes
    case("verify with the test fault refuses applied patches")
    process = FakeProcess(fx.loader_bytes, at)
    pm.apply_memory(plans, LOADED_BASE, process.read, process.write)
    try:
        pm.verify_applied(plans, LOADED_BASE, pm.faulty_read(process.read), "at the loader breakpoint")
        raise AssertionError("the verify fault passed")
    except pm.PatchError as error:
        assert "does not hold the replacement at the loader breakpoint" in str(error), error
    assert process.memory[0x2300:0x2304] == b"\x90" * 4, "the fault changed memory"
    case("verify with the test fault refuses memory that differs only in its first byte")
    process.memory[0x2300] ^= 0xFF
    for read, how in ((process.read, "plain read"), (pm.faulty_read(process.read), "test fault")):
        try:
            pm.verify_applied(plans, LOADED_BASE, read, "at the loader breakpoint")
            raise AssertionError(f"memory that differs in its first byte passed the {how}")
        except pm.PatchError as error:
            assert "patch rd: memory at +0x2300 does not hold the replacement at the loader breakpoint" in str(error), error

    # The run summary line and the child environment.
    case("report line without a manifest")
    assert pm.report_line(None) == "patches: none"
    case("report line with a manifest")
    assert pm.report_line(manifest) == f"patches: manifest sha256={manifest.sha256} active=rd,dt", pm.report_line(manifest)
    case("report line for patches never re-checked")
    assert pm.unverified_line(manifest).startswith(f"patches: unverified manifest sha256={manifest.sha256} active=rd,dt ")
    with open(manifest.path, "rb") as handle:
        assert manifest.sha256 == hashlib.sha256(handle.read()).hexdigest()
    case("child environment drops a stale data-patch map and the manifest switch")
    parent = {"X2W_DATA_PATCH_MAP": "stale.map", "x2w_data_patch_map": "stale2.map", "X2W_PATCH_STATE": "1",
              "X2W_PATCH_TEST_FAULT": "apply", "X2W_PATCHES": "m.toml", "x2w_Patches": "m2.toml",
              "X2W_PATCHESX": "kept", "X2W_LOG_AT": "1000", "PATH": "/bin"}
    child = pm.child_env(parent)
    assert child == {"X2W_PATCHESX": "kept", "X2W_LOG_AT": "1000", "PATH": "/bin"}, child
    assert parent["X2W_DATA_PATCH_MAP"] == "stale.map", "child_env changed its argument"

    # The command line and the second launcher.
    case("cli plan ok")
    code, out = run_cli("plan", fx.write(target(fx.loader_sha) + "".join(good)), fx.loader)
    assert code == 0 and out.startswith("patches: ok manifest sha256=") and out.endswith(" patches=2 planned"), (code, out)
    case("cli plan refused")
    code, out = run_cli("plan", fx.write(target(fx.loader_sha) + patch("i", 0x2060, b"\x90")), fx.loader)
    assert code == 3 and out.startswith("patches: refused: patch i: range 0x2060-0x2061 overlaps a loader-written"), (code, out)
    case("launch.py refuses X2W_PATCHES")
    work = os.path.join(fx.root, "launch")
    done = subprocess.run([sys.executable, "-B", os.path.join(TOOLS, "launch.py"), fx.loader, fx.root, work],
                          capture_output=True, text=True, timeout=60, env=dict(os.environ, X2W_PATCHES=fx.write(good[0])))
    assert done.returncode == 3 and done.stdout.strip() == (
        "patches: refused: launch.py does not apply patch manifests; use debug_launch.py"), (done.returncode, done.stdout, done.stderr)
    assert not os.path.exists(work), "launch.py created its log directory before refusing"


def cases(fx, checked):
    good = target(fx.sha) + MEMORY + MEMORY2

    def case(name):
        checked.append(name)

    case("synthetic PE is well-formed")
    with open(fx.input, "rb") as handle:
        check_synthetic_pe(handle.read())

    # Accepted: every field parsed, rva from a TOML hex integer.
    case("valid manifest of two patches")
    path = fx.write(good)
    manifest = pm.check(path, fx.input)
    with open(path, "rb") as handle:
        assert manifest.sha256 == hashlib.sha256(handle.read()).hexdigest(), "manifest sha256 is not of its bytes"
    assert manifest.input_sha256 == fx.sha
    first, second = manifest.patches
    assert (first.id, first.kind, first.rva, first.data) == ("p001", "memory", 0x2000, b"\x90\x90")
    assert first.expect_sha256 == H1, first.expect_sha256
    assert (second.id, second.rva, second.data, second.expect_sha256) == ("p002", 0x2008, b"\xc3", H2)

    case("uppercase input_sha256 refused")
    assert fx.sha != fx.sha.upper(), "the fixture hash has no letters"
    refused(fx, target(fx.sha.upper()) + MEMORY, "input_sha256 must be 64 lowercase hex digits")

    # The hash gate (negative controls).
    case("input hash wrong in its last digit")
    last = fx.sha[:-1] + ("0" if fx.sha[-1] != "0" else "1")
    refused(fx, target(last) + MEMORY, "manifest is for another input")
    case("input hash wrong in its first digit")
    first_digit = ("0" if fx.sha[0] != "0" else "1") + fx.sha[1:]
    refused(fx, target(first_digit) + MEMORY, "manifest is for another input")
    case("input is a directory")
    refused_input(fx, fx.root, "not a regular file")
    case("input is missing")
    refused_input(fx, os.path.join(fx.root, "absent.exe"), "not a regular file")

    # Accountability fields.
    case("missing why")
    refused(fx, target(fx.sha) + edit(MEMORY, 'why = "synthetic fixture"\n', ""), "[[patch]] 0 is missing: why")
    case("blank why")
    refused(fx, target(fx.sha) + edit(MEMORY, 'why = "synthetic fixture"', 'why = "  "'),
            "patch p001 why must be a non-empty string")
    case("missing remove_when")
    refused(fx, target(fx.sha) + edit(MEMORY, 'remove_when = "never; test input"\n', ""),
            "[[patch]] 0 is missing: remove_when")
    case("missing bytes")
    refused(fx, target(fx.sha) + edit(MEMORY, 'bytes = "9090"\n', ""), "[[patch]] 0 is missing: bytes")

    # Ids and kinds.
    case("duplicate id")
    refused(fx, target(fx.sha) + MEMORY + edit(MEMORY2, '"p002"', '"p001"'), "duplicate patch id: p001")
    case("uppercase id")
    refused(fx, target(fx.sha) + edit(MEMORY, '"p001"', '"P001"'), "id must match")
    case("id of 65 characters")
    refused(fx, target(fx.sha) + edit(MEMORY, '"p001"', '"' + "a" * 65 + '"'), "id must match")
    case("kind hook")
    refused(fx, target(fx.sha) + edit(MEMORY, '"memory"', '"hook"'), "kind 'hook' is not supported")
    case("kind data")
    refused(fx, target(fx.sha) + edit(MEMORY, '"memory"', '"data"'), "kind 'data' is not supported")
    case("unknown kind")
    refused(fx, target(fx.sha) + edit(MEMORY, '"memory"', '"code"'), "kind 'code' is not supported")
    case("kind shader, which the loader accepts, has no consumer here")
    refused(fx, target(fx.sha) + SHADER, 'patch s001: kind "shader" has no consumer in the startup debugger')

    # Unknown keys.
    case("unknown top-level key")
    refused(fx, "version = 1\n" + target(fx.sha) + MEMORY, "manifest has unknown keys: version")
    case("extra [target] key")
    refused(fx, target(fx.sha) + 'name = "x"\n' + MEMORY, "[target] has unknown keys: name")
    case("unknown patch key")
    refused(fx, target(fx.sha) + edit(MEMORY, 'kind = "memory"', 'kind = "memory"\nsize = 2'),
            "[[patch]] 0 has unknown keys: size")
    case("memory patch with a data-file key")
    refused(fx, target(fx.sha) + edit(MEMORY, 'kind = "memory"', 'kind = "memory"\npath = "a"'),
            "[[patch]] 0 has unknown keys: path")

    # Hashes, numbers and bytes.
    case("expect_sha256 of 63 digits")
    refused(fx, target(fx.sha) + edit(MEMORY, f'"{H1}"', f'"{H1[:-1]}"'),
            "expect_sha256 must be 64 lowercase hex digits")
    case("expect_sha256 with a non-hex digit")
    refused(fx, target(fx.sha) + edit(MEMORY, f'"{H1}"', f'"{H1[:-1]}g"'),
            "expect_sha256 must be 64 lowercase hex digits")
    case("input_sha256 not a string")
    refused(fx, "[target]\ninput_sha256 = 7\n" + MEMORY, "input_sha256 must be 64 lowercase hex digits")
    case("odd number of hex digits")
    refused(fx, target(fx.sha) + edit(MEMORY, '"9090"', '"909"'),
            "bytes must be a non-empty, even number of lowercase hex digits")
    case("empty bytes")
    refused(fx, target(fx.sha) + edit(MEMORY, '"9090"', '""'),
            "bytes must be a non-empty, even number of lowercase hex digits")
    case("bytes with a space")
    refused(fx, target(fx.sha) + edit(MEMORY, '"9090"', '"90 90"'),
            "bytes must be a non-empty, even number of lowercase hex digits")
    case("bytes at the cap")
    pm.check(fx.write(target(fx.sha) + edit(MEMORY, '"9090"', '"' + "90" * pm.MAX_BYTES + '"')), fx.input)
    case("bytes one past the cap")
    refused(fx, target(fx.sha) + edit(MEMORY, '"9090"', '"' + "90" * (pm.MAX_BYTES + 1) + '"'), "more than 4096")
    # Two bytes apart, so that the loader's overlap check passes them.
    many = [edit(edit(MEMORY, '"p001"', f'"p{i:04d}"'), "rva = 0x2000", f"rva = {0x2000 + 2 * i:#x}")
            for i in range(pm.MAX_PATCHES + 1)]
    case("patches at the cap")
    assert len(pm.check(fx.write(target(fx.sha) + "".join(many[:-1])), fx.input).patches) == 4096
    case("patches one past the cap")
    refused(fx, target(fx.sha) + "".join(many), "4097 [[patch]] entries, more than 4096")
    case("rva 0xffffffff with one byte")
    one = edit(edit(MEMORY, "rva = 0x2000", "rva = 0xffffffff"), '"9090"', '"90"')
    manifest = pm.check(fx.write(target(fx.sha) + one), fx.input)
    assert manifest.patches[0].rva == 0xFFFFFFFF
    case("rva as a hex string")
    refused(fx, target(fx.sha) + edit(MEMORY, "rva = 0x2000", 'rva = "0x2000"'), "rva must be an integer in [0, 2^32)")
    case("rva integer past 32 bits")
    refused(fx, target(fx.sha) + edit(MEMORY, "rva = 0x2000", "rva = 0x100000000"),
            "rva must be an integer in [0, 2^32)")
    case("negative rva")
    refused(fx, target(fx.sha) + edit(MEMORY, "rva = 0x2000", "rva = -1"), "rva must be an integer in [0, 2^32)")
    case("rva as a boolean")
    refused(fx, target(fx.sha) + edit(MEMORY, "rva = 0x2000", "rva = true"), "rva must be an integer in [0, 2^32)")
    case("rva as a decimal string")
    refused(fx, target(fx.sha) + edit(MEMORY, "rva = 0x2000", 'rva = "8192"'), "rva must be an integer in [0, 2^32)")

    # Document shape.
    case("not TOML")
    refused(fx, target(fx.sha) + "[[patch]\n", "not valid TOML")
    case("TOML duplicate key")
    refused(fx, target(fx.sha) + edit(MEMORY, 'kind = "memory"', 'kind = "memory"\nkind = "memory"'), "not valid TOML")
    # tomllib recurses once per nesting level: a 1,005-byte line of 500 arrays exceeds the default limit of 1000.
    deep = target(fx.sha) + "a = " + "[" * 500 + "]" * 500 + "\n"
    case("nesting deeper than tomllib parses")
    import tomllib
    try:
        tomllib.loads(deep)
        raise AssertionError("the nested document parsed; the case no longer reaches the recursion limit")
    except RecursionError:
        pass
    refused(fx, deep, "manifest is nested too deeply to parse")
    case("not UTF-8")
    refused(fx, "", "not UTF-8", raw=target(fx.sha).encode() + b'#\xff\n' + MEMORY.encode())
    case("no patches")
    refused(fx, target(fx.sha), "manifest is missing: patch")
    case("empty [[patch]] array")
    refused(fx, "patch = []\n" + target(fx.sha), "manifest needs at least one [[patch]]")
    case("missing [target]")
    refused(fx, MEMORY, "manifest is missing: target")
    case("unreadable manifest")
    try:
        pm.load(os.path.join(fx.root, "absent.toml"), b"")
        raise AssertionError("a missing manifest loaded")
    except pm.PatchError as error:
        assert "cannot read the manifest" in str(error), error

    # Accepted whole or refused whole.
    case("good patch then bad patch")
    refused(fx, target(fx.sha) + MEMORY + edit(MEMORY2, 'why = "synthetic fixture"\n', ""),
            "[[patch]] 1 is missing: why")

    # The command line.
    case("cli ok")
    code, out = run_cli("check", fx.write(good), fx.input)
    assert code == 0 and out.startswith("patches: ok manifest sha256=") and out.endswith(" patches=2"), (code, out)
    case("cli refused")
    code, out = run_cli("check", fx.write(target(last) + MEMORY), fx.input)
    assert code == 3 and out == (f"patches: refused: manifest is for another input: manifest input_sha256 {last}, "
                                 f"input sha256 {fx.sha}"), (code, out)
    for command in ("check", "plan"):
        case(f"cli {command} refuses a too deeply nested manifest")
        code, out = run_cli(command, fx.write(deep), fx.input)
        assert code == 3 and out == "patches: refused: manifest is nested too deeply to parse", (code, out)
    case("cli usage")
    code, out = run_cli("check", fx.input)
    assert code == 2 and out.startswith("usage: patch_plan.py check"), (code, out)

    # The loader, and with it tomllib, is imported only by load(): without tomllib, import works and load refuses
    # by name.
    case("tomllib imported lazily")
    probe = ("import sys; sys.path.insert(0, sys.argv[1]); import patch_plan as pm; "
             "assert 'tomllib' not in sys.modules, 'tomllib imported at module import'; "
             "assert 'patch_manifest' not in sys.modules, 'the loader imported at module import'; "
             "sys.modules['tomllib'] = None\n"
             "try:\n    pm.load(sys.argv[2], b'')\nexcept pm.PatchError as e:\n    print(e)")
    done = subprocess.run([sys.executable, "-B", "-c", probe, TOOLS, fx.write(good)],
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0 and done.stdout.strip() == "needs Python 3.11+ (tomllib)", (done.returncode,
                                                                                            done.stdout, done.stderr)

    case("the loader is tools/patch_manifest.py")
    assert os.path.samefile(pm._loader().__file__, LOADER), pm._loader().__file__

    memory_cases(fx, case)


def main():
    checked = []
    with tempfile.TemporaryDirectory() as root:
        try:
            cases(Fixture(root), checked)
        except Exception as error:  # name the case that failed, then the reason
            print(f"patch_plan: FAIL in case {checked[-1] if checked else '(setup)'!r}: "
                  f"{type(error).__name__}: {error}")
            return 1
    if len(checked) != EXPECTED_CASES:
        print(f"patch_plan: FAIL: {len(checked)} cases ran, expected {EXPECTED_CASES}")
        return 1
    print(f"patch_plan: PASS ({len(checked)} cases: loader refusals, planner rules, input hash gate and "
          f"memory-patch plan, "
          f"apply, report and environment rules, each refusal named; gate checked with a hash wrong only in its "
          f"last and only in its first digit)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

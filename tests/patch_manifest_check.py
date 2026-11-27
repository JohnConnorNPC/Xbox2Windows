"""Checks tools/startup/patch_manifest.py: the manifest schema, the loader and the input hash gate.

The input is a synthetic PE32+ built here (headers, .text, .data, .reloc with one DIR64 entry and
one ABSOLUTE pad); the first case parses it back and checks that layout. Manifests are written to
a temporary directory. Every refusal case is a negative control: the manifest must be refused
whole, with the reason named. The hash gate is checked with a hash that differs from the right one
only in its last hex digit and only in its first, so a gate that compares a prefix or a suffix
fails here. Fixture hashes contain letters, and one is written in upper case, so a hash that is not
lowercased fails here too. Needs Python 3.11+ (tomllib).
"""
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "tools", "startup")
sys.path.insert(0, TOOLS)
import patch_manifest as pm  # noqa: E402

# Every case below is counted; a case that is removed or never reached fails the check.
EXPECTED_CASES = 46
IMAGE_BASE = 0x140000000
DIR64, ABSOLUTE = 10, 0


def synthetic_pe():
    """A minimal AMD64 PE32+: .text (ret), .data (16 marker bytes, one pointer), .reloc (DIR64 + pad)."""
    file_align, section_align = 0x200, 0x1000
    sections = [(b".text", 0x1000, b"\xc3" + b"\xcc" * 15, 0x60000020),
                (b".data", 0x2000, bytes(range(0x40, 0x50)) + struct.pack("<Q", IMAGE_BASE + 0x2000), 0xC0000040),
                (b".reloc", 0x3000, struct.pack("<IIHH", 0x2000, 12, (DIR64 << 12) | 0x10, ABSOLUTE << 12),
                 0x42000040)]
    headers = bytearray(0x200)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", headers, 0x84, 0x8664, len(sections), 0, 0, 0, 0xF0, 0x22)
    opt = 0x98
    struct.pack_into("<HBBIIIII", headers, opt, 0x20B, 14, 0, 0x200, 0x400, 0, 0x1000, 0x1000)
    struct.pack_into("<QII", headers, opt + 24, IMAGE_BASE, section_align, file_align)
    struct.pack_into("<HHHHHH", headers, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<IIII", headers, opt + 52, 0, 0x4000, 0x200, 0)
    struct.pack_into("<HH", headers, opt + 68, 3, 0x0160)  # console; ASLR, high-entropy VA, NX
    struct.pack_into("<QQQQII", headers, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    struct.pack_into("<II", headers, opt + 112 + 8 * 5, 0x3000, 12)  # base relocation directory
    image = bytearray(headers)
    for i, (name, rva, body, flags) in enumerate(sections):
        raw = len(image)
        image += body.ljust(file_align, b"\0")
        struct.pack_into("<8sIIIIIIHHI", image, opt + 0xF0 + 40 * i, name, len(body), rva, file_align, raw,
                         0, 0, 0, 0, flags)
    return bytes(image)


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


class Fixture:
    def __init__(self, root):
        self.root = root
        self.input = os.path.join(root, "input.exe")
        with open(self.input, "wb") as handle:
            handle.write(synthetic_pe())
        with open(self.input, "rb") as handle:
            self.sha = hashlib.sha256(handle.read()).hexdigest()
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
rva = "0x2000"
expect_sha256 = "{H1.upper()}"
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
    done = subprocess.run([sys.executable, "-B", os.path.join(TOOLS, "patch_manifest.py"), *args],
                          capture_output=True, text=True, timeout=60)
    return done.returncode, done.stdout.strip()


def cases(fx, checked):
    good = target(fx.sha) + MEMORY + MEMORY2

    def case(name):
        checked.append(name)

    case("synthetic PE is well-formed")
    with open(fx.input, "rb") as handle:
        check_synthetic_pe(handle.read())

    # Accepted: every field parsed, hashes stored in lowercase, rva from a string and a TOML hex integer.
    case("valid manifest of two patches")
    path = fx.write(good)
    manifest = pm.check(path, fx.input)
    with open(path, "rb") as handle:
        assert manifest.sha256 == hashlib.sha256(handle.read()).hexdigest(), "manifest sha256 is not of its bytes"
    assert manifest.input_sha256 == fx.sha
    first, second = manifest.patches
    assert (first.id, first.kind, first.rva, first.data) == ("p001", "memory", 0x2000, b"\x90\x90")
    assert H1 != H1.upper() and first.expect_sha256 == H1, f"expect_sha256 not stored in lowercase: {first.expect_sha256}"
    assert (second.id, second.rva, second.data, second.expect_sha256) == ("p002", 0x2008, b"\xc3", H2)

    case("uppercase input_sha256 matches")
    assert fx.sha != fx.sha.upper(), "the fixture hash has no letters"
    pm.check(fx.write(target(fx.sha.upper()) + MEMORY), fx.input)

    # The hash gate (negative controls).
    case("input hash wrong in its last digit")
    last = fx.sha[:-1] + ("0" if fx.sha[-1] != "0" else "1")
    refused(fx, target(last) + MEMORY, "is not the manifest's target")
    case("input hash wrong in its first digit")
    first_digit = ("0" if fx.sha[0] != "0" else "1") + fx.sha[1:]
    refused(fx, target(first_digit) + MEMORY, "is not the manifest's target")
    case("input is a directory")
    refused_input(fx, fx.root, "not a regular file")
    case("input is missing")
    refused_input(fx, os.path.join(fx.root, "absent.exe"), "not a regular file")

    # Accountability fields.
    case("missing why")
    refused(fx, target(fx.sha) + edit(MEMORY, 'why = "synthetic fixture"\n', ""), "missing why")
    case("blank why")
    refused(fx, target(fx.sha) + edit(MEMORY, 'why = "synthetic fixture"', 'why = "  "'), "why: expected a non-empty")
    case("missing remove_when")
    refused(fx, target(fx.sha) + edit(MEMORY, 'remove_when = "never; test input"\n', ""), "missing remove_when")
    case("missing bytes")
    refused(fx, target(fx.sha) + edit(MEMORY, 'bytes = "9090"\n', ""), "missing bytes")

    # Ids and kinds.
    case("duplicate id")
    refused(fx, target(fx.sha) + MEMORY + edit(MEMORY2, '"p002"', '"p001"'), "duplicate id")
    case("uppercase id")
    refused(fx, target(fx.sha) + edit(MEMORY, '"p001"', '"P001"'), "id must match")
    case("id of 65 characters")
    refused(fx, target(fx.sha) + edit(MEMORY, '"p001"', '"' + "a" * 65 + '"'), "id must match")
    case("kind hook")
    refused(fx, target(fx.sha) + edit(MEMORY, '"memory"', '"hook"'), 'kind "hook" (stage 1) is not implemented')
    case("kind data")
    refused(fx, target(fx.sha) + edit(MEMORY, '"memory"', '"data"'), 'kind "data" (stage 3) is not implemented')
    case("unknown kind")
    refused(fx, target(fx.sha) + edit(MEMORY, '"memory"', '"code"'), 'kind must be "memory"')

    # Unknown keys.
    case("unknown top-level key")
    refused(fx, "version = 1\n" + target(fx.sha) + MEMORY, "unknown top-level key(s): version")
    case("extra [target] key")
    refused(fx, target(fx.sha) + 'name = "x"\n' + MEMORY, "[target] must hold exactly input_sha256")
    case("unknown patch key")
    refused(fx, target(fx.sha) + edit(MEMORY, 'kind = "memory"', 'kind = "memory"\nsize = 2'),
            "unknown key(s): size")
    case("memory patch with a data-file key")
    refused(fx, target(fx.sha) + edit(MEMORY, 'kind = "memory"', 'kind = "memory"\npath = "a"'),
            "unknown key(s): path")

    # Hashes, numbers and bytes.
    case("expect_sha256 of 63 digits")
    refused(fx, target(fx.sha) + edit(MEMORY, f'"{H1.upper()}"', f'"{H1[:-1]}"'), "expected 64 hex digits")
    case("expect_sha256 with a non-hex digit")
    refused(fx, target(fx.sha) + edit(MEMORY, f'"{H1.upper()}"', f'"{H1[:-1]}g"'), "expected 64 hex digits")
    case("input_sha256 not a string")
    refused(fx, "[target]\ninput_sha256 = 7\n" + MEMORY, "expected 64 hex digits")
    case("odd number of hex digits")
    refused(fx, target(fx.sha) + edit(MEMORY, '"9090"', '"909"'), "even number of hex digits")
    case("empty bytes")
    refused(fx, target(fx.sha) + edit(MEMORY, '"9090"', '""'), "even number of hex digits")
    case("bytes with a space")
    refused(fx, target(fx.sha) + edit(MEMORY, '"9090"', '"90 90"'), "even number of hex digits")
    case("bytes at the cap")
    pm.check(fx.write(target(fx.sha) + edit(MEMORY, '"9090"', '"' + "90" * pm.MAX_BYTES + '"')), fx.input)
    case("bytes one past the cap")
    refused(fx, target(fx.sha) + edit(MEMORY, '"9090"', '"' + "90" * (pm.MAX_BYTES + 1) + '"'), "more than 4096")
    case("rva 0xffffffff")
    manifest = pm.check(fx.write(target(fx.sha) + edit(MEMORY, '"0x2000"', '"0xffffffff"')), fx.input)
    assert manifest.patches[0].rva == 0xFFFFFFFF
    case("rva string past 32 bits")
    refused(fx, target(fx.sha) + edit(MEMORY, '"0x2000"', '"0x100000000"'), "out of range")
    case("rva integer past 32 bits")
    refused(fx, target(fx.sha) + edit(MEMORY, '"0x2000"', "0x100000000"), "out of range")
    case("negative rva")
    refused(fx, target(fx.sha) + edit(MEMORY, '"0x2000"', "-1"), "out of range")
    case("rva as a boolean")
    refused(fx, target(fx.sha) + edit(MEMORY, '"0x2000"', "true"), "expected an integer")
    case("rva as a decimal string")
    refused(fx, target(fx.sha) + edit(MEMORY, '"0x2000"', '"8192"'), "expected an integer")

    # Document shape.
    case("not TOML")
    refused(fx, target(fx.sha) + "[[patch]\n", "not valid TOML")
    case("TOML duplicate key")
    refused(fx, target(fx.sha) + edit(MEMORY, 'kind = "memory"', 'kind = "memory"\nkind = "memory"'), "not valid TOML")
    case("not UTF-8")
    refused(fx, "", "not UTF-8", raw=target(fx.sha).encode() + b'#\xff\n' + MEMORY.encode())
    case("no patches")
    refused(fx, target(fx.sha), "missing [[patch]] entries")
    case("missing [target]")
    refused(fx, MEMORY, "missing [target]")
    case("unreadable manifest")
    try:
        pm.load(os.path.join(fx.root, "absent.toml"))
        raise AssertionError("a missing manifest loaded")
    except pm.PatchError as error:
        assert "cannot read the manifest" in str(error), error

    # Accepted whole or refused whole.
    case("good patch then bad patch")
    refused(fx, target(fx.sha) + MEMORY + edit(MEMORY2, 'why = "synthetic fixture"\n', ""), "patch p002: missing why")

    # The command line.
    case("cli ok")
    code, out = run_cli("check", fx.write(good), fx.input)
    assert code == 0 and out.startswith("patches: ok manifest sha256=") and out.endswith(" patches=2"), (code, out)
    case("cli refused")
    code, out = run_cli("check", fx.write(target(last) + MEMORY), fx.input)
    assert code == 3 and out == "patches: refused: the input's SHA-256 is not the manifest's target input_sha256", \
        (code, out)
    case("cli usage")
    code, out = run_cli("check", fx.input)
    assert code == 2 and out.startswith("usage: patch_manifest.py check"), (code, out)

    # tomllib is imported only by load(): without it, import works and load refuses by name.
    case("tomllib imported lazily")
    probe = ("import sys; sys.path.insert(0, sys.argv[1]); import patch_manifest as pm; "
             "assert 'tomllib' not in sys.modules, 'tomllib imported at module import'; "
             "sys.modules['tomllib'] = None\n"
             "try:\n    pm.load(sys.argv[2])\nexcept pm.PatchError as e:\n    print(e)")
    done = subprocess.run([sys.executable, "-B", "-c", probe, TOOLS, fx.write(good)],
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0 and done.stdout.strip() == "needs Python 3.11+ (tomllib)", (done.returncode,
                                                                                            done.stdout, done.stderr)


def main():
    checked = []
    with tempfile.TemporaryDirectory() as root:
        try:
            cases(Fixture(root), checked)
        except Exception as error:  # name the case that failed, then the reason
            print(f"patch_manifest: FAIL in case {checked[-1] if checked else '(setup)'!r}: "
                  f"{type(error).__name__}: {error}")
            return 1
    if len(checked) != EXPECTED_CASES:
        print(f"patch_manifest: FAIL: {len(checked)} cases ran, expected {EXPECTED_CASES}")
        return 1
    print(f"patch_manifest: PASS ({len(checked)} cases: schema, loader and input hash gate, "
          f"each refusal named; gate checked with a hash wrong only in its last and only in its first digit)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

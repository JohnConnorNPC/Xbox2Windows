"""Checks tools/startup/patch_manifest.py: the manifest schema, the loader and the input hash gate.

The input is a synthetic PE32+ built here (headers, .text, .data, .reloc with one DIR64 entry).
Manifests are written to a temporary directory. Every refusal case is a negative control: the
manifest must be refused whole, with the reason named. The hash gate is checked with a hash that
differs from the right one only in its last hex digit and only in its first, so a gate that
compares a prefix or a suffix fails here. Runs on any platform with Python 3.11+.
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


def synthetic_pe():
    """A minimal AMD64 PE32+: .text (ret), .data (16 marker bytes), .reloc (one DIR64 entry)."""
    file_align, section_align = 0x200, 0x1000
    sections = [(b".text", 0x1000, b"\xc3" + b"\xcc" * 15, 0x60000020),
                (b".data", 0x2000, bytes(range(0x40, 0x50)) + struct.pack("<Q", 0x140002000), 0xC0000040),
                (b".reloc", 0x3000, struct.pack("<IIHH", 0x2000, 12, (10 << 12) | 0x10, 0), 0x42000040)]
    headers = bytearray(0x200)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", headers, 0x84, 0x8664, len(sections), 0, 0, 0, 0xF0, 0x22)
    opt = 0x98
    struct.pack_into("<HBBIIIII", headers, opt, 0x20B, 14, 0, 0x200, 0x400, 0, 0x1000, 0x1000)
    struct.pack_into("<QII", headers, opt + 24, 0x140000000, section_align, file_align)
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


H1 = "11" * 32
H2 = "22" * 32
MEMORY = f'''
[[patch]]
id = "p001"
kind = "memory"
rva = "0x2000"
expect_sha256 = "{H1}"
bytes = "9090"
why = "synthetic fixture"
remove_when = "never; test input"
'''
DATA_BYTES = f'''
[[patch]]
id = "d001"
kind = "data"
path = "data/archive.bin"
expect_size = 4096
offset = 0x10
expect_sha256 = "{H2}"
bytes = "00ff"
why = "synthetic fixture"
remove_when = "never; test input"
'''
DATA_FILE = f'''
[[patch]]
id = "d002"
kind = "data"
path = "data/other.bin"
expect_size = 65536
offset = "0x100"
expect_sha256 = "{H2}"
file = "replacements/other.bin"
replacement_sha256 = "{H1.upper()}"
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


def run_cli(*args):
    done = subprocess.run([sys.executable, "-B", os.path.join(TOOLS, "patch_manifest.py"), *args],
                          capture_output=True, text=True, timeout=60)
    return done.returncode, done.stdout.strip()


def cases(fx, checked):
    good = target(fx.sha) + MEMORY + DATA_BYTES + DATA_FILE

    def case(name):
        checked.append(name)
        return name

    # Accepted: every field parsed, hashes lowercased, numbers from strings and TOML hex integers.
    case("valid manifest of three patches")
    path = fx.write(good)
    manifest = pm.check(path, fx.input)
    with open(path, "rb") as handle:
        assert manifest.sha256 == hashlib.sha256(handle.read()).hexdigest(), "manifest sha256 is not of its bytes"
    assert manifest.input_sha256 == fx.sha
    assert [p.id for p in manifest.patches] == ["p001", "d001", "d002"]
    mem, dbytes, dfile = manifest.patches
    assert (mem.kind, mem.rva, mem.data, mem.expect_sha256) == ("memory", 0x2000, b"\x90\x90", H1)
    assert (dbytes.path, dbytes.expect_size, dbytes.offset, dbytes.data, dbytes.file) == \
        ("data/archive.bin", 4096, 0x10, b"\x00\xff", None)
    assert (dfile.offset, dfile.file, dfile.replacement_sha256, dfile.data) == \
        (0x100, "replacements/other.bin", H1, None), "replacement_sha256 not lowercased"
    assert (manifest.count("memory"), manifest.count("data")) == (1, 2)

    case("uppercase input_sha256 matches")
    pm.check(fx.write(target(fx.sha.upper()) + MEMORY), fx.input)

    # The hash gate (negative controls).
    case("input hash wrong in its last digit")
    last = fx.sha[:-1] + ("0" if fx.sha[-1] != "0" else "1")
    refused(fx, target(last) + MEMORY, "is not the manifest's target")
    case("input hash wrong in its first digit")
    first = ("0" if fx.sha[0] != "0" else "1") + fx.sha[1:]
    refused(fx, target(first) + MEMORY, "is not the manifest's target")
    case("input is a directory")
    try:
        pm.check(fx.write(good), fx.root)
        raise AssertionError("a directory passed the gate")
    except pm.PatchError as error:
        assert "not a regular file" in str(error), error
    case("input is missing")
    try:
        pm.check(fx.write(good), os.path.join(fx.root, "absent.exe"))
        raise AssertionError("a missing input passed the gate")
    except pm.PatchError as error:
        assert "not a regular file" in str(error), error

    # Accountability fields.
    case("missing why")
    refused(fx, target(fx.sha) + edit(MEMORY, 'why = "synthetic fixture"\n', ""), "missing why")
    case("blank why")
    refused(fx, target(fx.sha) + edit(MEMORY, 'why = "synthetic fixture"', 'why = "  "'), "why: expected a non-empty")
    case("missing remove_when")
    refused(fx, target(fx.sha) + edit(MEMORY, 'remove_when = "never; test input"\n', ""), "missing remove_when")

    # Ids and kinds.
    case("duplicate id")
    refused(fx, target(fx.sha) + MEMORY + edit(DATA_BYTES, '"d001"', '"p001"'), "duplicate id")
    case("uppercase id")
    refused(fx, target(fx.sha) + edit(MEMORY, '"p001"', '"P001"'), "id must match")
    case("id of 65 characters")
    refused(fx, target(fx.sha) + edit(MEMORY, '"p001"', '"' + "a" * 65 + '"'), "id must match")
    case("kind hook")
    refused(fx, target(fx.sha) + edit(MEMORY, '"memory"', '"hook"'), "(stage 1) is not implemented")
    case("unknown kind")
    refused(fx, target(fx.sha) + edit(MEMORY, '"memory"', '"code"'), 'kind must be "memory" or "data"')

    # Unknown and cross-kind keys.
    case("unknown top-level key")
    refused(fx, "version = 1\n" + target(fx.sha) + MEMORY, "unknown top-level key(s): version")
    case("extra [target] key")
    refused(fx, target(fx.sha) + 'name = "x"\n' + MEMORY, "[target] must hold exactly input_sha256")
    case("unknown patch key")
    refused(fx, target(fx.sha) + edit(MEMORY, 'kind = "memory"', 'kind = "memory"\nsize = 2'), "unknown key(s)")
    case("memory patch with a data key")
    refused(fx, target(fx.sha) + edit(MEMORY, 'kind = "memory"', 'kind = "memory"\npath = "a"'),
            "unknown key(s) for kind memory: path")
    case("data patch with a memory key")
    refused(fx, target(fx.sha) + edit(DATA_BYTES, 'kind = "data"', 'kind = "data"\nrva = 0x10'),
            "unknown key(s) for kind data: rva")

    # Hashes, numbers and bytes.
    case("expect_sha256 of 63 digits")
    refused(fx, target(fx.sha) + edit(MEMORY, f'"{H1}"', f'"{H1[:-1]}"'), "expected 64 hex digits")
    case("expect_sha256 with a non-hex digit")
    refused(fx, target(fx.sha) + edit(MEMORY, f'"{H1}"', f'"{H1[:-1]}g"'), "expected 64 hex digits")
    case("input_sha256 not a string")
    refused(fx, "[target]\ninput_sha256 = 7\n" + MEMORY, "expected 64 hex digits")
    case("odd number of hex digits")
    refused(fx, target(fx.sha) + edit(MEMORY, '"9090"', '"909"'), "even number of hex digits")
    case("empty bytes")
    refused(fx, target(fx.sha) + edit(MEMORY, '"9090"', '""'), "even number of hex digits")
    case("bytes at the cap")
    pm.check(fx.write(target(fx.sha) + edit(MEMORY, '"9090"', '"' + "90" * pm.MAX_INLINE_BYTES + '"')), fx.input)
    case("bytes one past the cap")
    refused(fx, target(fx.sha) + edit(MEMORY, '"9090"', '"' + "90" * (pm.MAX_INLINE_BYTES + 1) + '"'),
            "more than 4096")
    case("rva past 32 bits")
    refused(fx, target(fx.sha) + edit(MEMORY, '"0x2000"', '"0x100000000"'), "out of range")
    case("rva as a TOML hex integer")
    manifest = pm.check(fx.write(target(fx.sha) + edit(MEMORY, '"0x2000"', "0x2000")), fx.input)
    assert manifest.patches[0].rva == 0x2000
    case("rva as a boolean")
    refused(fx, target(fx.sha) + edit(MEMORY, '"0x2000"', "true"), "expected an integer")
    case("rva as a decimal string")
    refused(fx, target(fx.sha) + edit(MEMORY, '"0x2000"', '"8192"'), "expected an integer")
    case("negative offset")
    refused(fx, target(fx.sha) + edit(DATA_BYTES, "offset = 0x10", "offset = -1"), "out of range")

    # Data paths and replacements.
    for bad in ("../x", "data/../x", "/data/x", "data\\\\x", "C:/data/x", "data//x", "./data/x", "data/"):
        case(f"data path {bad!r}")
        refused(fx, target(fx.sha) + edit(DATA_BYTES, '"data/archive.bin"', f'"{bad}"'), "expected a relative path")
    case("replacement file outside the manifest folder")
    refused(fx, target(fx.sha) + edit(DATA_FILE, '"replacements/other.bin"', '"../other.bin"'),
            "expected a relative path")
    case("data patch with bytes and file")
    refused(fx, target(fx.sha) + edit(DATA_FILE, 'file = ', 'bytes = "00"\nfile = '), "exactly one of bytes or file")
    case("data patch with neither bytes nor file")
    refused(fx, target(fx.sha) + edit(DATA_BYTES, 'bytes = "00ff"\n', ""), "exactly one of bytes or file")
    case("file without replacement_sha256")
    refused(fx, target(fx.sha) + edit(DATA_FILE, f'replacement_sha256 = "{H1.upper()}"\n', ""),
            "file and replacement_sha256 go together")
    case("bytes with replacement_sha256")
    refused(fx, target(fx.sha) + edit(DATA_BYTES, 'bytes = "00ff"', f'bytes = "00ff"\nreplacement_sha256 = "{H1}"'),
            "file and replacement_sha256 go together")
    case("bytes ending at expect_size")
    pm.check(fx.write(target(fx.sha) + edit(DATA_BYTES, "offset = 0x10", "offset = 4094")), fx.input)
    case("bytes past expect_size")
    refused(fx, target(fx.sha) + edit(DATA_BYTES, "offset = 0x10", "offset = 4095"), "past expect_size")

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
    refused(fx, target(fx.sha) + MEMORY + edit(DATA_BYTES, 'why = "synthetic fixture"\n', ""), "patch d001: missing why")

    # The command line.
    case("cli ok")
    code, out = run_cli("check", fx.write(good), fx.input)
    assert code == 0 and out.startswith("patches: ok manifest sha256=") and out.endswith("patches=3 (memory=1 data=2)"), \
        (code, out)
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
    if sys.version_info < (3, 11):
        print("patch_manifest: SKIP (needs Python 3.11+ for tomllib)")
        return 77
    checked = []
    with tempfile.TemporaryDirectory() as root:
        try:
            cases(Fixture(root), checked)
        except Exception as error:  # name the case that failed, then the reason
            print(f"patch_manifest: FAIL in case {checked[-1] if checked else '(setup)'!r}: "
                  f"{type(error).__name__}: {error}")
            return 1
    print(f"patch_manifest: PASS ({len(checked)} cases: schema, loader and input hash gate, "
          f"each refusal named; gate checked with a hash wrong only in its last and only in its first digit)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

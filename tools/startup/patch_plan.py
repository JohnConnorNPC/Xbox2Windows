"""Patch manifests: plan one manifest for the startup debugger (docs/experiments/patch-manifests.md).

usage: patch_plan.py check|plan <manifest.toml> <input>

tools/patch_manifest.py loads a manifest, checks its shape and gates it on its input's SHA-256. This
module plans what that loader returns: `memory` patches, replacement bytes at an RVA of the loaded
image (stage 2). tools/startup/debug_launch.py applies memory patches when X2W_PATCHES names a
manifest: prepare() before the process exists; at its CREATE_PROCESS debug event gate_image() on the
file the process was created from, then apply_memory(); verify_applied() again at the loader
breakpoint.

Every loader refusal is raised here as a PatchError with the loader's reason. On top of the loader's
rules a manifest is refused here when an id does not match [a-z0-9][a-z0-9._-]{0,63} (the run summary
joins ids with commas), when it has a patch kind other than memory, when one memory patch replaces
more than MAX_BYTES bytes, or when it has more than MAX_PATCHES patches.

`check` (load + hash gate) prints `patches: ok manifest sha256=<hex> patches=<n>` and exits 0;
`plan` also plans every memory patch against the input PE and adds ` planned`. A refusal prints
`patches: refused: <reason>` and exits 3. Usage errors exit 2. A manifest is accepted whole or
refused whole: one bad patch refuses all of them.

The loader, and with it tomllib, is imported only when a manifest is loaded.
"""
import dataclasses
import hashlib
import os
import re
import struct
import sys

# The loader, tools/patch_manifest.py.
TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
# The longest replacement of one memory patch, and the most [[patch]] entries in one manifest (the plan
# compares every patch with every base relocation and loader-written range).
MAX_BYTES = 4096
MAX_PATCHES = 4096
# The launcher switch that names a manifest, and the variables only a launcher may set for the child.
# child_env drops all of them: the title sees neither the manifest path nor a value left in the shell.
ENV = "X2W_PATCHES"
CHILD_ONLY = ("X2W_DATA_PATCH_MAP",)
CHILD_ONLY_PREFIX = "X2W_PATCH_"
# Tests only: X2W_PATCH_TEST_FAULT=apply|verify|image shortens the read of that step (see faulty_read).
TEST_FAULT = "X2W_PATCH_TEST_FAULT"
TEST_FAULTS = ("apply", "verify", "image")
# Base relocation types and the bytes each one rewrites; ABSOLUTE is block padding.
RELOC_SIZES = {0: 0, 3: 4, 10: 8}
RELOC_NAMES = {3: "HIGHLOW", 10: "DIR64"}


class PatchError(Exception):
    """A manifest, or the input it is checked against, is refused."""


@dataclasses.dataclass(frozen=True)
class Patch:
    id: str
    kind: str  # "memory"
    why: str
    remove_when: str
    rva: int
    expect_sha256: str  # lowercase hash of the len(data) original bytes at rva
    data: bytes  # the replacement, written as `bytes`


@dataclasses.dataclass(frozen=True)
class Manifest:
    path: str
    sha256: str  # of the manifest file's bytes
    input_sha256: str  # lowercase
    patches: tuple


def _loader():
    """tools/patch_manifest.py. It imports tomllib at its own import, so it is imported here at the first load."""
    if TOOLS not in sys.path:
        sys.path.append(TOOLS)
    try:
        import patch_manifest
    except ImportError as error:
        if error.name == "tomllib":
            raise PatchError("needs Python 3.11+ (tomllib)") from None
        raise
    return patch_manifest


def load(path, data):
    """The manifest at path, gated on data (the input's bytes, already read): a Manifest or PatchError."""
    loader = _loader()
    try:
        bound = loader.load_data(path, data)
    except OSError as error:
        raise PatchError(f"cannot read the manifest: {error.strerror or error}") from None
    except UnicodeDecodeError:
        raise PatchError("the manifest is not UTF-8") from None
    except loader.tomllib.TOMLDecodeError as error:
        raise PatchError(f"the manifest is not valid TOML: {error}") from None
    except ValueError as error:
        raise PatchError(str(error)) from None
    entries = bound["patches"]
    if len(entries) > MAX_PATCHES:
        raise PatchError(f"{len(entries)} [[patch]] entries, more than {MAX_PATCHES}")
    patches = []
    for entry in entries:
        if not ID_RE.match(entry["id"]):
            raise PatchError(f"patch {entry['id']!r}: id must match [a-z0-9][a-z0-9._-]{{0,63}}")
        where = f"patch {entry['id']}"
        if entry["kind"] != "memory":
            raise PatchError(f"{where}: kind \"{entry['kind']}\" has no consumer in the startup debugger")
        if len(entry["bytes"]) > MAX_BYTES:
            raise PatchError(f"{where} bytes: {len(entry['bytes'])} bytes, more than {MAX_BYTES}")
        patches.append(Patch(id=entry["id"], kind=entry["kind"], why=entry["why"], remove_when=entry["remove_when"],
                             rva=entry["rva"], expect_sha256=entry["expect_sha256"], data=entry["bytes"]))
    return Manifest(path=os.path.abspath(path), sha256=bound["manifest_sha256"], input_sha256=bound["input_sha256"],
                    patches=tuple(patches))


def _read_input(input_path):
    if not os.path.isfile(input_path):
        raise PatchError("the input is not a regular file")
    try:
        with open(input_path, "rb") as handle:
            return handle.read()
    except OSError as error:
        raise PatchError(f"cannot read the input: {error.strerror or error}") from None


@dataclasses.dataclass(frozen=True)
class Section:
    name: str
    va: int
    end: int  # va + min(VirtualSize, SizeOfRawData): the bytes the file supplies to the image
    raw: int  # file offset of va


@dataclasses.dataclass(frozen=True)
class Image:
    image_base: int
    size_of_image: int
    sections: tuple
    directories: tuple  # (rva, size) per data directory

    def offset(self, rva, size, what):
        """File offset of [rva, rva + size), which must lie in one section's file-backed bytes."""
        for section in self.sections:
            if section.va <= rva and rva + size <= section.end:
                return section.raw + rva - section.va
        raise PatchError(f"the input's {what} at {rva:#x} is outside the file-backed section bytes")

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)


def parse_pe(data):
    """The section table and data directories of a PE32+ image (PE/COFF specification offsets).

    A section with file-backed bytes must start at a file offset that is a multiple of 0x200."""
    try:
        if data[:2] != b"MZ":
            raise PatchError("the input is not a PE image (no MZ signature)")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise PatchError("the input is not a PE image (no PE signature)")
        count, opt_size = struct.unpack_from("<H12xH", data, pe + 6)
        opt = pe + 24
        if struct.unpack_from("<H", data, opt)[0] != 0x20B:
            raise PatchError("the input is not a PE32+ image")
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        dir_count = min(struct.unpack_from("<I", data, opt + 108)[0], 16)
        directories = tuple(struct.unpack_from("<II", data, opt + 112 + 8 * i) for i in range(dir_count))
        sections = []
        for i in range(count):
            name, vsize, va, raw_size, raw = struct.unpack_from("<8sIIII", data, opt + opt_size + 40 * i)
            if raw + min(vsize, raw_size) > len(data):
                raise PatchError(f"section {i} runs past the end of the input")
            if va + min(vsize, raw_size) > size_of_image:
                raise PatchError(f"section {i} ends past SizeOfImage")
            if raw % 0x200 and min(vsize, raw_size):
                # pefile 2024.8.26 (requirements-dev.txt; the CPU lifter's reader) maps such a section from raw
                # rounded down to 0x200, whatever FileAlignment says, while this plan hashes the bytes at raw.
                raise PatchError(f"section {i} starts at file offset {raw:#x}, not a multiple of 0x200: "
                                 f"readers disagree on its bytes")
            sections.append(Section(name.rstrip(b"\0").decode("latin-1"), va, va + min(vsize, raw_size), raw))
    except struct.error:
        raise PatchError("the input is not a PE image (truncated headers)") from None
    return Image(image_base, size_of_image, tuple(sorted(sections, key=lambda s: s.va)), directories)


def _qword(data, image, rva, what):
    return struct.unpack_from("<Q", data, image.offset(rva, 8, what))[0]


def relocation_ranges(data, image):
    """(start, end, label) for every byte a base relocation rewrites; refuses unknown types."""
    rva, size = image.directory(5)
    ranges = []
    if not size:
        return ranges
    table = image.offset(rva, size, "base relocation directory")
    pos = 0
    while pos < size:
        if size - pos < 8:
            raise PatchError("the input's base relocation directory ends inside a block header")
        page, block = struct.unpack_from("<II", data, table + pos)
        if block < 8 or block % 2 or pos + block > size:
            raise PatchError(f"the input's base relocation block at {rva + pos:#x} has size {block}")
        for (entry,) in struct.iter_unpack("<H", data[table + pos + 8:table + pos + block]):
            kind, start = entry >> 12, page + (entry & 0xFFF)
            if kind not in RELOC_SIZES:
                raise PatchError(f"unsupported base relocation type {kind} at {start:#x}")
            if RELOC_SIZES[kind]:
                ranges.append((start, start + RELOC_SIZES[kind], f"base relocation {RELOC_NAMES[kind]}"))
        pos += block
    return ranges


def _thunk_count(data, image, rva, what):
    count = 0
    while _qword(data, image, rva + 8 * count, what):
        count += 1
    return count


def loader_written_ranges(data, image):
    """(start, end, label) for bytes the loader writes after mapping: import address tables, the TLS
    index slot and the load-config slots (security cookie, control-flow guard, XFG and CastGuard
    pointers, GuardMemcpy). Inputs with delay-load imports are refused. A directory counts as present
    when its RVA is set, whatever its Size says; every structure read must lie in one section's
    file-backed bytes (image.offset refuses otherwise)."""
    ranges = []
    # Imports: each FirstThunk array, terminator included. The loaders read descriptors from the directory's
    # RVA up to the null one and do not use its Size, so neither does this walk; a descriptor outside the
    # section's file-backed bytes refuses (image.offset).
    rva, pos = image.directory(1)[0], 0
    while rva:
        thunks, _, _, name, first = struct.unpack_from("<5I", data, image.offset(rva + pos, 20, "import descriptor"))
        if not (thunks or name or first):
            break
        count = _thunk_count(data, image, thunks or first, "import name table")
        ranges.append((first, first + 8 * (count + 1), "import address table"))
        pos += 20
    if any(image.directory(13)):
        raise PatchError("the input has delay-load imports, which memory patches do not model")
    rva, _ = image.directory(9)  # TLS: the loader stores the module's TLS index
    if rva:
        index = _qword(data, image, rva + 16, "TLS directory")
        if index:
            ranges.append((index - image.image_base, index - image.image_base + 4, "TLS index"))
    # Load config: IMAGE_LOAD_CONFIG_DIRECTORY64 offsets (winnt.h). A slot counts when the structure's own
    # Size field or the directory's Size covers it, so a loader that trusts either one is covered.
    rva, size = image.directory(10)
    if rva:
        config = image.offset(rva, 4, "load configuration")
        length = max(struct.unpack_from("<I", data, config)[0], size)
        for field, label in ((0x58, "security cookie"), (0x70, "guard check function pointer"),
                             (0x78, "guard dispatch function pointer"), (0x118, "XFG check function pointer"),
                             (0x120, "XFG dispatch function pointer"), (0x128, "XFG table dispatch function pointer"),
                             (0x130, "CastGuard failure mode"), (0x138, "guard memcpy function pointer")):
            if length >= field + 8:
                va = _qword(data, image, rva + field, "load configuration")
                if va:
                    ranges.append((va - image.image_base, va - image.image_base + 8, label))
    return ranges


def plan_memory(manifest, data):
    """Checks every memory patch against the input PE bytes; returns the patches or raises PatchError.

    A range must lie in one section's file-backed bytes ([VirtualAddress, VirtualAddress +
    min(VirtualSize, SizeOfRawData))), must not touch a base relocation or a loader-written slot, and
    the input's bytes there must hash to expect_sha256. The loader has refused patches that overlap
    each other and ranges that end past 2**32; parse_pe refuses sections that end past SizeOfImage, and
    ends are Python integers, so a range cannot wrap."""
    image = parse_pe(data)
    blocked = relocation_ranges(data, image) + loader_written_ranges(data, image)
    first_va = image.sections[0].va if image.sections else image.size_of_image
    for patch in manifest.patches:
        start, end = patch.rva, patch.rva + len(patch.data)
        where = f"patch {patch.id}: range {start:#x}-{end:#x}"
        section = next((s for s in image.sections if s.va <= start < s.end), None)
        if section is None:
            raise PatchError(f"{where} is in the headers" if start < first_va else
                             f"{where} is outside every section's file-backed bytes")
        if end > section.end:
            later = next((s for s in image.sections if s.va > section.va), None)
            raise PatchError(f"{where} crosses from section {section.name} into {later.name}"
                             if later and end > later.va else
                             f"{where} runs past the file-backed bytes of section {section.name}")
        for low, high, label in blocked:
            if start < high and low < end:
                kind = "base relocation" if label.startswith("base relocation") else "loader-written range"
                raise PatchError(f"{where} overlaps a {kind} ({label} at {low:#x})")
        offset = section.raw + start - section.va
        if hashlib.sha256(data[offset:offset + len(patch.data)]).hexdigest() != patch.expect_sha256:
            raise PatchError(f"patch {patch.id}: the input's bytes at {start:#x} do not match expect_sha256")
    return manifest.patches


def prepare(environ, exe_path):
    """(manifest, plans) for the EXE the launcher starts, or (None, ()) without X2W_PATCHES.

    The EXE is read once: the hash gate and the plan use the same bytes."""
    path = environ.get(ENV)
    if not path:
        return None, ()
    data = _read_input(exe_path)
    manifest = load(path, data)
    return manifest, plan_memory(manifest, data)


def gate_image(manifest, read):
    """Refuses unless the file the process was created from hashes to the manifest's input_sha256.

    prepare() gated the EXE by its path before CreateProcessW opened that path again; debug_launch hands
    this a reader of the CREATE_PROCESS event's file handle, the file the process maps. read(offset,
    size) returns the bytes at offset (b"" at the end of the file) or raises PatchError."""
    digest, offset = hashlib.sha256(), 0
    while True:
        chunk = read(offset, 1 << 20)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    if digest.hexdigest() != manifest.input_sha256:
        raise PatchError("the image the process was created from is not the manifest's target input_sha256 "
                         "(the EXE changed after the gate)")


def verify_applied(plans, base, read, when):
    """Refuses unless memory at every patch range holds its replacement."""
    for patch in plans:
        if read(base + patch.rva, len(patch.data)) != patch.data:
            raise PatchError(f"patch {patch.id}: memory at +{patch.rva:#x} does not hold the replacement {when}")


def apply_memory(plans, base, read, write):
    """Writes every patch into a process whose image is at base.

    Every range is read and hashed before the first write; a short read or a different hash
    refuses with nothing written. Then each range is written (write returns false on any failed
    step) and read back. A refusal after the first write can leave earlier ranges written: the
    caller must end the process before it runs (debug_launch never continues it)."""
    for patch in plans:
        found = read(base + patch.rva, len(patch.data))
        if len(found) != len(patch.data):
            raise PatchError(f"patch {patch.id}: read {len(found)} of {len(patch.data)} bytes at +{patch.rva:#x}")
        if hashlib.sha256(found).hexdigest() != patch.expect_sha256:
            raise PatchError(f"patch {patch.id}: the bytes in memory at +{patch.rva:#x} do not match expect_sha256")
    for patch in plans:
        if not write(base + patch.rva, patch.data):
            raise PatchError(f"patch {patch.id}: writing +{patch.rva:#x} failed")
    verify_applied(plans, base, read, "after the write")


def test_fault(environ):
    """The step named by X2W_PATCH_TEST_FAULT ("apply", "verify" or "image"), or None. Test-only."""
    value = environ.get(TEST_FAULT)
    if not value:
        return None
    if value not in TEST_FAULTS:
        raise PatchError(f"{TEST_FAULT} must be apply, verify or image (a test-only switch)")
    return value


def faulty_read(read):
    """read() with the last byte of each result dropped: a short read. It changes only what was read,
    never the expected bytes. apply_memory refuses a short read by its length and verify_applied by its
    compare, whatever the process memory holds. gate_image, which reads on from where each read ended,
    then hashes the file without its last byte. So a test fault can make a step fail but never pass."""
    def wrapped(address, size):
        return read(address, size)[:-1]
    return wrapped


def patch_at(plans, rva):
    """The id of the patch whose range holds rva, or None."""
    return next((p.id for p in plans if p.rva <= rva < p.rva + len(p.data)), None)


def report_line(manifest):
    """The run summary's patch line."""
    if manifest is None:
        return "patches: none"
    return f"patches: manifest sha256={manifest.sha256} active={','.join(p.id for p in manifest.patches)}"


def unverified_line(manifest):
    """The summary line when patches were written but the process ended before the loader breakpoint."""
    return (f"patches: unverified manifest sha256={manifest.sha256} active={','.join(p.id for p in manifest.patches)} "
            f"(written; the process ended before the loader-breakpoint re-check)")


def child_env(environ):
    """environ without the launcher switch (ENV) and the variables only a launcher sets for the child
    (names compared case-blind, as Windows does), so a value left in the shell cannot reach the title
    unreported."""
    return {k: v for k, v in environ.items()
            if k.upper() != ENV and k.upper() not in CHILD_ONLY and not k.upper().startswith(CHILD_ONLY_PREFIX)}


def check(manifest_path, input_path):
    """The manifest gated on the file at input_path, accepted whole, or PatchError."""
    return load(manifest_path, _read_input(input_path))


def main(argv):
    if len(argv) != 4 or argv[1] not in ("check", "plan"):
        print(__doc__.splitlines()[2])
        return 2
    try:
        if argv[1] == "plan":
            manifest, _ = prepare({ENV: argv[2]}, argv[3])
        else:
            manifest = check(argv[2], argv[3])
    except PatchError as error:
        print(f"patches: refused: {error}")
        return 3
    print(f"patches: ok manifest sha256={manifest.sha256} patches={len(manifest.patches)}"
          + (" planned" if argv[1] == "plan" else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

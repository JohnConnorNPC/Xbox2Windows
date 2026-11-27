"""Patch manifests: load, validate and hash-gate one manifest (docs/experiments/patch-manifests.md).

usage: patch_manifest.py check <manifest.toml> <input>

A patch manifest is a TOML file bound to one input file by SHA-256. It lists `memory` patches
(bytes at an RVA of the loaded image) and `data` patches (a byte range of a data file). This module
only reads and checks manifests; nothing here applies a patch.

`check` prints `patches: ok manifest sha256=<hex> patches=<n> (memory=<n> data=<n>)` and exits 0,
or prints `patches: refused: <reason>` and exits 3. Usage errors exit 2. A manifest is accepted
whole or refused whole: one bad patch refuses all of them.

Hashes are 64 hex digits in either case; they are compared in lowercase. tomllib (Python 3.11+)
is imported only when a manifest is loaded, so importing this module works on older versions.
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
import re
import sys

SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
HEX_BYTES_RE = re.compile(r"(?:[0-9a-fA-F]{2})+\Z")
HEX_NUMBER_RE = re.compile(r"0x[0-9a-fA-F]{1,16}\Z")
# The longest replacement written as `bytes`; a longer data replacement uses `file`.
MAX_INLINE_BYTES = 4096

TOP_KEYS = {"target", "patch"}
TARGET_KEYS = {"input_sha256"}
COMMON_KEYS = {"id", "kind", "why", "remove_when"}
MEMORY_KEYS = {"rva", "expect_sha256", "bytes"}
DATA_REQUIRED = {"path", "expect_size", "offset", "expect_sha256"}
DATA_OPTIONAL = {"bytes", "file", "replacement_sha256"}


class PatchError(Exception):
    """A manifest, or the input it is checked against, is refused."""


@dataclasses.dataclass(frozen=True)
class Patch:
    id: str
    kind: str  # "memory" or "data"
    why: str
    remove_when: str
    expect_sha256: str  # lowercase hash of the original bytes the patch replaces
    rva: int | None = None  # memory
    path: str | None = None  # data: relative to the data directory, "/" separators
    expect_size: int | None = None  # data: size of the original file
    offset: int | None = None  # data: first replaced byte in the original file
    data: bytes | None = None  # replacement written inline as `bytes`
    file: str | None = None  # data: replacement file, relative to the manifest's directory
    replacement_sha256: str | None = None  # data: lowercase hash of `file`


@dataclasses.dataclass(frozen=True)
class Manifest:
    path: str
    sha256: str  # of the manifest file's bytes
    input_sha256: str  # lowercase
    patches: tuple

    def count(self, kind):
        return sum(p.kind == kind for p in self.patches)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256(where, value):
    if not isinstance(value, str) or not SHA256_RE.match(value):
        raise PatchError(f"{where}: expected 64 hex digits")
    return value.lower()


def _text(where, value):
    if not isinstance(value, str) or not value.strip():
        raise PatchError(f"{where}: expected a non-empty string")
    return value


def _number(where, value, bits):
    """A TOML integer or a "0x..." string, from 0 up to 2**bits - 1."""
    if isinstance(value, str) and HEX_NUMBER_RE.match(value):
        value = int(value, 16)
    elif isinstance(value, bool) or not isinstance(value, int):
        raise PatchError(f"{where}: expected an integer or a \"0x...\" hex string")
    if not 0 <= value < 1 << bits:
        raise PatchError(f"{where}: out of range")
    return value


def _hex_bytes(where, value):
    if not isinstance(value, str) or not HEX_BYTES_RE.match(value):
        raise PatchError(f"{where}: expected an even number of hex digits")
    data = bytes.fromhex(value)
    if len(data) > MAX_INLINE_BYTES:
        raise PatchError(f"{where}: {len(data)} bytes, more than {MAX_INLINE_BYTES}")
    return data


def _relative_path(where, value):
    """A relative path with "/" separators that cannot leave its base directory."""
    if not isinstance(value, str) or not value:
        raise PatchError(f"{where}: expected a relative path")
    parts = value.split("/")
    if "\\" in value or ":" in value or "\0" in value or any(p in ("", ".", "..") for p in parts):
        raise PatchError(f"{where}: expected a relative path with \"/\" separators and no \".\" or \"..\" parts")
    return value


def _patch(index, entry):
    where = f"patch[{index}]"
    if not isinstance(entry, dict):
        raise PatchError(f"{where}: expected a table")
    raw_id = entry.get("id")
    if not isinstance(raw_id, str) or not ID_RE.match(raw_id):
        raise PatchError(f"{where}: id must match [a-z0-9][a-z0-9._-]{{0,63}}")
    where = f"patch {raw_id}"
    kind = entry.get("kind")
    if kind == "hook":
        raise PatchError(f"{where}: kind \"hook\" (stage 1) is not implemented")
    if kind == "memory":
        required, optional = MEMORY_KEYS, set()
    elif kind == "data":
        required, optional = DATA_REQUIRED, DATA_OPTIONAL
    else:
        raise PatchError(f"{where}: kind must be \"memory\" or \"data\"")
    unknown = set(entry) - COMMON_KEYS - required - optional
    if unknown:
        raise PatchError(f"{where}: unknown key(s) for kind {kind}: {', '.join(sorted(unknown))}")
    missing = (COMMON_KEYS | required) - set(entry)
    if missing:
        raise PatchError(f"{where}: missing {', '.join(sorted(missing))}")
    common = dict(id=raw_id, kind=kind, why=_text(f"{where} why", entry["why"]),
                  remove_when=_text(f"{where} remove_when", entry["remove_when"]),
                  expect_sha256=_sha256(f"{where} expect_sha256", entry["expect_sha256"]))
    if kind == "memory":
        return Patch(**common, rva=_number(f"{where} rva", entry["rva"], 32),
                     data=_hex_bytes(f"{where} bytes", entry["bytes"]))
    if ("bytes" in entry) == ("file" in entry):
        raise PatchError(f"{where}: needs exactly one of bytes or file")
    if ("file" in entry) != ("replacement_sha256" in entry):
        raise PatchError(f"{where}: file and replacement_sha256 go together")
    size = _number(f"{where} expect_size", entry["expect_size"], 63)
    offset = _number(f"{where} offset", entry["offset"], 63)
    patch = Patch(**common, path=_relative_path(f"{where} path", entry["path"]), expect_size=size, offset=offset)
    if "bytes" in entry:
        data = _hex_bytes(f"{where} bytes", entry["bytes"])
        if offset + len(data) > size:
            raise PatchError(f"{where}: offset + length of bytes is past expect_size")
        return dataclasses.replace(patch, data=data)
    return dataclasses.replace(patch, file=_relative_path(f"{where} file", entry["file"]),
                               replacement_sha256=_sha256(f"{where} replacement_sha256",
                                                          entry["replacement_sha256"]))


def load(path):
    """Read and validate a manifest; returns a Manifest or raises PatchError."""
    try:
        import tomllib
    except ImportError:
        raise PatchError("needs Python 3.11+ (tomllib)") from None
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as error:
        raise PatchError(f"cannot read the manifest: {error.strerror or error}") from None
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise PatchError("the manifest is not UTF-8") from None
    except tomllib.TOMLDecodeError as error:
        raise PatchError(f"the manifest is not valid TOML: {error}") from None
    unknown = set(document) - TOP_KEYS
    if unknown:
        raise PatchError(f"unknown top-level key(s): {', '.join(sorted(unknown))}")
    target = document.get("target")
    if not isinstance(target, dict):
        raise PatchError("missing [target]")
    if set(target) != TARGET_KEYS:
        raise PatchError("[target] must hold exactly input_sha256")
    entries = document.get("patch")
    if not isinstance(entries, list) or not entries:
        raise PatchError("missing [[patch]] entries")
    patches = tuple(_patch(i, entry) for i, entry in enumerate(entries))
    seen = set()
    for patch in patches:
        if patch.id in seen:
            raise PatchError(f"patch {patch.id}: duplicate id")
        seen.add(patch.id)
    return Manifest(path=os.path.abspath(path), sha256=hashlib.sha256(raw).hexdigest(),
                    input_sha256=_sha256("[target] input_sha256", target["input_sha256"]), patches=patches)


def gate(manifest, input_path):
    """Refuses unless input_path is a regular file whose SHA-256 is the manifest's target."""
    if not os.path.isfile(input_path):
        raise PatchError("the input is not a regular file")
    try:
        actual = sha256_file(input_path)
    except OSError as error:
        raise PatchError(f"cannot read the input: {error.strerror or error}") from None
    if actual != manifest.input_sha256:
        raise PatchError("the input's SHA-256 is not the manifest's target input_sha256")


def check(manifest_path, input_path):
    """load + gate: the manifest, accepted whole, or PatchError."""
    manifest = load(manifest_path)
    gate(manifest, input_path)
    return manifest


def main(argv):
    if len(argv) != 4 or argv[1] != "check":
        print(__doc__.splitlines()[2])
        return 2
    try:
        manifest = check(argv[2], argv[3])
    except PatchError as error:
        print(f"patches: refused: {error}")
        return 3
    print(f"patches: ok manifest sha256={manifest.sha256} patches={len(manifest.patches)} "
          f"(memory={manifest.count('memory')} data={manifest.count('data')})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

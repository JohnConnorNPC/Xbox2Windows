"""Patch manifests: load, validate and hash-gate one manifest (docs/experiments/patch-manifests.md).

usage: patch_manifest.py check <manifest.toml> <input>

A patch manifest is a TOML file bound to one input file by SHA-256. It lists `memory` patches:
replacement bytes at an RVA of the loaded image. This module only reads and checks manifests;
nothing here applies a patch. Kinds of later stages (`hook`, stage 1; `data`, stage 3) are refused.

`check` prints `patches: ok manifest sha256=<hex> patches=<n>` and exits 0, or prints
`patches: refused: <reason>` and exits 3. Usage errors exit 2. A manifest is accepted whole or
refused whole: one bad patch refuses all of them.

Hashes are 64 hex digits in either case; they are stored and compared in lowercase. tomllib is
imported only when a manifest is loaded.
"""
import dataclasses
import hashlib
import os
import re
import sys

SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
HEX_BYTES_RE = re.compile(r"(?:[0-9a-fA-F]{2})+\Z")
HEX_NUMBER_RE = re.compile(r"0x[0-9a-fA-F]{1,16}\Z")
# The longest replacement of one memory patch.
MAX_BYTES = 4096

TOP_KEYS = {"target", "patch"}
TARGET_KEYS = {"input_sha256"}
PATCH_KEYS = {"id", "kind", "why", "remove_when", "rva", "expect_sha256", "bytes"}
NOT_IMPLEMENTED = {"hook": "stage 1", "data": "stage 3"}


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


def _rva(where, value):
    """A TOML integer or a "0x..." string, below 2**32."""
    if isinstance(value, str) and HEX_NUMBER_RE.match(value):
        value = int(value, 16)
    elif isinstance(value, bool) or not isinstance(value, int):
        raise PatchError(f"{where}: expected an integer or a \"0x...\" hex string")
    if not 0 <= value < 1 << 32:
        raise PatchError(f"{where}: out of range")
    return value


def _hex_bytes(where, value):
    if not isinstance(value, str) or not HEX_BYTES_RE.match(value):
        raise PatchError(f"{where}: expected an even number of hex digits")
    data = bytes.fromhex(value)
    if len(data) > MAX_BYTES:
        raise PatchError(f"{where}: {len(data)} bytes, more than {MAX_BYTES}")
    return data


def _patch(index, entry):
    where = f"patch[{index}]"
    if not isinstance(entry, dict):
        raise PatchError(f"{where}: expected a table")
    raw_id = entry.get("id")
    if not isinstance(raw_id, str) or not ID_RE.match(raw_id):
        raise PatchError(f"{where}: id must match [a-z0-9][a-z0-9._-]{{0,63}}")
    where = f"patch {raw_id}"
    kind = entry.get("kind")
    if kind in NOT_IMPLEMENTED:
        raise PatchError(f"{where}: kind \"{kind}\" ({NOT_IMPLEMENTED[kind]}) is not implemented")
    if kind != "memory":
        raise PatchError(f"{where}: kind must be \"memory\"")
    unknown = set(entry) - PATCH_KEYS
    if unknown:
        raise PatchError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
    missing = PATCH_KEYS - set(entry)
    if missing:
        raise PatchError(f"{where}: missing {', '.join(sorted(missing))}")
    return Patch(id=raw_id, kind=kind, why=_text(f"{where} why", entry["why"]),
                 remove_when=_text(f"{where} remove_when", entry["remove_when"]),
                 rva=_rva(f"{where} rva", entry["rva"]),
                 expect_sha256=_sha256(f"{where} expect_sha256", entry["expect_sha256"]),
                 data=_hex_bytes(f"{where} bytes", entry["bytes"]))


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
    print(f"patches: ok manifest sha256={manifest.sha256} patches={len(manifest.patches)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

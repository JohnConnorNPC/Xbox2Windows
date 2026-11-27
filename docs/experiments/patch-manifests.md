# Patch manifests: schema, loader and input hash gate

Refs [#3037](https://github.com/R0Y00/Xbox2Windows/issues/3037) and discussion
[#3026](https://github.com/R0Y00/Xbox2Windows/discussions/3026). A patch manifest describes
adjustments for one specific input without changing the input or its data files on disk. This
note covers the first part: the file format, the loader and the hash gate in
`tools/startup/patch_manifest.py`. No launcher applies patches yet. Applying `memory` patches
(stage 2) is a separate follow-up. `data` patches arrive with stage 3, and stage 1 translator hooks
are not implemented. Until then a manifest that uses `kind = "data"` or `kind = "hook"` is refused.

## Repository boundary

The repository holds the mechanism, the schema and synthetic fixtures. Manifests for real inputs
stay local. The suggested location is `game-files/patches/<input sha256>.toml`, which is gitignored.
A manifest stores hashes of the bytes it replaces, never the bytes themselves. Its replacement
bytes are our own.

## Format

A manifest is UTF-8 TOML (read with `tomllib`, Python 3.11 or newer). The top level holds exactly
`[target]` and one or more `[[patch]]` tables:

```toml
[target]
input_sha256 = "<SHA-256 of the exact input file this manifest was written for>"

[[patch]]
id = "p001"
kind = "memory"
rva = "0x2000"                       # TOML integer or "0x..." string, below 2**32
expect_sha256 = "<SHA-256 of the original bytes being replaced>"
bytes = "9090"                       # replacement, hex, 1 to 4096 bytes
why = "<issue or root cause>"
remove_when = "<condition under which the patch can go>"
```

`expect_sha256` is the hash of exactly `len(bytes)` original bytes starting at `rva`: a patch
replaces as many bytes as it writes.

The loader enforces these rules and refuses the whole manifest on the first violation:

- Every patch has `id`, `kind`, `why`, `remove_when`, `rva`, `expect_sha256` and `bytes`. `why` and
  `remove_when` must be non-empty, so a patch cannot quietly hide a translator bug.
- `id` matches `[a-z0-9][a-z0-9._-]{0,63}` and is unique in the manifest.
- `kind` is `memory`. Any other key, at the top level, in `[target]` or in a patch, is refused.
- A hash is 64 hex digits, upper or lower case. Hashes are stored and compared in lower case.
- `bytes` is an even number of hex digits with no spaces, at most 4096 bytes.

The manifest's identity is the SHA-256 of its file bytes. The hash gate hashes the input file and
refuses the manifest unless the result equals `[target] input_sha256`. A refusal applies nothing.
This part does not check `rva` against the input's sections; the stage that applies the patches
does.

## Check a manifest

```bash
python3 -B tools/startup/patch_manifest.py check <manifest.toml> <input>
```

The command prints `patches: ok manifest sha256=<hex> patches=<n>` and exits 0, or prints
`patches: refused: <reason>` and exits 3. A usage error exits 2.

## Test

```bash
python3 -B tests/patch_manifest_check.py
```

Expected result: `patch_manifest: PASS (46 cases: ...)`, exit 0. The check fails if a different
number of cases runs. The input is a synthetic PE32+ built by the test, and the first case parses
it back and checks its layout. Every refusal case is a negative control that must be refused with
its reason named. The gate is checked with the correct hash in upper case (accepted), and with
hashes that are wrong only in the last hex digit or only in the first (both refused), so a gate
that compares only a prefix or a suffix fails the check. The fixture hashes contain letters and one
is written in upper case, so a hash that is not lowercased also fails it. The Linux CI job runs the
check from `tests/checks/python-linux/patch_manifest.txt`.

Measured: the check above on Linux with Python 3.13. Not measured: Python older than 3.11.
No patch is applied by this part.

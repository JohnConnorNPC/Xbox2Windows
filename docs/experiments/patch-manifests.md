# Patch manifests: schema, loader and hash gate

A patch manifest describes adjustments to a source-translated build without changing the input
file on disk. This first step defines the format and the loader, `tools/patch_manifest.py`.
Nothing applies a patch yet. Memory patches at load time, data patches in the file layer and
translator hooks will each come in their own change ([#3037](https://github.com/R0Y00/Xbox2Windows/issues/3037)).

## Format

```toml
[target]
input_sha256 = "<sha256 of the exact input file>"

[[patch]]
id = "p001"
kind = "memory"
why = "<issue or root cause>"
remove_when = "<condition under which the patch can go>"
rva = 0x1010                      # first byte to replace
expect_sha256 = "<sha256 of the original bytes at rva, as many as the replacement>"
bytes = "90c3"                    # the replacement, lowercase hex
```

- **Hash gate:** the manifest applies only to the file whose SHA-256 equals `input_sha256`. Any other input is refused with `manifest is for another input`.
- **Bytes already read:** `load_data(manifest, data)` is `load` for a caller that has already read the input: it hashes `data`, so the bytes that pass the gate are the bytes the caller goes on to use, even if the file changes in between.
- **No partial apply:** the whole manifest is validated, and the input hash compared, before the loader returns anything. One bad patch refuses the manifest.
- **Every patch** needs a unique `id`, a `kind`, and non-empty `why` and `remove_when`.
- **Strict keys:** unknown keys and missing keys are refused at every level, so a misspelled key fails instead of being ignored.
- **Nesting:** `tomllib` recurses once per nested array or inline table. A manifest nested past the interpreter's recursion limit is refused with `manifest is nested too deeply to parse`, and the CLI exits with status 1 instead of printing a traceback.
- **Kinds:** `kind` must be a string, and `memory` and `shader` are defined. `hook`, `data` and any other kind are refused as `not supported`.
- **Memory patches:** `bytes` must be non-empty, and every byte it replaces needs an RVA below 2^32: a 1-byte patch at `0xffffffff` is accepted, a 2-byte one is not. Two memory patches may not overlap. Whether the span lies in a mapped section is checked later, by the runtime stage.
- **Original bytes are never stored:** `expect_sha256` is a hash of the bytes the patch replaces. The loader only checks its shape; the memory stage will compare it with the mapped image.
- **Reporting:** the loader returns `manifest_sha256`, the SHA-256 of the manifest file's bytes, with the patch ids, for run reports to record.

### Shader patches

A shader patch names the translation files of one shader cache key, for the runtime to read instead
of the shader cache's. The loader checks their shape only. Reading and hashing the files, and
serving them, belong to a later consumer; none exists yet.

```toml
[[patch]]
id = "s001"
kind = "shader"
why = "<issue or root cause>"
remove_when = "<condition under which the patch can go>"
key = "0123456789abcdef"          # the cache key, 16 lowercase hex digits
pipeline = "compute"              # graphics, compute or mesh86
revision = "x2w-startup-shader-29cs"
files = [{ ext = ".txt", file = "s001.txt", sha256 = "<sha256 of the file>" },
         { ext = ".cs.cso", file = "s001.cs.cso", sha256 = "<sha256 of the file>" }]
```

| `pipeline` | `revision` form | Files the runtime reads | Required |
|---|---|---|---|
| `graphics` | `x2w-startup-shader-<n>` | `.txt`, `.vs.cso`, `.ps.cso` | all three |
| `compute` | `x2w-startup-shader-<n>cs` | `.txt`, `.cs.cso` | both |
| `mesh86` | `x2w-startup-mesh-86-<n>` | `.mesh86.txt`, `.ms.cso`, `.ps.cso` | `.mesh86.txt`, `.ms.cso` |

- **Revision:** `revision` must have the form of the pipeline's key revision in the runtime (`src/startup_stubs/d3d12_draw.inl`, `src/startup_stubs/mesh86_cache.inl`), where `<n>` is a number without leading zeros, so another pipeline's revision is refused. The loader does not check that `<n>` is the runtime's current one: the runtime bumps it often, and a new revision changes every key. A later consumer that serves the files must compare it with the runtime; none exists yet.
- **Files:** each entry is a table of exactly `ext`, `file` and `sha256`. `ext` is one of the pipeline's files and is listed once; the required ones must all be there. `file` is a non-empty path for the consumer to resolve; `sha256` is lowercase.
- **One patch per key:** two shader patches for the same `key` are refused. Shader patches take no part in the memory overlap check.

Input-specific manifests stay local under `game-files/patches/`, which is gitignored. Do not
publish them or the hashes in them.

## Check

```bash
./out/pe-env/bin/python -B tests/patch_manifest_check.py
python -B tools/patch_manifest.py MANIFEST INPUT
```

On Windows: `ctest --preset dev --no-tests=error -R '^patch_manifest_controls$' -V`.

The check builds a synthetic PE32+ at run time with `build_pe32_plus` from
`tests/call_evidence_check.py`. Its manifest replaces two bytes at the start of the `.rdata` section.

- **Bound input:** the manifest loads, and the CLI prints the manifest hash and `p001`.
- **Wrong input:** the same image with its last byte flipped makes the CLI exit with status 1 and `manifest is for another input`, with nothing on stdout.
- **Malformed manifests:** each of these is refused with its own message: a misspelled key, kind `hook`, a list or inline-table `kind`, a missing `why`, a blank `remove_when`, a duplicate id, overlapping patches, odd-length `bytes`, a boolean `rva`, a 2-byte patch at `0xffffffff`, an upper-case `input_sha256`, no patches, and a TOML syntax error.
- **Edge of the RVA range:** a 1-byte patch at `0xffffffff` loads.
- **Wrong-type `kind` through the CLI:** exit status 1 with a `patch manifest:` message, and no traceback.
- **Bytes already read:** `load_data` on the image's bytes returns what `load` returns; on the flipped image it is refused as `for another input`. With the input file then replaced by the flipped image, `load_data` on the original bytes still loads and `load` on the file is refused.
- **Shader patches:** one per pipeline loads beside a memory patch, mesh86 with and without its `.ps.cso`, and the CLI lists their ids. Each of these is refused with its own message: a 15-digit key, an upper-case key, an unknown pipeline, another pipeline's revision (compute, graphics and the mesh57 cache's), a revision without its number, one with a leading zero, an integer revision, an empty `files`, an unknown or a missing file key, another pipeline's extension, an extension listed twice, a missing required file (compute and graphics), an empty `file`, an upper-case `sha256`, two patches for one key, a memory key on a shader patch, a missing `files`, and kind `shaders`.
- **Revision forms pinned:** the runtime's current revision of each pipeline, read from its source, has the loader's form. A bump that only raises `<n>` keeps the check green. The fixture uses revisions of each form that are not the runtime's current ones.
- **Deep nesting:** an array nested 2000 deep is refused as `nested too deeply`, by `parse` and through the CLI (status 1, nothing on stdout, no traceback). Shape control: one nested 50 deep gets past `tomllib` and is refused only for its unknown key.
- **Mutations:**

  | Change | Result |
  |---|---|
  | Input hash comparison removed | The wrong-input test fails. |
  | Overlap check removed | The overlap case fails. |
  | String check on `kind` removed | Both wrong-type cases raise `TypeError`, and the CLI prints a traceback. |
  | Span check removed | The 2-byte patch at `0xffffffff` is accepted. |
  | Span check off by one (`>=`) | The 1-byte case at `0xffffffff` is refused. |
  | `load_data` compares the target with itself | The flipped image is accepted by `load_data`. |
  | Revision form check removed | The other-pipeline and malformed revision cases are accepted. |
  | Required-file check removed | Both missing-file cases are accepted. |
  | Same-key check removed | The two-patches-for-one-key case is accepted. |
  | `RecursionError` no longer caught | The deep-nesting case raises `RecursionError`, and the CLI prints a traceback. |

Measured on 27.11.2026 on Windows 11 Pro with Python 3.14: 3 tests, all passed. The `python-linux`
CI job ran the first version of the check with Python 3.12 and passed.

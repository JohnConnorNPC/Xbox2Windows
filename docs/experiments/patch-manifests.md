# Patch manifests: schema, loader, hash gate and memory patches

A patch manifest describes adjustments to a source-translated build without changing the input
file on disk. The format and the loader are in `tools/patch_manifest.py`. Stage 2, `memory` patches
that the startup debugger writes into the title's image and that the CPU converter
(`tools/exe_aot.py --patches`) translates, is planned by `tools/startup/patch_plan.py`
([Memory patches](#memory-patches-stage-2)). Data patches in the file layer and translator hooks
will each come in their own change ([#3037](https://github.com/R0Y00/Xbox2Windows/issues/3037)).

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
- **Memory patches:** `bytes` must be non-empty, and every byte it replaces needs an RVA below 2^32: a 1-byte patch at `0xffffffff` is accepted, a 2-byte one is not. Two memory patches may not overlap. Whether the span lies in a section's file-backed bytes is checked by the planner ([Memory patches](#memory-patches-stage-2)).
- **Original bytes are never stored:** `expect_sha256` is a hash of the bytes the patch replaces. The loader only checks its shape; the planner compares it with the input's bytes and the debugger with the mapped image.
- **Reporting:** the loader returns `manifest_sha256`, the SHA-256 of the manifest file's bytes, with the patch ids, for run reports to record.

`input_sha256` is the SHA-256 of the original, unpatched input. Another manifest bound to the same
input, the CPU translator's `--bind-ranges` range manifest, uses the same hash in lower case, and a
translator gates both on the original bytes before it translates a patched copy.

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
| `compute` | `x2w-startup-shader-<n>cs` | `.txt`, `.cs.cso`, `.cs.hlsl` | `.txt`, `.cs.cso` |
| `mesh86` | `x2w-startup-mesh-86-<n>` | `.mesh86.txt`, `.ms.cso`, `.ps.cso` | `.mesh86.txt`, `.ms.cso` |

The runtime looks for a compute key's `.cs.hlsl`, the Python translator's output, only when its `.txt` has no `native` line, and reads a mesh86 key's `.ps.cso` only for a request with a pixel shader. The loader does not read the `.txt` or the request, so both stay optional.

- **Revision:** `revision` must have the form of the pipeline's key revision in the runtime (`src/startup_stubs/d3d12_draw.inl`, `src/startup_stubs/mesh86_cache.inl`), where `<n>` is a number without leading zeros, so another pipeline's revision is refused. The loader does not check that `<n>` is the runtime's current one: the runtime bumps it often, and a new revision changes every key. A later consumer that serves the files must compare it with the runtime; none exists yet.
- **Files:** each entry is a table of exactly `ext`, `file` and `sha256`. `ext` is one of the pipeline's files and is listed once; the required ones must all be there. `file` is a bare file name, for a later consumer to resolve in the manifest's directory: a `/` or `\`, a drive (`:`), `.` and `..` are refused. That consumer is the runtime, which runs on Windows, so a name Windows would not open as a file of that name in the directory is refused too: one with `<`, `>`, `"`, `|`, `?`, `*` or a control character, one ending in a dot or a space (Windows drops them), and a device name (`CON`, `PRN`, `AUX`, `NUL`, `COM0`-`COM9`, `LPT0`-`LPT9`, `COM` and `LPT` with a superscript 1 to 3, `CONIN$`, `CONOUT$`) in any case, alone or before an extension, as Microsoft's "Naming Files, Paths, and Namespaces" lists them. `sha256` is lowercase.
- **One patch per key:** two shader patches for the same `key` are refused. Shader patches take no part in the memory overlap check.

Input-specific manifests stay local under `game-files/patches/`, which is gitignored. Do not
publish them or the hashes in them.

## Check

```bash
./out/pe-env/bin/python -B tests/patch_manifest_check.py
python -B tools/patch_manifest.py MANIFEST INPUT
```

On Windows: `ctest --preset dev --no-tests=error -R '^patch_manifest_controls$' -V`. The planner and the
debugger have their own checks ([Memory patches](#memory-patches-stage-2)).

The check builds a synthetic PE32+ at run time with `build_pe32_plus` from
`tests/call_evidence_check.py`. Its manifest replaces two bytes at the start of the `.rdata` section.

- **Bound input:** the manifest loads with every field of `p001` as written, and the CLI prints the manifest hash and `p001`.
- **Wrong input:** the same image with its last byte flipped makes the CLI exit with status 1 and `manifest is for another input`, with nothing on stdout. An input file that does not exist also gives status 1, with a `patch manifest: [Errno ...]` message and no traceback.
- **Malformed manifests:** each of these is refused with its own message: a misspelled key, kind `hook`, a list or inline-table `kind`, a missing `why`, a blank `remove_when`, a duplicate id, overlapping patches, odd-length or empty `bytes`, a boolean `rva`, a 2-byte patch at `0xffffffff`, an upper-case `input_sha256`, an `input_sha256` or `expect_sha256` with trailing text, no patches, and a TOML syntax error.
- **Edge of the RVA range:** a 1-byte patch at `0xffffffff` loads.
- **Memory patches side by side:** four memory patches load when listed in descending RVA, three of them adjacent and one at RVA 0. Their ids follow neither the RVA order nor its reverse, so no order by id is an order by address. Two patches that share one byte are refused as an overlap, in either order.
- **Wrong-type `kind` through the CLI:** exit status 1 with a `patch manifest:` message, and no traceback.
- **Bytes already read:** `load_data` on the image's bytes returns what `load` returns; on the flipped image it is refused as `for another input`. With the input file then replaced by the flipped image, `load_data` on the original bytes still loads and `load` on the file is refused.
- **Shader patches:** one per pipeline loads beside a memory patch, mesh86 with and without its `.ps.cso`, compute with and without its `.cs.hlsl`, and the CLI lists their ids. Each of these is refused with its own message: a 15-digit key, a 17-digit one, an upper-case key, an unknown pipeline, another pipeline's revision (compute, graphics and the mesh57 cache's), a revision without its number, one with a leading zero, an integer revision, an empty `files`, an unknown or a missing file key, another pipeline's extension, an extension listed twice, a missing required file (compute and graphics), an empty `file`, a `file` with a `/` or a `\`, an absolute one, one with a drive, `..` and `.`, a `file` with `*`, `?`, `<`, `>`, `|`, `"`, a tab or U+0001, `s001.txt.` and `s001.txt ` (trailing space), the device names `NUL`, `CON.txt`, `Com1`, `nul .txt`, `CONIN$`, `conout$.txt`, `COM` + U+00B9 and `lpt` + U+00B3 + `.cso`, an upper-case `sha256`, two patches for one key, a memory key on a shader patch, a missing `files`, and kind `shaders`.
- **Files pinned:** each pipeline's extensions are the ones its loader in the runtime reads for a key (`cache_path(..., L"", key, ext)` in `d3d12_draw.inl`, `d3d12_compute_dispatch.inl` and `mesh86_cache.inl`, and mesh86's `load_stage`), and the optional ones are mesh86's `.ps.cso`, read only for a request with a pixel shader, and compute's `.cs.hlsl`, looked for only when the `.txt` has no `native` line (`NativeComputeOutput::unmarked`).
- **Revision forms pinned:** the runtime's current revision of each pipeline, read from its source, has the loader's form. A bump that only raises `<n>` keeps the check green. The fixture uses revisions of each form that are not the runtime's current ones.
- **Deep nesting:** with the recursion limit set to 1000 inside the test, an array nested 2000 deep is refused as `nested too deeply`, by `parse` and through the CLI (status 1, nothing on stdout, no traceback). Shape control: one nested 50 deep gets past `tomllib` and is refused only for its unknown key.
- **Mutations:**

  | Change | Result |
  |---|---|
  | Input hash comparison removed | The wrong-input test fails. |
  | Overlap check removed | The overlap case fails. |
  | String check on `kind` removed | Both wrong-type cases raise `TypeError`, and the CLI prints a traceback. |
  | Span check removed | The 2-byte patch at `0xffffffff` is accepted. |
  | Span check off by one (`>=`) | The 1-byte case at `0xffffffff` is refused. |
  | `load_data` compares the target with itself | The flipped image is accepted by `load_data`. |
  | Revision form check removed | The other-pipeline, number-less and leading-zero revision cases are accepted. |
  | The runtime's graphics revision gets a suffix (`x2w-startup-shader-29b`) | The revision-form pin fails for graphics. |
  | The runtime's graphics revision is bumped (`-29` to `-30`), loader untouched | Control: the check stays green. |
  | Bare-name check on `file` removed | The six non-bare `file` cases are accepted. |
  | Check for `<>"\|?*` in `file` removed | The six cases with one of those characters are accepted. |
  | Control-character check on `file` removed | The tab and U+0001 cases are accepted. |
  | Trailing dot or space check removed; or it checks the dot only; or the space only | Both cases; the trailing space; the trailing dot are accepted. |
  | Device-name check removed | The eight device-name cases are accepted. |
  | Device names matched case-sensitively | The upper- and mixed-case ones (`NUL`, `CON.txt`, `Com1`, `CONIN$`, `COM` + U+00B9) are accepted. |
  | Device names matched as a prefix (`match`, not `fullmatch`) | `console.txt`, `nulls.cso`, `com10.txt` and `conin.txt` are refused. |
  | Device name matched against the whole `file`, not the part before the first dot | `CON.txt`, `nul .txt`, `conout$.txt` and `lpt` + U+00B3 + `.cso` are accepted. |
  | Trailing spaces kept on the part before the dot | `nul .txt` is accepted. |
  | `CONIN$` and `CONOUT$` dropped from the device names | Both cases are accepted. |
  | Superscript `COM` and `LPT` dropped from the device names | Both cases are accepted. |
  | The runtime reads `.vx.cso` instead of `.vs.cso` (`d3d12_draw.inl`) | The files pin fails for graphics. |
  | Required-file check removed | Both missing-file cases are accepted. |
  | Same-key check removed | The two-patches-for-one-key case is accepted. |
  | `RecursionError` no longer caught | The deep-nesting case raises `RecursionError`. |
  | `SHA256.fullmatch` changed to `match` | The `input_sha256` and `expect_sha256` cases with trailing text are accepted. |
  | Shader `KEY.fullmatch` changed to `match` | The 17-digit key is accepted. |
  | `bytes` pattern allows zero digit pairs (`*`) | The empty `bytes` case is accepted. |
  | Overlap check `<` changed to `<=` | The side-by-side case refuses its adjacent patches. |
  | Spans no longer sorted before the overlap check | The side-by-side case refuses its descending order. |
  | Spans sorted by id (`key=lambda s: s[2]`), ascending or descending, instead of by address | The side-by-side case refuses its patches, whose ids do not follow the addresses. |
  | `rva` lower bound `0 <=` changed to `0 <` | The side-by-side case refuses its patch at RVA 0. |
  | `why` dropped from a memory patch | The bound-input case finds a patch without `why`. |
  | The CLI catches `ValueError` only | The missing input file ends in a traceback. |

Measured on 27.11.2026 on Windows 11 Pro with Python 3.14: 3 tests, all passed. The `python-linux`
CI job ran the first version of the check with Python 3.12 and passed.

With the nesting, shader, `load_data` and side-by-side memory cases: 9 tests, all passed on Linux
(Debian 13) with Python 3.13.5 and pefile 2024.8.26. Each mutation in the table above made the check
fail, and the revision-bump control stayed green. Not yet run on Windows.

With the side-by-side ids out of step with the addresses: 9 tests, all passed on Linux (Debian 13) with
Python 3.13.5 and pefile 2024.8.26. The ascending id sort above, which passed before this change, and the
descending one now fail the check on the side-by-side case. A sort by span end (`key=lambda s: s[1]`)
still passes: for spans of at least one byte it flags an overlap exactly when the sort by start does, so
it is not counted as a survivor.

With the Windows file-name refusals (review of `4968e124`): 9 tests, all passed on Linux (Debian 13) with
Python 3.13.5 and pefile 2024.8.26. Each of the twelve mutations of the refusal in the table above made the
check fail, and the 24 earlier loader mutations still did. Not run on Windows.

## Memory patches (stage 2)

Set `X2W_PATCHES=<manifest.toml>` for a startup debugger run (`run.ps1`, `run.sh` or
`debug_launch.py` directly). Under Wine the debugger is a Windows Python, so the path must be one it
can open, such as `Z:/home/.../manifest.toml`. Before the process exists, the debugger reads the EXE
it is about to pass to `CreateProcessW` once and loads the manifest with `load_data` on those bytes,
so the gate and the plan use the same bytes. `tools/startup/patch_plan.py` raises every loader
refusal with the loader's reason and adds its own rules, each of which refuses the whole manifest:

- `id` matches `[a-z0-9][a-z0-9._-]{0,63}`: the run summary joins ids with commas.
- Every patch is `memory`: the debugger has no consumer for `shader` patches.
- One patch replaces at most 4096 bytes, and a manifest holds at most 4096 `[[patch]]` entries (the
  plan compares every patch with every base relocation and loader-written range).

The plan then refuses the whole manifest when a patch range:

- starts in the headers, or anywhere outside one section's file-backed bytes, which are
  `[VirtualAddress, VirtualAddress + min(VirtualSize, SizeOfRawData))`. File bytes past
  `VirtualSize` and virtual-only tails are refused;
- runs past those bytes or crosses into the next section. An input with a section that ends past
  `SizeOfImage` is refused whole. So is an input with a section whose file-backed bytes start at a
  `PointerToRawData` that is not a multiple of 0x200: pefile 2024.8.26, which the CPU lifter reads
  the input with, maps such a section from the offset rounded down to 0x200, whatever
  `FileAlignment` says, so it and the plan would disagree on the bytes;
- touches a base relocation entry (DIR64 covers 8 bytes, HIGHLOW 4, ABSOLUTE padding nothing; any
  other type refuses the plan);
- touches a slot the loader writes after mapping: an import address table (each import descriptor's
  `FirstThunk` array, terminator included; descriptors are read from the directory's RVA up to the
  null one, as the loaders read them), the TLS index slot, or a load configuration slot: the
  security cookie, the control-flow guard check and dispatch pointers, the XFG check, dispatch and
  table dispatch pointers, the CastGuard failure mode and the guard memcpy pointer, each when the
  configuration's own `Size` field or the directory's `Size` covers it. Inputs with delay-load
  imports are refused. The import, TLS, load-configuration and delay-import directories count as
  present when their RVA is set, whatever their `Size` says, and every structure read must lie in
  one section's file-backed bytes. A delay-load table that no directory names is not detected;
- holds input bytes whose SHA-256 is not `expect_sha256`.

Overlapping patches and spans past 2^32 never reach the plan: the loader refuses them.

The patches are written at the process's CREATE_PROCESS debug event, before any code of the process
runs. The gate read the EXE by its path before `CreateProcessW` opened that path again, so the
debugger first hashes the file the process was created from, through the file handle the event hands
it, and refuses unless that is still `input_sha256`: an EXE replaced in between is not patched, even
where it differs only outside the patch ranges. Every range is read and hashed next; a short read or
a different hash refuses before the first write. Each write checks the protection change, the full
byte count and the protection restore, and every range is read back. At the loader's initial
breakpoint, before the debugger arms `X2W_COUNT`, `X2W_REDIRECT` or `X2W_LOG_AT` breakpoints, every
range is checked again, and a breakpoint address inside a patch is logged to `events.txt`. Any
refusal ends the run: the process is terminated before it continues, the summary says `patches:
refused: <reason>` and `debug_launch.py` exits 3. A refusal after the first write can leave earlier
ranges written in the process, which never runs.

The loader breakpoint is not early enough on its own. In Wine's `dlls/ntdll/loader.c`
(`loader_init`, master as read on 2026-11-27) the static imports' `DLL_PROCESS_ATTACH` and the
main image's TLS callbacks run before `process_breakpoint()`. The fixture's TLS callback shows
whether the patch was in place before the first code of the image ran. So under Wine the
loader-breakpoint re-check runs after the TLS callbacks and DLL initializers: a loader write over a
patch is caught there only after that code has run. On Windows the breakpoint comes before both.

Every debugger run prints `patches: none`, or `patches: manifest sha256=<hex> active=<ids>` once the
loader-breakpoint re-check has passed, to the console summary, `finished.txt` and `events.txt`. A
process that ends after the write but before that breakpoint gets `patches: unverified manifest ...`
instead. The child environment never inherits `X2W_PATCHES`, `X2W_DATA_PATCH_MAP` or any
`X2W_PATCH_*` variable from the shell (names compared case-blind), so a leftover value cannot change
the title unreported. `launch.py` refuses `X2W_PATCHES` with exit code 3 instead of running the
title unpatched.

`X2W_PATCH_TEST_FAULT=apply|verify|image` is for the fixture only. It drops the last byte of each
read at that step: the process memory at the write step or the loader breakpoint, or the image file
through the CREATE_PROCESS handle, which is then hashed without its last byte. It never changes the
expected bytes. Each step refuses such a read whatever the memory or the file holds, so the switch
can only turn a pass into a refusal. The child never sees it.

## Memory patches in the CPU converter

`tools/exe_aot.py <input.exe> <out_dir> --patches <manifest.toml>` translates the same memory
patches when it [converts an EXE](../experiments.md#converting-an-exe-with-one-command). Its
stages are header, imports, patches, translate and build. The patches stage does not read the
input again: it gates the manifest on the bytes the tool read once, plans every patch with the
rules above, and writes each replacement into a copy at its file offset. The profile's translator
lifts that copy; the input file is not changed.

- The report's `sha256`, a `--bind-ranges` range manifest and, with `--entry-export`, the
  `aot_source_sha256` symbol all name the original input. A range manifest written for the patched
  bytes is refused (`range binding is for another image`).
- The only profile, `console-stdio`, lifts code and no image data. A patch whose range lies outside
  an executable section could not change the output, so it is refused (`... which profile
  console-stdio does not lift (not executable)`).
- The translator's reads of the copy's section bytes (pefile's `SectionStructure.get_data`, behind
  every read of the lifter) are recorded. A patch none of whose bytes was read, such as one in
  padding between functions, could not change the generated source: it is listed in `not_lifted`
  with its reason and left out of `active`, and a manifest of only such patches gives the same
  source as no manifest. `active` means read, not used: a lifted function's whole range is read,
  including bytes it never reaches, and a leaf entry without unwind data owns its whole section.
- `report.json` holds `"patches": null` or `{"manifest", "manifest_sha256", "active",
  "not_lifted", "patched_sha256"}` (`not_lifted`: `{"id", "reason"}` per patch; `patched_sha256`:
  the copy the translator read, every replacement in it), `"bind_ranges"`, and `"patch_line"`:
  `patches: none`, `patches: manifest sha256=<hex> active=<ids>`, followed by ` not lifted: <n>`
  when some are not lifted, `patches: none active, manifest sha256=<hex> not lifted: <n>`, or
  `patches: refused: <reason>`, which the tool prints after a conversion. With `--patches`, a
  refusal at any later stage gives `patches: refused: not applied, the conversion was refused at
  the <stage> stage`: at the header or imports stage the manifest was never read, at the translate
  stage no translation holds the copy (`"patches"` stays null), and at the build stage no EXE
  exists (`"patches"` describes the generated source, which is kept). A source with an active
  patch exports `aot_patch_manifest_sha256` and `aot_patched_sha256`. A refusal at the patches
  stage writes no source and removes a stale one.
- A `--bind-ranges` file that cannot be read, is not a JSON object, is nested too deeply for the
  JSON parser or is not a range manifest is refused at the translate stage, with `report.json`
  written and no source left behind.
- A profile that translated with image data (`cpu_switch_aot.py --image-data`) would address a
  live mapping of the input at run time, which would need the same patches. No such profile exists.

## Check or plan a manifest

```bash
python3 -B tools/startup/patch_plan.py check <manifest.toml> <input>
python3 -B tools/startup/patch_plan.py plan <manifest.toml> <input.exe>
```

`check` loads the manifest through the loader, with the hash gate, and applies the planner's rules.
`plan` also plans every memory patch against the input PE, as the debugger does. They print
`patches: ok manifest sha256=<hex> patches=<n>` (`plan` adds ` planned`) and exit 0, or print
`patches: refused: <reason>` and exit 3. A usage error exits 2.

## Test

```bash
python3 -B tests/patch_plan_check.py
```

Expected result: `patch_plan: PASS (125 cases: ...)`, exit 0. The check fails if a different number
of cases runs. The Linux CI job runs it from `tests/checks/python-linux/patch_plan.txt`, and CTest as
`patch_plan_controls`. The schema input is a synthetic PE32+ built by the test, and the first case
parses it back and checks its layout. Each loader refusal the planner passes on is checked by its
message: unknown, missing and blank keys, kinds `hook`, `data` and `code`, an upper-case
`input_sha256`, malformed hashes and `bytes`, an `rva` that is a string, a boolean, negative or past
32 bits, invalid TOML, a duplicate TOML key, nesting deeper than `tomllib` parses, a file that is not
UTF-8, a manifest without patches, without `[target]` or with an empty `patch` array, and a missing
manifest file. The planner's own rules: an upper-case id, one of 65 characters and a shader patch
the loader accepts are refused; 4096 bytes and 4096 patches load, and 4097 of either are refused. The gate
is checked with hashes that are wrong only in the last hex digit or only in the first (both refused),
so a gate that compares only a prefix or a suffix fails the check. The loader is pinned as
`tools/patch_manifest.py`, and neither it nor `tomllib` is imported until a manifest is loaded.

The plan input is a second synthetic PE32+ with an import table, a TLS directory, a load
configuration and two base relocation blocks, which its own case parses back. A copy with a second
import descriptor past the directory's `Size` of 20 has that descriptor's address table blocked, and
with a `Size` of 0 the first descriptor's table is still blocked. So are the TLS index slot and the
security cookie with a TLS or load-configuration directory `Size` of 0, and the guard check pointer
when the directory's `Size` covers it but the configuration's own `Size` field does not; a
delay-import directory with a `Size` of 0 is refused. `apply_memory` runs against a fake process
whose writes are counted: with a good first patch and a second one that differs in memory, nothing
is written. With the test fault, apply and verify both refuse memory that differs from the expected
bytes only in its first byte. A section whose file-backed bytes end exactly at `SizeOfImage` plans.
A section at file offset 0x400 plans, and the same section moved to 0x410 is refused.

On Windows, after the full build:

```powershell
ctest --preset dev --no-tests=error -R '^startup_patch_memory$' -V
```

`tests/startup_patch_memory_check.py` runs the debugger on `tests/startup_patch_probe.cpp`, which
keeps a 16-byte marker in `.rdata`; its TLS callback copies the marker before `main` prints the copy
and the live marker. Without a manifest both are original and the summary says `patches: none`.
With a manifest that replaces 8 marker bytes, both show the replacement and the summary names the
manifest, and `events.txt` shows the image file hashed through the CREATE_PROCESS handle before
the write. A wrong `expect_sha256` or input hash exits 3 before the probe exists. Each test fault
exits 3 with no probe output and no `patches: manifest` line. A copy of the probe whose first static
import other than `kernel32.dll` names a DLL that does not exist is patched at process creation and
then ended by the loader before its initial breakpoint (exit `0xc0000135`): its summary,
`finished.txt` and `events.txt` say `patches: unverified manifest ...`. `launch.py` refuses the
manifest, and a stale `X2W_DATA_PATCH_MAP` does not reach the probe. The check reads the loaded base
from `events.txt`: on Windows the probe must be relocated (ASLR). A second build of the probe,
`startup_patch_probe_low`, is linked at 0x7FFE0000, the shared user-data page, which is never free,
so it is relocated on Windows and under Wine and must be patched there too. MSVC's linker may warn
that this base is below 4 GB; that is the point of the target. The test is in the `pr` presets.

For the CPU converter:

```bash
python3 -B tests/exe_aot_patch_check.py
```

Expected result: `Ran 18 tests`, `OK`. A synthetic console EXE returns `0x1357` from its entry, or
from a function without unwind data that a range manifest binds; the manifest replaces the
immediate with `0x2468`. The cases check the generated source and the report: the replacement
constant only with the manifest, the refusals above (wrong input, wrong `expect_sha256`, an import
address table slot, a `.rdata` range) with no source left behind, a range manifest for the
original accepted while one for the patched bytes is refused, and a patch in zero bytes of `.text`
that no function owns listed as not lifted (the recorded reads cover the immediate and not those
bytes; alone it gives the unpatched source). A translate-stage and a build-stage refusal give the
refused patch line. With a compiler argument the same
file builds the conversions and runs them:

```powershell
ctest --preset dev --no-tests=error -R '^cpu_exe_aot_patch$' -V
```

The converted EXEs exit with `0x1357` unpatched and `0x2468` patched, and the patched EXE exports
the report's two hashes.

Measured on the planner's earlier copy of the loader, before it moved onto `tools/patch_manifest.py`:
the Linux checks above with Python 3.13, and under Proton Wine the Windows check above, which passed
on a clang-cl build of the probe. The patch line was logged before the first module load in
`events.txt`, and with the patch moved to the loader breakpoint instead, the TLS copy showed the
original bytes. The copy with a missing import was patched, ended by Wine's loader before the
breakpoint and reported `patches: unverified`. Wine's CREATE_PROCESS event carries a file handle the
debugger can read: the image hashed through it matched the gated EXE, and with the `image` fault the
run was refused. The `cpu_exe_aot_patch` build cases passed with clang-cl 19 and the xwin SDK, run
under Wine. Not measured: the Windows ordering, the missing-import case and the handle read on
Windows, an EXE actually replaced between the gate and `CreateProcessW` (the fixture cannot time
that), the `startup_patch_memory` and `cpu_exe_aot_patch` CTests on Windows with MSVC, and Python
older than 3.11.

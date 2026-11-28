"""Memory patches in the CPU translator (#3037; docs/experiments/patch-manifests.md).

usage: exe_aot_patch_check.py [CXX] [unittest options]

A synthetic PE32+ console EXE returns 0x1357 from its entry, or from a function without unwind
data that a range manifest binds. A patch manifest replaces the immediate with 0x2468. The cases
check that the patched copy is what gets translated, while the input hash, the range manifest and
aot_source_sha256 still name the original input. A patch in zero bytes of .text that no function owns is
reported as not lifted. The lifter writes the immediate as `0x1357ull`.

Without CXX the cases translate only (Linux). With CXX (cl, as tools/exe_aot.py invokes it) the
BuildTests also compile each conversion and run it: its exit code is the returned constant.
"""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "tests")]
import cpu_stdio_exe_aot  # noqa: E402
import exe_aot  # noqa: E402
import pefile  # noqa: E402
from cpu_stdio_exe_aot_check import RAW_OFFSET, RDATA_RVA, SECTION_SIZE, TEXT_RVA, build_console_exe  # noqa: E402

ORIGINAL, REPLACEMENT = 0x1357, 0x2468
PADDING_RVA = TEXT_RVA + 0xF00  # zero bytes in .text that no function of either fixture owns
ORIGINAL_TEXT, REPLACEMENT_TEXT = "0x1357ull", "0x2468ull"
CXX = None  # set from the command line; BuildTests run only with a compiler


def run_exe(path):
    """Exit code of a converted EXE."""
    return subprocess.run([str(path)], stdin=subprocess.DEVNULL, capture_output=True, timeout=60).returncode


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fixture(mode):
    """(original bytes, patched bytes, meta): the patched copy has REPLACEMENT at the immediate's file offset."""
    raw, meta = build_console_exe(entry_mode=mode, constant=ORIGINAL)
    offset = RAW_OFFSET + meta["imm32_rva"] - TEXT_RVA
    assert offset != meta["imm32_rva"], "the fixture's file offset must differ from the RVA"
    assert raw[offset:offset + 4] == ORIGINAL.to_bytes(4, "little")
    patched = bytearray(raw)
    patched[offset:offset + 4] = REPLACEMENT.to_bytes(4, "little")
    return raw, bytes(patched), meta


def write_manifest(path, input_sha256, patches):
    """patches: (id, rva, original bytes, replacement bytes)."""
    lines = ["[target]", f'input_sha256 = "{input_sha256}"']
    for patch_id, rva, original, replacement in patches:
        lines += ["", "[[patch]]", f'id = "{patch_id}"', 'kind = "memory"', 'why = "synthetic fixture"',
                  'remove_when = "never"', f'rva = {rva:#x}', f'expect_sha256 = "{sha256(original)}"',
                  f'bytes = "{replacement.hex()}"']
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def imm_patch(meta, patch_id="imm"):
    return (patch_id, meta["imm32_rva"], ORIGINAL.to_bytes(4, "little"), REPLACEMENT.to_bytes(4, "little"))


def pad_patch(patch_id="pad"):
    """A patch in executable bytes outside every lifted function."""
    return (patch_id, PADDING_RVA, bytes(4), b"\xcc" * 4)


def ranges_for(digest, meta):
    return {"image_sha256": digest, "functions": [{"name": "bare", "start": meta["bare_rva"], "end": meta["bare_end"]}]}


class TranslateTests(unittest.TestCase):
    """cpu_stdio_exe_aot.translate(data=, ranges=, image_sha256=)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def image(self, raw):
        path = Path(self.tmp.name) / "console.exe"
        path.write_bytes(raw)
        return path

    def assert_returns(self, source, text):
        other = ORIGINAL_TEXT if text == REPLACEMENT_TEXT else REPLACEMENT_TEXT
        self.assertIn(text, source)
        self.assertNotIn(other, source)

    def test_data_is_lifted_instead_of_the_path(self):
        raw, patched, _ = fixture("const")
        image = self.image(raw)
        self.assert_returns(cpu_stdio_exe_aot.translate(image), ORIGINAL_TEXT)
        self.assert_returns(cpu_stdio_exe_aot.translate(image, data=patched), REPLACEMENT_TEXT)

    def test_range_manifest_for_the_original_binds_on_the_patched_copy(self):
        raw, patched, meta = fixture("bare_call")
        image = self.image(raw)
        source = cpu_stdio_exe_aot.translate(image, data=patched, ranges=ranges_for(sha256(raw), meta),
                                             image_sha256=sha256(raw))
        self.assert_returns(source, REPLACEMENT_TEXT)

    def test_range_manifest_for_the_patched_copy_is_refused(self):
        raw, patched, meta = fixture("bare_call")
        image = self.image(raw)
        with self.assertRaisesRegex(ValueError, "range binding is for another image"):
            cpu_stdio_exe_aot.translate(image, data=patched, ranges=ranges_for(sha256(patched), meta),
                                        image_sha256=sha256(raw))
        # Control: without image_sha256 the bytes handed over are the image, as before.
        source = cpu_stdio_exe_aot.translate(image, data=patched, ranges=ranges_for(sha256(patched), meta))
        self.assert_returns(source, REPLACEMENT_TEXT)

    def test_bare_call_needs_a_range_manifest(self):
        raw, _, _ = fixture("bare_call")
        with self.assertRaisesRegex(ValueError, r"\(--bind-ranges\) is needed"):
            cpu_stdio_exe_aot.translate(self.image(raw))

    def test_reads_cover_the_lifted_function_only(self):
        raw, patched, meta = fixture("const")
        reads = []
        cpu_stdio_exe_aot.translate(self.image(raw), data=patched, image_sha256=sha256(raw), reads=reads)
        self.assertTrue(any(low <= meta["imm32_rva"] and meta["imm32_rva"] + 4 <= high for low, high in reads), reads)
        self.assertFalse(any(low < PADDING_RVA + 4 and PADDING_RVA < high for low, high in reads), reads)

    def test_aot_source_sha256_names_the_original(self):
        raw, patched, _ = fixture("const")
        image = self.image(raw)
        line = 'extern "C" __declspec(dllexport) const char aot_source_sha256[] = "{}";'
        source = cpu_stdio_exe_aot.translate(image, entry_export="native_entry", data=patched,
                                             image_sha256=sha256(raw))
        self.assertIn(line.format(sha256(raw)), source)
        self.assertNotIn(sha256(patched), source)
        self.assert_returns(source, REPLACEMENT_TEXT)


class ConvertTests(unittest.TestCase):
    """tools/exe_aot.py --patches / --bind-ranges, translate only (--no-build)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.out = self.dir / "out"
        self.source = self.out / "console_aot.cpp"

    def image(self, raw):
        path = self.dir / "console.exe"
        path.write_bytes(raw)
        return path

    def convert(self, image, **options):
        return exe_aot.convert(image, self.out, compile_exe=False, **options)

    def test_no_manifest_reports_none(self):
        raw, _, _ = fixture("const")
        report = self.convert(self.image(raw))
        self.assertEqual((report["status"], report["patches"], report["bind_ranges"]), ("translated", None, None))
        self.assertEqual(report["patch_line"], "patches: none")
        source = self.source.read_text(encoding="ascii")
        self.assertIn(ORIGINAL_TEXT, source)
        self.assertNotIn("aot_patch", source)

    def test_manifest_translates_the_patched_copy(self):
        raw, patched, meta = fixture("const")
        manifest = write_manifest(self.dir / "m.toml", sha256(raw), [imm_patch(meta)])
        report = self.convert(self.image(raw), patches=manifest)
        self.assertEqual(report["status"], "translated")
        self.assertEqual(report["sha256"], sha256(raw))
        self.assertEqual(report["patches"], {"manifest": str(manifest.resolve()),
                                             "manifest_sha256": sha256(manifest.read_bytes()),
                                             "active": ["imm"], "not_lifted": [], "patched_sha256": sha256(patched)})
        self.assertEqual(report["patch_line"], f"patches: manifest sha256={sha256(manifest.read_bytes())} active=imm")
        source = self.source.read_text(encoding="ascii")
        self.assertIn(REPLACEMENT_TEXT, source)
        self.assertNotIn(ORIGINAL_TEXT, source)
        for name, value in (("aot_patch_manifest_sha256", sha256(manifest.read_bytes())),
                            ("aot_patched_sha256", sha256(patched))):
            self.assertIn(f'extern "C" __declspec(dllexport) const char {name}[] = "{value}";', source)

    def test_patch_outside_every_lifted_function_is_not_lifted(self):
        raw, patched, meta = fixture("const")
        manifest = write_manifest(self.dir / "m.toml", sha256(raw), [imm_patch(meta), pad_patch()])
        report = self.convert(self.image(raw), patches=manifest)
        self.assertEqual(report["status"], "translated")
        self.assertEqual((report["patches"]["active"], report["patches"]["not_lifted"]),
                         (["imm"], [{"id": "pad", "reason": exe_aot.NOT_LIFTED}]))
        self.assertEqual(report["patch_line"],
                         f"patches: manifest sha256={sha256(manifest.read_bytes())} active=imm not lifted: 1")
        offset = RAW_OFFSET + PADDING_RVA - TEXT_RVA
        both = patched[:offset] + b"\xcc" * 4 + patched[offset + 4:]
        self.assertEqual(report["patches"]["patched_sha256"], sha256(both))  # the copy holds both replacements
        self.assertIn(REPLACEMENT_TEXT, self.source.read_text(encoding="ascii"))

    def test_only_unlifted_patches_leave_the_original_translation(self):
        raw, _, _ = fixture("const")
        image = self.image(raw)
        self.assertEqual(self.convert(image)["status"], "translated")
        plain = self.source.read_text(encoding="ascii")
        manifest = write_manifest(self.dir / "m.toml", sha256(raw), [pad_patch()])
        report = self.convert(image, patches=manifest)
        self.assertEqual((report["status"], report["patches"]["active"]), ("translated", []))
        self.assertEqual(report["patch_line"], f"patches: none active, manifest sha256={sha256(manifest.read_bytes())} "
                                               "not lifted: 1")
        # The same source as without the manifest, and no patch provenance exported.
        self.assertEqual(self.source.read_text(encoding="ascii"), plain)

    def test_build_refusal_after_patches(self):
        raw, _, meta = fixture("const")
        manifest = write_manifest(self.dir / "m.toml", sha256(raw), [imm_patch(meta)])
        report = exe_aot.convert(self.image(raw), self.out, cxx=str(self.dir / "absent-cl"), patches=manifest)
        self.assertEqual((report["status"], report["refusal"]["stage"]), ("refused", "build"))
        self.assertEqual(report["patch_line"], "patches: refused: not applied, the conversion was refused at the build stage")
        self.assertEqual(report["patches"]["active"], ["imm"])  # what the kept source holds
        self.assertIn(REPLACEMENT_TEXT, self.source.read_text(encoding="ascii"))

    def test_refusals_write_no_source(self):
        raw, patched, meta = fixture("const")
        with pefile.PE(data=raw, fast_load=True) as pe:
            pe.parse_data_directories(directories=[1])
            module = pe.DIRECTORY_ENTRY_IMPORT[0]
            slot = module.imports[0].address - pe.OPTIONAL_HEADER.ImageBase
            dll_name = module.struct.Name
        def rdata(rva, size):
            offset = RAW_OFFSET + SECTION_SIZE + rva - RDATA_RVA
            return raw[offset:offset + size]
        imm = imm_patch(meta)
        cases = {
            "wrong input": (sha256(patched), [imm], "manifest is for another input"),
            "wrong expect": (sha256(raw), [(imm[0], imm[1], b"\0" * 4, imm[3])], "do not match expect_sha256"),
            "IAT slot": (sha256(raw), [("iat", slot, rdata(slot, 8), b"\1" * 8)],
                         "loader-written range (import address table"),
            ".rdata": (sha256(raw), [("rdata", dll_name, rdata(dll_name, 2), b"XY")],
                       "is in section .rdata, which profile console-stdio does not lift (not executable)"),
        }
        image = self.image(raw)
        for name, (target, patches, message) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.convert(image)["status"], "translated")
                self.assertTrue(self.source.is_file())
                report = self.convert(image, patches=write_manifest(self.dir / "m.toml", target, patches))
                self.assertEqual((report["status"], report["refusal"]["stage"]), ("refused", "patches"))
                self.assertIn(message, report["refusal"]["message"])
                self.assertIsNone(report["patches"])
                self.assertEqual(report["patch_line"], f"patches: refused: {report['refusal']['message']}")
                self.assertFalse(self.source.exists())
                self.assertEqual(json.loads((self.out / "report.json").read_text())["status"], "refused")

    def test_range_manifest_for_the_original_with_patches(self):
        raw, _, meta = fixture("bare_call")
        image = self.image(raw)
        ranges = self.dir / "ranges.json"
        ranges.write_text(json.dumps(ranges_for(sha256(raw), meta)), encoding="utf-8")
        manifest = write_manifest(self.dir / "m.toml", sha256(raw), [imm_patch(meta)])
        report = self.convert(image, patches=manifest, bind_ranges=ranges)
        self.assertEqual((report["status"], report["bind_ranges"]), ("translated", str(ranges.resolve())))
        source = self.source.read_text(encoding="ascii")
        self.assertIn(REPLACEMENT_TEXT, source)
        self.assertNotIn(ORIGINAL_TEXT, source)

    def test_range_manifest_for_the_patched_copy_or_unreadable_is_refused(self):
        raw, patched, meta = fixture("bare_call")
        image = self.image(raw)
        manifest = write_manifest(self.dir / "m.toml", sha256(raw), [imm_patch(meta)])
        ranges = self.dir / "ranges.json"
        ranges.write_text(json.dumps(ranges_for(sha256(patched), meta)), encoding="utf-8")
        for name, path, message in (("patched sha", ranges, "range binding is for another image"),
                                    ("missing", self.dir / "absent.json", "range manifest")):
            with self.subTest(name):
                report = self.convert(image, patches=manifest, bind_ranges=path)
                self.assertEqual((report["status"], report["refusal"]["stage"]), ("refused", "translate"))
                self.assertIn(message, report["refusal"]["message"])
                self.assertFalse(self.source.exists())
                # Applied to the copy, but no translation holds it: the refused line, no patches entry.
                self.assertIsNone(report["patches"])
                self.assertEqual(report["patch_line"],
                                 "patches: refused: not applied, the conversion was refused at the translate stage")

    def test_malformed_range_manifests_are_refused(self):
        raw, _, meta = fixture("bare_call")
        image = self.image(raw)
        good = self.dir / "good.json"
        good.write_text(json.dumps(ranges_for(sha256(raw), meta)), encoding="utf-8")
        cases = {
            "not JSON": ("{", "range manifest"),
            "array": ("[1]", "expected a JSON object"),
            "entry not an object": (json.dumps({"image_sha256": sha256(raw), "functions": [1]}), "has no attribute"),
            "functions not a list": (json.dumps({"image_sha256": sha256(raw), "functions": 5}), "not iterable"),
            "bad hash": (json.dumps({"image_sha256": "X" * 64, "functions": []}), "lowercase hex image_sha256"),
            # 20,000 bytes, 10,000 levels: json recurses once per level and raises RecursionError.
            "nested too deeply": ("[" * 10000 + "]" * 10000, "maximum recursion depth exceeded"),
        }
        bad = self.dir / "bad.json"
        for name, (text, message) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.convert(image, bind_ranges=good)["status"], "translated")
                bad.write_text(text, encoding="utf-8")
                report = self.convert(image, bind_ranges=bad)
                self.assertEqual((report["status"], report["refusal"]["stage"]), ("refused", "translate"))
                self.assertIn(f"range manifest {bad.resolve()}: ", report["refusal"]["message"])
                self.assertIn(message, report["refusal"]["message"])
                self.assertFalse(self.source.exists())
                on_disk = json.loads((self.out / "report.json").read_text())
                self.assertEqual((on_disk["status"], on_disk["bind_ranges"]), ("refused", str(bad.resolve())))

    def assert_stale_output_replaced(self, report):
        """No source survives the refusal, and report.json on disk is this run's refusal."""
        self.assertFalse(self.source.exists())
        self.assertEqual(json.loads((self.out / "report.json").read_text()), report)
        self.assertEqual(report["status"], "refused")

    def test_too_deeply_nested_patch_manifest_is_refused_at_patches(self):
        raw, _, meta = fixture("const")
        image = self.image(raw)
        good = write_manifest(self.dir / "good.toml", sha256(raw), [imm_patch(meta)])
        deep = self.dir / "deep.toml"
        deep.write_text(f'[target]\ninput_sha256 = "{sha256(raw)}"\na = ' + "[" * 500 + "]" * 500 + "\n",
                        encoding="utf-8")
        self.assertEqual(self.convert(image, patches=good)["status"], "translated")
        self.assertTrue(self.source.is_file())
        report = self.convert(image, patches=deep)
        self.assertEqual(report["refusal"], {"stage": "patches",
                                             "message": "manifest is nested too deeply to parse"})
        self.assertIsNone(report["patches"])
        self.assertEqual(report["patch_line"], "patches: refused: manifest is nested too deeply to parse")
        self.assert_stale_output_replaced(report)

    def test_refusal_before_patches_names_its_stage_in_the_patch_line(self):
        raw, _, meta = fixture("const")
        manifest = write_manifest(self.dir / "m.toml", sha256(raw), [imm_patch(meta)])
        with pefile.PE(data=raw) as pe:
            pe.FILE_HEADER.Characteristics |= 0x2000  # IMAGE_FILE_DLL
            dll = bytes(pe.write())
            name = pe.DIRECTORY_ENTRY_IMPORT[0].imports[0].name
        self.assertEqual(raw.count(name + b"\0"), 1)
        unbound = raw.replace(name + b"\0", b"Zz" + name[2:] + b"\0")
        for stage, data in (("header", dll), ("imports", unbound)):
            with self.subTest(stage):
                self.assertEqual(self.convert(self.image(raw), patches=manifest)["status"], "translated")
                self.assertTrue(self.source.is_file())
                report = self.convert(self.image(data), patches=manifest)
                self.assertEqual(report["refusal"]["stage"], stage)
                self.assertIsNone(report["patches"])
                self.assertEqual(report["patch_line"], "patches: refused: not applied, the conversion was refused "
                                                       f"at the {stage} stage")
                self.assert_stale_output_replaced(report)
                # Without --patches the same refusal reports no manifest.
                self.assertEqual(self.convert(self.image(data))["patch_line"], "patches: none")

    def test_cli_reports_the_patch_line(self):
        raw, _, meta = fixture("const")
        image = self.image(raw)
        manifest = write_manifest(self.dir / "m.toml", sha256(raw), [imm_patch(meta)])
        for args, code, stdout_line, stderr_line in (
                ([], 0, "patches: none", ""),
                (["--patches", str(manifest)], 0,
                 f"patches: manifest sha256={sha256(manifest.read_bytes())} active=imm", ""),
                (["--patches", str(self.dir / "absent.toml")], 1, "", "refused at patches: cannot read the manifest")):
            with self.subTest(args=args):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    result = exe_aot.main([str(image), str(self.out), "--no-build", *args])
                self.assertEqual(result, code)
                if stdout_line:
                    self.assertIn(stdout_line, stdout.getvalue().splitlines())
                if stderr_line:
                    self.assertIn(stderr_line, stderr.getvalue())
                else:
                    self.assertEqual(stderr.getvalue(), "")


class BuildTests(unittest.TestCase):
    """Compile and run the conversions (Windows: ctest cpu_exe_aot_patch)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def build(self, mode, name, *, patched=False, ranges=False):
        raw, patched_bytes, meta = fixture(mode)
        image = self.dir / f"{name}.exe"
        image.write_bytes(raw)
        options = {}
        if patched:
            options["patches"] = write_manifest(self.dir / f"{name}.toml", sha256(raw), [imm_patch(meta)])
        if ranges:
            options["bind_ranges"] = self.dir / f"{name}.json"
            options["bind_ranges"].write_text(json.dumps(ranges_for(sha256(raw), meta)), encoding="utf-8")
        report = exe_aot.convert(image, self.dir / f"{name}_out", cxx=CXX, **options)
        self.assertEqual(report["status"], "built", report.get("refusal"))
        return Path(report["exe"]), report

    def exported(self, exe):
        """aot_* exported name -> the 64-character string at its address (other exports are code)."""
        with pefile.PE(str(exe)) as pe:
            exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            return {symbol.name.decode(): pe.get_string_at_rva(symbol.address, 64).decode("ascii")
                    for symbol in (exports.symbols if exports else ())
                    if symbol.name and symbol.name.startswith(b"aot_")}

    def test_unpatched_exits_with_the_original_constant(self):
        exe, _ = self.build("const", "plain")
        self.assertEqual(run_exe(exe), ORIGINAL)
        self.assertNotIn("aot_patched_sha256", self.exported(exe))

    def test_patched_exits_with_the_replacement_and_exports_its_hashes(self):
        exe, report = self.build("const", "patched", patched=True)
        self.assertEqual(run_exe(exe), REPLACEMENT)
        self.assertEqual({k: v for k, v in self.exported(exe).items() if k.startswith("aot_patch")},
                         {"aot_patch_manifest_sha256": report["patches"]["manifest_sha256"],
                          "aot_patched_sha256": report["patches"]["patched_sha256"]})

    def test_range_bound_callee_patched(self):
        exe, _ = self.build("bare_call", "ranged", patched=True, ranges=True)
        self.assertEqual(run_exe(exe), REPLACEMENT)


if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        CXX = sys.argv.pop(1)
    else:
        del BuildTests
    unittest.main()

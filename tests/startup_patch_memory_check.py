"""Check stage 2 memory patches in tools/startup/debug_launch.py on a source-built probe (Windows).

tests/startup_patch_probe.cpp keeps a 16-byte marker in .rdata. Its TLS callback, the first code of
the image the loader runs, copies the marker; main prints that copy and the live marker, and whether
X2W_DATA_PATCH_MAP reached it. The manifest replaces 8 marker bytes. Cases:
- no manifest: both copies original, `patches: none`, and a stale X2W_DATA_PATCH_MAP is not passed on;
- a good manifest: the replacement in BOTH copies (so it was written before the TLS callback ran),
  the `patches: manifest sha256=<hex> active=marker` line in the summary, finished.txt and events.txt,
  the image file hashed through the CREATE_PROCESS handle before the write, and an X2W_LOG_AT address
  inside the patch logged as such;
- a wrong expect_sha256 and a wrong input_sha256: debug_launch exits 3 before the probe exists
  (no stdout.txt);
- the test-only X2W_PATCH_TEST_FAULT with the good manifest: `image` (the hash through the handle) and
  `apply` refuse at process creation and `verify` at the loader breakpoint, each with exit 3, no probe
  output and never a `patches: manifest` line;
- a copy of the probe whose first non-kernel32 static import names a DLL that does not exist: the patches
  are written at process creation, the loader ends the process before its initial breakpoint (exit
  0xc0000135, STATUS_DLL_NOT_FOUND, not a timeout), and the
  summary, finished.txt and events.txt say `patches: unverified manifest ...`, never `patches: manifest`;
- launch.py with X2W_PATCHES: exit 3;
- the image base from events.txt: the probe is relocated on Windows (ASLR); a second build of the probe,
  linked at 0x7FFE0000 (the shared user-data page, never free), is relocated everywhere and patched too.
debug_launch returns 0 for a finished run; the probe's own exit is read from the summary line.
"""
import ctypes
import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools" / "startup"
sys.path.insert(0, str(TOOLS))
import patch_plan as pm  # noqa: E402

MARKER = b"X2W-PATCH-MARK01"
REPLACEMENT = b"patched!"  # over marker bytes 4..11
PATCHED = MARKER[:4] + REPLACEMENT + MARKER[12:]


def text(path):
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def marker_rva(data):
    """RVA of the probe's marker, found by its bytes in the file and mapped through the section table."""
    assert data.count(MARKER) == 1, f"the marker occurs {data.count(MARKER)} times in the probe"
    offset = data.index(MARKER)
    for section in pm.parse_pe(data).sections:
        if section.raw <= offset and offset + len(MARKER) <= section.raw + section.end - section.va:
            return section.va + offset - section.raw
    raise AssertionError("the marker is not in a section's file-backed bytes")


def manifest(work, name, input_sha, rva, expect):
    path = work / f"{name}.toml"
    path.write_text(f'[target]\ninput_sha256 = "{input_sha}"\n\n[[patch]]\nid = "marker"\nkind = "memory"\n'
                    f'rva = {rva:#x}\nexpect_sha256 = "{expect}"\nbytes = "{REPLACEMENT.hex()}"\n'
                    f'why = "fixture"\nremove_when = "never; test input"\n', encoding="utf-8")
    return path


def run(script, probe, work, name, variables, timeout="60"):
    logdir = work / name
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("X2W_")}
    env.update(variables)
    command = [sys.executable, "-B", str(TOOLS / script), str(probe), str(work), str(logdir), "--timeout", timeout]
    if script == "debug_launch.py":
        command += ["--console", "0"]
    done = subprocess.run(command, capture_output=True, text=True, timeout=180, env=env)
    return done.returncode, done.stdout + done.stderr, logdir


def probe_lines(logdir):
    return [line for line in text(logdir / "stdout.txt").splitlines() if line.startswith("patch-probe")]


def loaded_base(logdir, probe):
    found = re.search(rf"process {re.escape(probe.name)} at (0x[0-9a-f]+)", text(logdir / "events.txt"))
    assert found, text(logdir / "events.txt")
    return int(found[1], 16)


def missing_import_copy(data):
    """data with the name of its first static import other than kernel32.dll changed to a DLL that does not
    exist (same length, first three characters replaced by "x2w"), so the loader fails before its breakpoint."""
    image = pm.parse_pe(data)
    rva, size = image.directory(1)
    for pos in range(0, size - 19, 20):
        name_rva = struct.unpack_from("<5I", data, image.offset(rva + pos, 20, "import descriptor"))[3]
        if not name_rva:
            break
        at = image.offset(name_rva, 1, "import name")
        name = data[at:data.index(b"\0", at)]
        if name.lower() != b"kernel32.dll":
            assert not name.lower().startswith(b"x2w"), name
            return data[:at] + b"x2w" + data[at + 3:], name.decode("ascii")
    raise AssertionError("the probe has no static import besides kernel32.dll")


def under_wine():
    return hasattr(ctypes.WinDLL("ntdll"), "wine_get_version")


def patched_run(probe, work, name):
    """A good manifest on `probe`; returns the loaded base and whether it differs from the preferred one."""
    data = probe.read_bytes()
    rva = marker_rva(data) + 4
    path = manifest(work, name, hashlib.sha256(data).hexdigest(), rva, hashlib.sha256(MARKER[4:12]).hexdigest())
    code, out, logdir = run("debug_launch.py", probe, work, name, {"X2W_PATCHES": str(path)})
    assert code == 0 and "process exited with 0x00000000" in out, (name, out)
    assert probe_lines(logdir)[:2] == [f"patch-probe tls {PATCHED.hex()}", f"patch-probe live {PATCHED.hex()}"], (
        name, probe_lines(logdir))
    base = loaded_base(logdir, probe)
    return base, base != pm.parse_pe(data).image_base


def main(probe, low_probe):
    probe, low_probe = Path(probe).resolve(), Path(low_probe).resolve()
    data = probe.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    rva = marker_rva(data) + 4
    expect = hashlib.sha256(MARKER[4:12]).hexdigest()
    stale = {"X2W_DATA_PATCH_MAP": "stale.map"}
    with tempfile.TemporaryDirectory() as root:
        work = Path(root)
        good = manifest(work, "good", sha, rva, expect)
        good_sha = hashlib.sha256(good.read_bytes()).hexdigest()

        code, out, logdir = run("debug_launch.py", probe, work, "none", stale)
        assert code == 0 and "process exited with 0x00000000" in out, out
        assert probe_lines(logdir) == [f"patch-probe tls {MARKER.hex()}", f"patch-probe live {MARKER.hex()}",
                                       "patch-probe data-patch map absent"], probe_lines(logdir)
        assert "patches: none\n" in out and "patches: none\n" in text(logdir / "finished.txt"), out
        assert "patches: none\n" in text(logdir / "events.txt"), text(logdir / "events.txt")

        code, out, logdir = run("debug_launch.py", probe, work, "good",
                                dict(stale, X2W_PATCHES=str(good), X2W_LOG_AT=f"{rva + 2:x}"))
        assert code == 0 and "process exited with 0x00000000" in out, out
        assert probe_lines(logdir) == [f"patch-probe tls {PATCHED.hex()}", f"patch-probe live {PATCHED.hex()}",
                                       "patch-probe data-patch map absent"], probe_lines(logdir)
        line = f"patches: manifest sha256={good_sha} active=marker"
        assert line + "\n" in out and line + "\n" in text(logdir / "finished.txt"), out
        events = text(logdir / "events.txt")
        assert line in events and f"patches: breakpoint at +{rva + 2:#x} is inside patch marker" in events, events
        assert events.index("ranges written at process creation") < events.index(" load "), events
        hashed = "patches: the process's image file is the manifest's input"
        assert hashed in events and events.index(hashed) < events.index("ranges written at process creation"), (
            "good: the image file was not hashed through the process's handle before the write", events)

        # Test-only faults corrupt what was read, never the expected bytes: both must refuse a matching manifest.
        for fault, want in (("image", "patches: refused: the image the process was created from is not the manifest's "
                                      "target input_sha256"),
                            ("apply", "patches: refused: patch marker: read 7 of 8 bytes at"),
                            ("verify", "does not hold the replacement at the loader breakpoint")):
            code, out, logdir = run("debug_launch.py", probe, work, f"fault-{fault}",
                                    {"X2W_PATCHES": str(good), "X2W_PATCH_TEST_FAULT": fault})
            assert code == 3 and want in out, (fault, code, out)
            assert not probe_lines(logdir), (fault, probe_lines(logdir))
            for where in (out, text(logdir / "finished.txt"), text(logdir / "events.txt")):
                assert "patches: manifest" not in where, (fault, where)

        # Written at process creation, then the loader ends the process before its initial breakpoint.
        broken_data, renamed = missing_import_copy(data)
        broken = work / "missing_import_probe.exe"
        broken.write_bytes(broken_data)
        broken_manifest = manifest(work, "missing-import", hashlib.sha256(broken_data).hexdigest(), rva, expect)
        broken_line = f"patches: unverified manifest sha256={hashlib.sha256(broken_manifest.read_bytes()).hexdigest()} active=marker "
        code, out, logdir = run("debug_launch.py", broken, work, "missing-import", {"X2W_PATCHES": str(broken_manifest)})
        events = text(logdir / "events.txt")
        # The loader ended it (STATUS_DLL_NOT_FOUND), not the run's timeout.
        assert "process exited with 0xc0000135" in out, ("missing-import", renamed, out)
        assert "ranges written at process creation" in events, ("missing-import", renamed, events)
        assert not probe_lines(logdir), ("missing-import", renamed, probe_lines(logdir))
        for where in (out, text(logdir / "finished.txt"), events):
            assert broken_line in where and "patches: manifest" not in where, ("missing-import", renamed, where)

        wrong_sha = sha[:-1] + ("0" if sha[-1] != "0" else "1")
        for name, path, want in (
                ("wrong-expect", manifest(work, "wrong-expect", sha, rva, expect[:-1] + ("0" if expect[-1] != "0" else "1")),
                 f"patches: refused: patch marker: the input's bytes at {rva:#x} do not match expect_sha256"),
                ("wrong-input", manifest(work, "wrong-input", wrong_sha, rva, expect),
                 f"patches: refused: manifest is for another input: manifest input_sha256 {wrong_sha}, "
                 f"input sha256 {sha}")):
            code, out, logdir = run("debug_launch.py", probe, work, name, {"X2W_PATCHES": str(path)})
            assert code == 3 and want + "\n" in out, (name, code, out)
            assert not (logdir / "stdout.txt").exists(), f"{name}: the probe was started"
            assert want + "\n" in text(logdir / "finished.txt"), (name, text(logdir / "finished.txt"))

        code, out, logdir = run("launch.py", probe, work, "launch", {"X2W_PATCHES": str(good)})
        assert code == 3 and "patches: refused: launch.py does not apply patch manifests" in out, (code, out)
        assert not (logdir / "stdout.txt").exists(), "launch.py started the probe"

        base, relocated = patched_run(probe, work, "base")
        low_base, low_relocated = patched_run(low_probe, work, "low-base")
        wine = under_wine()
        print(f"startup_patch_memory: probe at {base:#x} relocated {'yes' if relocated else 'no'}; low-base probe at "
              f"{low_base:#x} relocated {'yes' if low_relocated else 'no'}; {'Wine' if wine else 'Windows'}")
        assert low_relocated, "the low-base probe loaded at 0x7FFE0000"
        assert relocated or wine, "Windows loaded the probe at its preferred base (ASLR off?)"

    print("startup_patch_memory: PASS (no manifest: original and `patches: none`; good manifest: replaced before the "
          "TLS callback and reported; wrong expect_sha256 or input hash: exit 3 before the process exists; "
          "the image file re-hashed through the process's handle; test faults refuse at process creation and at the "
          "loader breakpoint; a process ended by the loader before "
          "its breakpoint reports its patches unverified; launch.py refuses; a stale "
          "data-patch map is not passed on; relocated images patched)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: startup_patch_memory_check.py <startup_patch_probe.exe> <startup_patch_probe_low.exe>")
        sys.exit(2)
    try:
        sys.exit(main(sys.argv[1], sys.argv[2]))
    except AssertionError as error:
        print(f"startup_patch_memory: FAIL: {error}")
        sys.exit(1)

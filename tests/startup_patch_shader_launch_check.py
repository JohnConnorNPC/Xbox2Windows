"""Check how tools/startup/debug_launch.py hands a manifest's shader overrides to the child (Windows).

Runs the debugger on tests/startup_patch_probe.cpp, which prints X2W_PATCH_SHADER_DIR when it is set.
The probe does not read the files; the runtime side is tests/startup_shader_override_check.py. Cases:
- no manifest, a stale X2W_PATCH_SHADER_DIR in the shell: the probe prints no shader directory,
  `patches: none`, and no patch_shaders directory is created;
- a manifest of two shader overrides (compute, mesh86) and the same stale value: the probe prints
  <logdir>/patch_shaders, which holds exactly <key><ext> per file with the manifest's bytes; the
  summary, finished.txt and events.txt name the manifest with both ids under `offered=` (not
  `active=`), events.txt the override directory and the image file hashed through the CREATE_PROCESS
  handle before that line, and the summary ends with `found 0 of 2`: the probe is not the stand-in
  and asks for no translation;
- memory and shader patches in one manifest: the marker is replaced before the TLS callback and the
  probe gets the directory too; `active=` names the memory patch, `offered=` the override; events.txt
  has `ranges written at process creation; 1 shader overrides` before the loader breakpoint and the
  `patches: manifest` line only after it;
- a shader-only manifest gated on another input: exit 3 before the probe exists, nothing copied;
- a shader-only manifest with the test-only `image` fault: exit 3 at process creation, no probe
  output and never a `patches: manifest` line;
- a shader file whose sha256 is wrong: exit 3 before the probe exists, and nothing is copied.
"""
import hashlib
from pathlib import Path
import sys
import tempfile

from startup_patch_memory_check import MARKER, PATCHED, REPLACEMENT, marker_rva, probe_lines, run, text

KEY_CS = "00c0ffee0badf00d"
KEY_MESH = "0123456789abcdef"
FILES = {"cs.txt": b"x2w-manifest 2\nfixture\n", "cs.cso": b"fixture compute bytecode",
         "m.mesh86.txt": b"x2w-mesh86 1 fixture\n", "m.ms.cso": b"fixture mesh bytecode"}


current = ["setup"]  # the case running, named in a FAIL line


def sha(data):
    return hashlib.sha256(data).hexdigest()


def shader(pid, key, pipeline, revision, files):
    listed = ", ".join(f'{{ ext = "{ext}", file = "{name}", sha256 = "{digest}" }}' for ext, name, digest in files)
    return (f'[[patch]]\nid = "{pid}"\nkind = "shader"\nkey = "{key}"\npipeline = "{pipeline}"\n'
            f'revision = "{revision}"\nfiles = [{listed}]\nwhy = "fixture"\nremove_when = "never; test input"\n')


def main(probe):
    probe = Path(probe).resolve()
    data = probe.read_bytes()
    rva = marker_rva(data) + 4
    memory = (f'[[patch]]\nid = "marker"\nkind = "memory"\nrva = {rva:#x}\n'
              f'expect_sha256 = "{sha(MARKER[4:12])}"\nbytes = "{REPLACEMENT.hex()}"\n'
              f'why = "fixture"\nremove_when = "never; test input"\n')
    with tempfile.TemporaryDirectory() as root:
        work = Path(root)
        for name, body in FILES.items():
            (work / name).write_bytes(body)
        compute = shader("cs", KEY_CS, "compute", "x2w-startup-shader-29cs",
                         [(".txt", "cs.txt", sha(FILES["cs.txt"])), (".cs.cso", "cs.cso", sha(FILES["cs.cso"]))])
        mesh = shader("me", KEY_MESH, "mesh86", "x2w-startup-mesh-86-1",
                      [(".mesh86.txt", "m.mesh86.txt", sha(FILES["m.mesh86.txt"])),
                       (".ms.cso", "m.ms.cso", sha(FILES["m.ms.cso"]))])
        copies = {f"{KEY_CS}.txt": FILES["cs.txt"], f"{KEY_CS}.cs.cso": FILES["cs.cso"],
                  f"{KEY_MESH}.mesh86.txt": FILES["m.mesh86.txt"], f"{KEY_MESH}.ms.cso": FILES["m.ms.cso"]}
        head = f'[target]\ninput_sha256 = "{sha(data)}"\n\n'
        stale = {"X2W_PATCH_SHADER_DIR": str(work / "stale")}
        original = [f"patch-probe tls {MARKER.hex()}", f"patch-probe live {MARKER.hex()}", "patch-probe data-patch map absent"]

        current[0] = "no manifest"
        code, out, logdir = run("debug_launch.py", probe, work, "none", stale)
        assert code == 0 and "process exited with 0x00000000" in out, out
        assert probe_lines(logdir) == original, probe_lines(logdir)
        assert "patches: none\n" in out and not (logdir / "patch_shaders").exists(), out

        current[0] = "shader manifest"
        path = work / "shaders.toml"
        path.write_text(head + compute + mesh, encoding="utf-8")
        code, out, logdir = run("debug_launch.py", probe, work, "shaders", dict(stale, X2W_PATCHES=str(path)))
        assert code == 0 and "process exited with 0x00000000" in out, out
        directory = logdir / "patch_shaders"
        assert probe_lines(logdir) == original + [f"patch-probe shader dir {directory}"], probe_lines(logdir)
        found = {entry.name: entry.read_bytes() for entry in directory.iterdir()}
        assert found == copies, sorted(found)
        line = f"patches: manifest sha256={sha(path.read_bytes())} offered=cs,me"
        found_line = "patches: shader overrides found 0 of 2: found=- not_found=cs,me"
        events, finished = text(logdir / "events.txt"), text(logdir / "finished.txt")
        assert line + "\n" in out and line + "\n" in finished and line in events, out
        assert found_line + "\n" in out and found_line + "\n" in finished and found_line + "\n" in events, out
        assert f"patches: shader overrides for 2 keys in {directory}\n" in events, events
        hashed = "patches: the process's image file is the manifest's input"
        assert hashed in events and events.index(hashed) < events.index(line), ("no image hash before the line", events)
        shader_line = line

        current[0] = "memory and shader patches"
        path = work / "mixed.toml"
        path.write_text(head + memory + compute, encoding="utf-8")
        code, out, logdir = run("debug_launch.py", probe, work, "mixed", {"X2W_PATCHES": str(path)})
        assert code == 0 and "process exited with 0x00000000" in out, out
        assert probe_lines(logdir) == [f"patch-probe tls {PATCHED.hex()}", f"patch-probe live {PATCHED.hex()}",
                                       "patch-probe data-patch map absent",
                                       f"patch-probe shader dir {logdir / 'patch_shaders'}"], probe_lines(logdir)
        line = f"patches: manifest sha256={sha(path.read_bytes())} active=marker offered=cs"
        assert line + "\n" in out, out
        assert "patches: shader overrides found 0 of 1: found=- not_found=cs\n" in out, out
        # Written at process creation, with the override count; reported only after the loader-breakpoint re-check.
        events = text(logdir / "events.txt")
        written = "patches: 1 ranges written at process creation; 1 shader overrides\n"
        loader_break = events.find("exception 0x80000003")
        assert written in events and line in events and loader_break >= 0, ("written, line or breakpoint missing", events)
        assert events.index(written) < loader_break < events.index(line), ("line before the loader breakpoint", events)

        current[0] = "shader-only manifest gated on another input"
        path = work / "gated.toml"
        other = sha(data + b"\0")
        path.write_text(f'[target]\ninput_sha256 = "{other}"\n\n' + compute, encoding="utf-8")
        code, out, logdir = run("debug_launch.py", probe, work, "gated", {"X2W_PATCHES": str(path)})
        assert code == 3 and (f"patches: refused: manifest is for another input: manifest input_sha256 {other}, "
                              f"input sha256 {sha(data)}\n") in out, (code, out)
        assert not (logdir / "stdout.txt").exists() and not (logdir / "patch_shaders").exists(), "started or copied"

        current[0] = "shader-only manifest with the image fault"
        code, out, logdir = run("debug_launch.py", probe, work, "fault-image",
                                {"X2W_PATCHES": str(work / "shaders.toml"), "X2W_PATCH_TEST_FAULT": "image"})
        assert code == 3 and ("patches: refused: the image the process was created from is not the manifest's target "
                              "input_sha256") in out, (code, out)
        assert not probe_lines(logdir), probe_lines(logdir)
        for where in (out, text(logdir / "finished.txt"), text(logdir / "events.txt")):
            assert "patches: manifest" not in where and shader_line not in where, where

        current[0] = "wrong file hash"
        path = work / "wrong.toml"
        right = sha(FILES["cs.cso"])
        path.write_text(head + compute.replace(right, right[:-1] + ("0" if right[-1] != "0" else "1")), encoding="utf-8")
        code, out, logdir = run("debug_launch.py", probe, work, "wrong", {"X2W_PATCHES": str(path)})
        assert code == 3 and "patches: refused: patch cs: .cs.cso file " in out and " does not match its sha256\n" in out, \
            (code, out)
        assert not (logdir / "stdout.txt").exists() and not (logdir / "patch_shaders").exists(), "started or copied"

    print("startup_patch_shader_launch: PASS (no manifest: no directory reaches the probe; shader manifest: the probe "
          "gets <logdir>/patch_shaders holding exactly the manifest's bytes, reported as offered after the image hash, "
          "0 found; with a memory patch: both, reported after the loader breakpoint; gated on another input or a "
          "wrong file hash: exit 3 before the process exists, nothing copied; the image fault refuses)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: startup_patch_shader_launch_check.py <startup_patch_probe.exe>")
        sys.exit(2)
    try:
        sys.exit(main(sys.argv[1]))
    except AssertionError as error:
        print(f"startup_patch_shader_launch: FAIL in case {current[0]!r}: {error}")
        sys.exit(1)

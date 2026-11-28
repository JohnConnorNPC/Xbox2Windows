"""A patch manifest's shader override served by the stand-in in place of the shader cache's translation (Windows).

usage: startup_shader_override_check.py <startup_stream_consumer> <dxc> <warp|hardware>

Uses the compute dispatch of tests/startup_compute_dispatch_check.py (case A of startup_gfx2hlsl_compute_check.py,
Dispatch(3, 2, 2), 288 of the 320 output words stored). The runs share one shader cache:

a) before translation the request is published, the Dispatch is refused and the output keeps the sentinel;
b) after gfx2hlsl.py --pending with DXC the output is the CPU reference, and nothing is logged as an override;
c) a manifest (gated on the consumer EXE) overrides the requested key with a copy of the cache's .txt and a .cs.cso
   compiled from the cache's .cs.hlsl with the stored value XORed with 0x5a5a5a5a, plus a second key nobody
   requests. tools/startup/patch_plan.py plans and copies them as debug_launch.py does, and the consumer
   gets X2W_PATCH_SHADER_DIR. For this run the cache's own <key>.txt is replaced by one the runtime refuses
   ("manifest version"), so a pass shows that both files came from the override: every stored word is the
   reference XOR 0x5a5a5a5a, the unstored words keep the sentinel, `x2w-patch shader <key> found` is logged once
   for .txt and once for .cs.cso, never for the other key, and found_line counts 1 of 2;
d) the cache's .txt restored (checked by hash), without X2W_PATCH_SHADER_DIR: the reference again;
e) a directory holding only <key>.txt: the Dispatch is refused with "no compiled program", the output keeps
   the sentinel and the log says the .cs.cso was not taken from the cache.
Exit 77 only if the initial probe cannot use the adapter or required heaps.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import startup_gfx2hlsl_compute_check as C
from startup_compute_dispatch_check import dispatch, lines, prepare_case
from startup_stream_check import gfx2hlsl as G

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools' / 'startup'))
import patch_plan as pm  # noqa: E402

FLIP = 0x5a5a5a5a
STORE = 'u0.Store(a, v5);'  # case A's one store in the translation
STORED = 2 * 3 * 4 * 3 * 2 * 2  # group size times groups: one word per thread


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def overrides(work, consumer, entries):
    """A manifest gated on the consumer with one compute override per (id, key, txt, cso)."""
    text = f'[target]\ninput_sha256 = "{sha(consumer)}"\n'
    for pid, key, txt, cso in entries:
        text += (f'\n[[patch]]\nid = "{pid}"\nkind = "shader"\nkey = "{key:016x}"\npipeline = "compute"\n'
                 f'revision = "{pm.PIPELINES["compute"].revision}"\n'
                 f'files = [{{ ext = ".txt", file = "{txt.name}", sha256 = "{sha(txt)}" }}, '
                 f'{{ ext = ".cs.cso", file = "{cso.name}", sha256 = "{sha(cso)}" }}]\n'
                 f'why = "fixture"\nremove_when = "never; test input"\n')
    path = work / 'overrides.toml'
    path.write_text(text, encoding='utf-8')
    return path


def main(consumer, dxc, adapter):
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        cache, env = prepare_case(directory, adapter)
        env.pop(pm.SHADER_DIR_ENV, None)
        untouched, expected = [C.SENTINEL] * C.WORDS, C.expected('A')
        stored = [i for i in range(C.WORDS) if expected[i] != C.SENTINEL]
        assert len(stored) == STORED, f'{len(stored)} stored words in the reference, expected {STORED}'
        flipped = [word ^ FLIP if i in stored else word for i, word in enumerate(expected)]

        got, result = dispatch(directory, consumer, env, 'dispatch', probe=True)
        print(result.stdout, end='')
        assert got == untouched and len(lines(result, 'Dispatch(3, 2, 2) refused: no translation')) == 1, result.stderr[-3000:]
        published = lines(result, 'x2w-draw compute request')
        assert published and ' published ' in published[0], result.stderr[-3000:]
        key = int(published[0].split()[3], 16)

        out = subprocess.run([sys.executable, '-B', G.__file__, '--pending', cache], check=True, capture_output=True,
                             text=True, env=dict(os.environ, X2W_DXC=dxc)).stdout
        assert f'{key:016x}: ok' in out, out
        got, result = dispatch(directory, consumer, env, 'dispatch')
        assert got == expected and not lines(result, 'x2w-patch shader'), result.stderr[-3000:]
        print('b) cache translation: all %d words match the CPU reference' % C.WORDS)

        work = directory / 'override'
        work.mkdir()
        hlsl = (Path(cache) / f'{key:016x}.cs.hlsl').read_text()
        assert hlsl.count(STORE) == 1, f'the translation has {hlsl.count(STORE)} copies of {STORE!r}'
        (work / 'flip.cs.hlsl').write_text(hlsl.replace(STORE, f'u0.Store(a, v5 ^ 0x{FLIP:08x}u);'))
        subprocess.run([dxc, '-Gis', '-T', 'cs_6_0', '-E', 'main', '-Fo', str(work / 'flip.cs.cso'),
                        str(work / 'flip.cs.hlsl')], check=True, capture_output=True, text=True)
        cached_txt = Path(cache) / f'{key:016x}.txt'
        original_txt = cached_txt.read_bytes()
        shutil.copyfile(cached_txt, work / 'flip.txt')
        txt, cso = work / 'flip.txt', work / 'flip.cs.cso'
        manifest_path = overrides(work, consumer, [('flip', key, txt, cso), ('unrequested', key ^ 1, txt, cso)])
        manifest, memory = pm.prepare({pm.ENV: str(manifest_path)}, consumer)
        assert memory == () and [p.id for p in manifest.patches] == ['flip', 'unrequested'], manifest
        plans = pm.plan_shaders(manifest)
        served_dir = pm.materialize_shaders(plans, directory / 'run' / 'patch_shaders')

        cached_txt.write_bytes(b'x2w-manifest 0\n')  # the runtime refuses this .txt: "manifest version"
        assert sha(cached_txt) != sha(txt), 'the cache and the override hold the same .txt'
        try:
            got, result = dispatch(directory, consumer, dict(env, **{pm.SHADER_DIR_ENV: served_dir}), 'dispatch')
        finally:
            cached_txt.write_bytes(original_txt)
        assert hashlib.sha256(cached_txt.read_bytes()).hexdigest() == hashlib.sha256(original_txt).hexdigest()
        wrong = [i for i in range(C.WORDS) if got[i] != flipped[i]]
        assert not wrong, 'override: word=%d got=%08x expected=%08x (%d words differ)\n%s' % (
            wrong[0], got[wrong[0]], flipped[wrong[0]], len(wrong), result.stderr[-3000:])
        logged = lines(result, 'x2w-patch shader')
        assert [line[line.index('x2w-patch'):] for line in logged] == [
            f'x2w-patch shader {key:016x} found .txt', f'x2w-patch shader {key:016x} found .cs.cso'], logged
        assert len(lines(result, 'Dispatch(3, 2, 2) translated')) == 1 and not lines(result, 'refused'), result.stderr[-3000:]
        assert pm.found_line(plans, result.stderr) == (
            'patches: shader overrides found 1 of 2: found=flip not_found=unrequested'), result.stderr[-3000:]
        print(f'c) override (the cache\'s .txt refused meanwhile): all {STORED} stored words are the reference XOR '
              f'{FLIP:#010x}, found .txt and .cs.cso once, the unrequested key never')

        got, result = dispatch(directory, consumer, env, 'dispatch')
        assert got == expected and not lines(result, 'x2w-patch shader'), result.stderr[-3000:]
        print('d) the cache\'s .txt restored, without X2W_PATCH_SHADER_DIR: the cache translation again')

        partial = directory / 'partial'
        partial.mkdir()
        shutil.copyfile(txt, partial / f'{key:016x}.txt')
        got, result = dispatch(directory, consumer, dict(env, **{pm.SHADER_DIR_ENV: str(partial)}), 'dispatch')
        refused = lines(result, 'refused: ')
        assert got == untouched and len(refused) == 1 and refused[0].endswith(
            'Dispatch(3, 2, 2) refused: no compiled program'), result.stderr[-3000:]
        logged = [line[line.index('x2w-patch'):] for line in lines(result, 'x2w-patch shader')]
        assert logged == [f'x2w-patch shader {key:016x} found .txt',
                          f'x2w-patch shader {key:016x} has no .cs.cso, not taken from the cache'], logged
        print('e) override without its .cs.cso: refused, the cache\'s .cs.cso not used')
        print(f'startup_shader_override: PASS on {adapter}')


if __name__ == '__main__':
    if len(sys.argv) != 4 or sys.argv[3] not in ('warp', 'hardware'):
        sys.exit(__doc__)
    main(*sys.argv[1:])

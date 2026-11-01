#!/usr/bin/env python3
"""Compile and run the host link recorder tests without a Cargo workspace."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='psonoci-recorder-tests-') as directory:
    binary = Path(directory) / ('recorder-tests.exe' if os.name == 'nt' else 'recorder-tests')
    environment = dict(os.environ, PSONOCI_SBOM_TARGET='x86_64-unknown-linux-gnu', PSONOCI_SBOM_LINKER='cc')
    subprocess.run(['rustc', '--edition=2024', '--test', str(root / 'scripts/sbom-linker.rs'), '-o', str(binary)],
                   cwd=root, env=environment, check=True)
    subprocess.run([str(binary)], check=True)
    if sys.platform.startswith('linux'):
        # An actual native object must survive argument/trace capture, even
        # though it is not a Cargo archive or a recognized startup object.
        linker = shutil.which('cc')
        if not linker:
            raise RuntimeError('cc is required for the native-object integration test')
        environment['PSONOCI_SBOM_LINKER'] = linker
        environment['CCACHE_DIR'] = str(Path(directory) / 'ccache')
        recorder = Path(directory) / 'recorder'
        subprocess.run(['rustc', '--edition=2024', str(root / 'scripts/sbom-linker.rs'), '-o', str(recorder)],
                       cwd=root, env=environment, check=True)
        main = Path(directory) / 'main.c'
        codec = Path(directory) / 'codec.c'
        main.write_text('extern int codec(void); int main(void) { return codec() != 42; }\n')
        codec.write_text('int codec(void) { return 42; }\n')
        output = Path(directory) / 'psonoci'
        objects = [Path(directory) / 'psonoci.unit.rcgu.o', Path(directory) / 'codec.o']
        for source, obj in zip((main, codec), objects):
            subprocess.run([linker, '-c', str(source), '-o', str(obj)], env=environment, check=True)
        subprocess.run([str(recorder), *(str(obj) for obj in objects), '-o', str(output)],
                       env=environment, check=True, capture_output=True)
        capture = json.loads((Path(directory) / 'runtime-capture/capture.json').read_text())
        roles = {Path(item['path']).name: item['role'] for item in capture['inputs']}
        if roles.get('codec.o') != 'provider' or roles.get(objects[0].name) != 'root-rust-object':
            raise RuntimeError(f'Native object coverage regression: {roles}')
        subprocess.run([str(output)], check=True)
        print('Native-object final-link integration test passed')

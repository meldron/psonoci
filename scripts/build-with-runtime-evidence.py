#!/usr/bin/env python3
"""Build psonoci and collect runtime evidence in the same build environment."""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CROSS_LINKERS = {
    'x86_64-unknown-linux-musl': 'x86_64-linux-musl-gcc',
    'aarch64-unknown-linux-musl': 'aarch64-linux-musl-gcc',
    'armv7-unknown-linux-musleabihf': 'arm-linux-musleabihf-gcc',
    'armv7-unknown-linux-gnueabihf': 'arm-linux-gnueabihf-gcc',
    'x86_64-pc-windows-gnu': 'x86_64-w64-mingw32-gcc',
}


def run(command, **kwargs):
    return subprocess.run(command, cwd=ROOT, check=True, **kwargs)


def msvc_environment(environment):
    vswhere = Path(environment.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
    installation = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
                                           'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], text=True).strip()
    if not installation:
        raise RuntimeError('MSVC installation not found')
    batch = Path(installation) / 'Common7/Tools/VsDevCmd.bat'
    result = run(['cmd.exe', '/d', '/s', '/c', f'""{batch}" -no_logo -arch=amd64 -host_arch=amd64 >nul && set"'],
                 text=True, capture_output=True)
    environment.update(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line and not line.startswith('='))
    linker = shutil.which('link.exe', path=environment.get('Path', environment.get('PATH')))
    if not linker:
        raise RuntimeError('MSVC linker unavailable after VsDevCmd')
    return linker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--cross', action='store_true')
    parser.add_argument('--image', help='Cross base image (resolved to a digest before building)')
    parser.add_argument('--linker', help='Explicit real linker driver; no shell command')
    args = parser.parse_args()
    environment = dict(os.environ)
    image = 'native'
    target_key = args.target.upper().replace('-', '_')
    if args.cross:
        supplied_image = bool(args.image)
        if not args.image:
            # The Windows GNU target uses a local Dockerfile in Cross.toml.
            # Build it explicitly to give the recorder an immutable image ID.
            dockerfile = ROOT / f'build_files/Dockerfile-{args.target}'
            if not dockerfile.is_file():
                parser.error('--image is required for this Cross target')
            tag = f'psonoci-sbom-builder:{args.target}'
            run(['docker', 'build', '--file', str(dockerfile), '--tag', tag, str(ROOT / 'build_files')])
            args.image = tag
        if supplied_image:
            run(['docker', 'pull', args.image])
        inspected = json.loads(subprocess.check_output(['docker', 'image', 'inspect', args.image], text=True))[0]
        image = next(iter(inspected.get('RepoDigests', [])), inspected['Id'])
        cross_image = image
        if not inspected.get('RepoDigests'):
            # BuildKit resolves FROM by repository/tag, not a bare daemon image
            # ID. Use a content-addressed local tag and retain the actual ID.
            cross_image = 'psonoci-sbom-builder:sha256-' + inspected['Id'].removeprefix('sha256:')
            run(['docker', 'tag', args.image, cross_image])
        environment[f'CROSS_TARGET_{target_key}_IMAGE'] = cross_image
        # Newer Cross versions normally copy only Cargo-declared artifacts
        # back from a remote daemon; the recorder's sidecars are also needed.
        environment['CROSS_REMOTE_COPY_FULL_TARGET_DIR'] = 'true'
        linker = args.linker or CROSS_LINKERS.get(args.target)
        if not linker:
            parser.error('this Cross target needs an explicit --linker')
    elif 'msvc' in args.target:
        linker = args.linker or msvc_environment(environment)
    elif 'windows-gnu' in args.target:
        linker = args.linker or shutil.which('gcc')
        if not linker:
            parser.error('MinGW GCC is required')
        machine = subprocess.check_output([linker, '-dumpmachine'], env=environment, text=True).strip()
        if 'mingw' not in machine:
            parser.error('Windows GNU builds require a MinGW GCC linker')
    else:
        key = f'CARGO_TARGET_{target_key}_LINKER'
        linker = args.linker or environment.get(key) or shutil.which('cc')
        if not linker:
            parser.error('linker driver not found')

    # Cross remote mode excludes Cargo cache directories when copying sources.
    # Keep the host recorder outside target/ so it reaches the build container.
    tools = ROOT / '.sbom-tools' / args.target
    tools.mkdir(parents=True, exist_ok=True)
    wrapper = tools / ('sbom-linker.exe' if os.name == 'nt' else 'sbom-linker')
    compile_env = environment | {'PSONOCI_SBOM_TARGET': args.target, 'PSONOCI_SBOM_LINKER': linker,
                                 'PSONOCI_SBOM_IMAGE': image}
    command = ['rustc', '--edition=2024', str(ROOT / 'scripts/sbom-linker.rs'), '-o', str(wrapper)]
    if args.cross:
        if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
            parser.error('Cross evidence capture currently requires a Linux x86_64 build host')
        # The recorder must also run in old Cross images with older glibc.
        run(['rustup', 'target', 'add', 'x86_64-unknown-linux-musl'])
        command += ['--target', 'x86_64-unknown-linux-musl']
    run(command, env=compile_env)
    release = ROOT / 'target' / args.target / 'release'
    capture = release / 'runtime-capture'
    evidence = release / 'psonoci.runtime.json'
    if capture.exists():
        shutil.rmtree(capture)
    evidence.unlink(missing_ok=True)
    builder = ['cross'] if args.cross else ['cargo', 'auditable']
    # Restrict the recorder to the final application link; build scripts and
    # procedural macros continue to use the original host linker.
    # Always relink: Cargo freshness does not know that capture files were removed.
    run(['cargo', 'clean', '--package', 'psonoci', '--target', args.target, '--release', '--target-dir', str(ROOT / 'target')], env=environment)
    run([*builder, 'rustc', '--locked', '--release', '--bin', 'psonoci', '--target', args.target, '--target-dir', str(ROOT / 'target'),
         '--', '-C', f'linker={wrapper}'], env=environment)
    binary = release / ('psonoci.exe' if 'windows' in args.target else 'psonoci')
    run([os.fspath(Path(os.sys.executable)), str(ROOT / 'scripts/runtime_evidence.py'),
         '--target', args.target, '--binary', str(binary), '--capture', str(capture), '--output', str(evidence)])
    print(f'Runtime evidence: {evidence}')


if __name__ == '__main__':
    main()

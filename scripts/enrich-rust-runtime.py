#!/usr/bin/env python3
"""Expose registry crates bundled in supported Rust target sysroots.

Prepare downloads the exact-commit library lockfile and checksum-verified crate
metadata. Enrich is offline and requires captured inputs to match this sysroot.
It identifies supplied linker inputs, not individual retained machine functions.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import re
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

import sbom
import tomllib

runtime = sbom.runtime_info
SUPPORTED_TARGETS = runtime.RUST_RUNTIME_TARGETS
TOOL_NAME = 'psonoci-rust-runtime-enricher'
TOOL_VERSION = '1.1.0'


def rust_identity(evidence):
    release = re.search(r'^release: (\S+)$', evidence['rustc'], re.M)
    commit = re.search(r'^commit-hash: ([0-9a-f]{40})$', evidence['rustc'], re.M)
    if not release or not commit or evidence['target'] not in SUPPORTED_TARGETS:
        raise runtime.EvidenceError('runtime enrichment requires exact Rust identity and a supported release target')
    return release[1], commit[1]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def selected_packages(evidence, lock):
    by_crate = {}
    for package in lock['package']:
        if package.get('source') == 'registry+https://github.com/rust-lang/crates.io-index':
            by_crate.setdefault(package['name'].replace('-', '_'), []).append(package)
    selected = {}
    for component in evidence['components']:
        if component['name'] != 'Rust standard library':
            continue
        for proof in component['evidence']:
            name = Path(runtime.normalized_path(proof['path'])).name
            match = re.fullmatch(r'lib(.+)-[0-9a-f]+\.rlib', name)
            candidates = by_crate.get(match[1], []) if match else []
            if len(candidates) > 1:
                raise runtime.EvidenceError(f'{name}: ambiguous versions in Rust library lockfile')
            if candidates:
                selected[name] = candidates[0]
    if not selected:
        raise runtime.EvidenceError('no registry runtime archives found')
    return selected


def package_metadata(directory, package):
    filename = f"{package['name']}-{package['version']}.crate"
    data = (directory / filename).read_bytes()
    if sha256(data) != package['checksum']:
        raise runtime.EvidenceError(f'{filename}: registry checksum mismatch')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        member = archive.extractfile(f"{package['name']}-{package['version']}/Cargo.toml")
        if member is None:
            raise runtime.EvidenceError(f'{filename}: no package manifest')
        manifest = tomllib.loads(member.read().decode())['package']
    if (manifest['name'], manifest['version']) != (package['name'], package['version']):
        raise runtime.EvidenceError('registry package identity mismatch')
    license_id = sbom.normalize_license(manifest.get('license'))
    repository = manifest.get('repository')
    if not license_id or not repository:
        raise runtime.EvidenceError('runtime registry package needs license and source metadata')
    return manifest, license_id


def download(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def atomic_write(path: Path, data: bytes):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + '.', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def prepare(evidence, directory, *, offline=False, refresh=False):
    if offline and refresh:
        raise runtime.EvidenceError('--offline and --refresh cannot be combined')
    release, commit = rust_identity(evidence)
    directory.mkdir(parents=True, exist_ok=True)
    url = f'https://raw.githubusercontent.com/rust-lang/rust/{commit}/library/Cargo.lock'
    lock_path = directory / 'Cargo.lock'
    provenance_path = directory / 'provenance.json'
    cached = lock_path.is_file() and provenance_path.is_file()
    if cached and not refresh:
        provenance = json.loads(provenance_path.read_text())
        if (provenance.get('format'), provenance.get('rustRelease'), provenance.get('rustCommit'), provenance.get('lockUrl')) != (1, release, commit, url):
            raise runtime.EvidenceError('cached catalog belongs to another toolchain; use --refresh')
        data = lock_path.read_bytes()
        if sha256(data) != provenance.get('lockSha256'):
            raise runtime.EvidenceError('cached source lockfile is corrupt; use --refresh')
    else:
        if offline:
            raise runtime.EvidenceError('source catalog is not cached; prepare it online first')
        data = download(url)
    lock = tomllib.loads(data.decode())
    selected = selected_packages(evidence, lock)
    for package in {p['name']: p for p in selected.values()}.values():
        filename = f"{package['name']}-{package['version']}.crate"
        path = directory / filename
        if not path.is_file() or refresh:
            if offline:
                raise runtime.EvidenceError(f'{filename}: package is not cached')
            payload = download(f"https://static.crates.io/crates/{package['name']}/{filename}")
            if sha256(payload) != package['checksum']:
                raise runtime.EvidenceError(f'{filename}: downloaded registry checksum mismatch')
            atomic_write(path, payload)
        try:
            package_metadata(directory, package)
        except runtime.EvidenceError as error:
            raise runtime.EvidenceError(f'{error}; use --refresh to replace corrupt cache entries') from error
    atomic_write(lock_path, data)
    atomic_write(provenance_path, (json.dumps({
        'format': 1, 'rustRelease': release, 'rustCommit': commit,
        'lockUrl': url, 'lockSha256': sha256(data),
    }, indent=2) + '\n').encode())
    print(f'Prepared {len(selected)} checksum-verified registry packages at {commit}')


def enrich(evidence, directory, sysroot):
    result = copy.deepcopy(evidence)
    if 'rustStdRegistry' in result:
        raise runtime.EvidenceError('runtime evidence is already enriched')
    release, commit = rust_identity(result)
    provenance = json.loads((directory / 'provenance.json').read_text())
    expected_url = f'https://raw.githubusercontent.com/rust-lang/rust/{commit}/library/Cargo.lock'
    if (provenance.get('format'), provenance.get('rustRelease'), provenance.get('rustCommit'), provenance.get('lockUrl')) != (1, release, commit, expected_url):
        raise runtime.EvidenceError('runtime catalog belongs to a different Rust source/toolchain')
    data = (directory / 'Cargo.lock').read_bytes()
    if sha256(data) != provenance['lockSha256']:
        raise runtime.EvidenceError('Rust source lockfile checksum mismatch')
    lock = tomllib.loads(data.decode())
    selected = selected_packages(result, lock)
    std = next(c for c in result['components'] if c['name'] == 'Rust standard library')
    registry_components = {}
    records = []
    for proof in list(std['evidence']):
        archive_name = Path(runtime.normalized_path(proof['path'])).name
        if archive_name not in selected:
            continue
        package = selected[archive_name]
        archive = sysroot / 'lib/rustlib' / result['target'] / 'lib' / archive_name
        if not archive.is_file() or runtime.digest(archive) != proof['sha512']:
            raise runtime.EvidenceError(f'{archive_name}: captured archive differs from installed Rust sysroot')
        manifest, license_id = package_metadata(directory, package)
        component = runtime.identity(package['name'], package['version'],
                                     f"https://crates.io/crates/{package['name']}", license_id)
        component.update(purl=sbom.purl('cargo', package['name'], package['version']),
                         source=manifest['repository'], delivery='bundled',
                         origin='rust-std-registry', parentPurl=std['purl'], dependencyGraph='incomplete',
                         versionContext='registry version in the exact Rust source library lockfile; supplied sysroot linker input, not a reachability claim')
        evidence_record = dict(proof, method='linked sysroot archive hash; exact-commit Rust library Cargo.lock; checksum-verified upstream crate manifest',
                               rustCommit=commit, libraryLockSha256=provenance['lockSha256'],
                               registryPackageSha256=package['checksum'])
        existing = registry_components.setdefault(component['purl'], component)
        existing['evidence'].append(evidence_record)
        std['evidence'].remove(proof)
        records.append({'purl': component['purl'], 'archive': archive_name,
                        'registryPackageSha256': package['checksum'], 'archiveSha512': proof['sha512']})
    # Preserve observed package edges without turning core/alloc facades into
    # cycles through the aggregate std group. Feature-specific/internal edges
    # remain explicitly incomplete; source declarations are retained separately.
    by_name = {c['name']: c['purl'] for c in registry_components.values()}
    for package in selected.values():
        component = registry_components[sbom.purl('cargo', package['name'], package['version'])]
        edges = set()
        for dependency in package.get('dependencies', []):
            name = dependency.split()[0]
            if name in by_name:
                edges.add(by_name[name])
        component['dependsOn'] = sorted(edges)
        component['sourceDependencies'] = package.get('dependencies', [])
    std['dependencyGraph'] = 'incomplete'
    result['components'].extend(registry_components.values())
    result['components'].sort(key=lambda c: c['purl'])
    result['rustStdRegistry'] = dict(provenance, packages=records,
                                    tool={'name': TOOL_NAME, 'version': TOOL_VERSION},
                                    scope='registry crates in supplied Rust sysroot archives; internal Rust crates and native runtimes retain distribution identities')
    runtime.validate_evidence(result, result['binarySha512'], result['target'], result['imports'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'enrich'])
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--catalog', required=True, type=Path)
    parser.add_argument('--sysroot', type=Path)
    parser.add_argument('--offline', action='store_true', help='prepare only from verified cached inputs')
    parser.add_argument('--refresh', action='store_true', help='atomically replace cached inputs from pinned sources')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        evidence = json.loads(args.evidence.read_text())
        if args.command == 'prepare':
            prepare(evidence, args.catalog, offline=args.offline, refresh=args.refresh)
        else:
            if not args.sysroot or not args.output:
                parser.error('enrich requires --sysroot and --output')
            current = subprocess.check_output(['rustc', '-vV'], text=True)
            if rust_identity(dict(evidence, rustc=current)) != rust_identity(evidence):
                raise runtime.EvidenceError('active Rust toolchain differs from captured toolchain')
            expected = Path(subprocess.check_output(['rustc', '--print', 'sysroot'], text=True).strip())
            if args.sysroot.resolve() != expected.resolve():
                raise runtime.EvidenceError('--sysroot must be the active captured Rust toolchain')
            result = enrich(evidence, args.catalog, args.sysroot)
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
            print(f'Enriched {len(result["rustStdRegistry"]["packages"])} Rust runtime package inputs')
    except (runtime.EvidenceError, sbom.SbomError, OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(1, f'Rust runtime enrichment: {error}\n')


if __name__ == '__main__':
    main()

"""Verify source attribution and reject stale or altered runtime provenance."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from test_sbom import minimal_document, sbom

spec = importlib.util.spec_from_file_location('enrich_rust_runtime', Path(__file__).resolve().parents[1] / 'scripts/enrich-rust-runtime.py')
enrichment = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'sbom': sbom}):
    spec.loader.exec_module(enrichment)
helper_spec = importlib.util.spec_from_file_location('runtime_build_helper', Path(__file__).resolve().parents[1] / 'scripts/build-with-runtime-evidence.py')
helper = importlib.util.module_from_spec(helper_spec)
helper_spec.loader.exec_module(helper)


class RustRuntimeEnrichmentTests(unittest.TestCase):
    def test_ambiguous_locked_versions_are_not_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence, catalog, _ = self.fixture(Path(directory))
            lock = tomllib.loads((catalog / 'Cargo.lock').read_text())
            duplicate = copy.deepcopy(lock['package'][0])
            duplicate['version'] = '9.9.9'
            lock['package'].append(duplicate)
            with self.assertRaisesRegex(sbom.runtime_info.EvidenceError, 'ambiguous versions'):
                enrichment.selected_packages(evidence, lock)

    def fixture(self, root, target='x86_64-unknown-linux-musl'):
        evidence = json.loads(minimal_document('0' * 128, '1' * 128)['metadata']['properties'][-1]['value'])
        evidence['target'] = target
        musl = sbom.runtime_info.identity('musl', '1.2.5', 'https://musl.libc.org/', 'MIT')
        musl.update(delivery='bundled', evidence=[{'path': '/rust/libc.a', 'sha512': '3' * 128, 'method': 'fixture'}])
        evidence['components'].append(musl)
        evidence['inputs'].append({'path': '/rust/libc.a', 'sha512': '3' * 128})
        catalog = root / 'catalog'
        catalog.mkdir()
        sysroot = root / 'sysroot'
        libraries = sysroot / 'lib/rustlib' / evidence['target'] / 'lib'
        libraries.mkdir(parents=True)
        std = evidence['components'][0]
        lock = 'version = 4\n'
        for name, version in [('cfg-if', '1.0.4'), ('libc', '0.2.178')]:
            manifest = f'[package]\nname = "{name}"\nversion = "{version}"\nlicense = "MIT OR Apache-2.0"\nrepository = "https://example.test/{name}"\n'
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
                member = tarfile.TarInfo(f'{name}-{version}/Cargo.toml')
                member.size = len(manifest.encode())
                archive.addfile(member, io.BytesIO(manifest.encode()))
            payload = buffer.getvalue()
            (catalog / f'{name}-{version}.crate').write_bytes(payload)
            lock += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "{hashlib.sha256(payload).hexdigest()}"\ndependencies = ["rustc-std-workspace-core"]\n'
            archive_name = f'lib{name.replace("-", "_")}-abcdef.rlib'
            (libraries / archive_name).write_bytes(name.encode())
            proof = {'path': '/captured/sysroot/' + archive_name, 'sha512': hashlib.sha512(name.encode()).hexdigest(), 'method': 'fixture'}
            std['evidence'].append(proof)
            evidence['inputs'].append({k: proof[k] for k in ('path', 'sha512')})
        (catalog / 'Cargo.lock').write_text(lock)
        (catalog / 'provenance.json').write_text(json.dumps({
            'format': 1, 'rustRelease': '1.94.1', 'rustCommit': 'a' * 40,
            'lockSha256': hashlib.sha256(lock.encode()).hexdigest(),
            'lockUrl': 'https://raw.githubusercontent.com/rust-lang/rust/' + 'a' * 40 + '/library/Cargo.lock',
        }))
        return evidence, catalog, sysroot

    def test_packages_gain_registry_identities_and_retained_input_proofs(self):
        for target in enrichment.SUPPORTED_TARGETS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                evidence, catalog, sysroot = self.fixture(Path(directory), target)
                result = enrichment.enrich(evidence, catalog, sysroot)
                crates = [c for c in result['components'] if c.get('origin') == 'rust-std-registry']
                self.assertEqual({c['purl'] for c in crates}, {'pkg:cargo/cfg-if@1.0.4', 'pkg:cargo/libc@0.2.178'})
                self.assertEqual(len(result['inputs']), len(evidence['inputs']))
                self.assertEqual(len(next(c for c in result['components'] if c['name'] == 'Rust standard library')['evidence']), 1)
                self.assertTrue(all(c['dependsOn'] == [evidence['components'][0]['purl']] for c in crates))
                self.assertNotIn('rustStdRegistry', evidence)

    def test_every_release_musl_target_is_supported(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/release.yml').read_text()
        targets = set(re.findall(r'target: (\S*musl\S*)', workflow))
        self.assertEqual(targets, enrichment.SUPPORTED_TARGETS)

    def test_build_helper_enriches_all_musl_targets_and_skips_other_platforms(self):
        for target in enrichment.SUPPORTED_TARGETS | {'armv7-unknown-linux-gnueabihf', 'x86_64-apple-darwin', 'x86_64-pc-windows-gnu', 'x86_64-pc-windows-msvc'}:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence = root / 'psonoci.runtime.json'
                evidence.write_text('original evidence')
                commands = []

                def run(command, **kwargs):
                    commands.append(command)
                    if 'enrich' in command:
                        Path(command[command.index('--output') + 1]).write_text('enriched evidence')

                with patch.object(helper, 'ROOT', root), patch.object(helper, 'run', side_effect=run), patch.object(helper.subprocess, 'check_output', return_value='/exact/sysroot\n') as sysroot:
                    helper.enrich_musl_runtime(target, evidence, {})
                if target in enrichment.SUPPORTED_TARGETS:
                    self.assertEqual(evidence.read_text(), 'enriched evidence')
                    self.assertEqual(commands[0], ['rustup', 'target', 'add', target])
                    self.assertIn(str(root / '.sbom-tools/rust-runtime' / target), commands[1])
                    self.assertIn('/exact/sysroot', commands[2])
                else:
                    self.assertEqual(evidence.read_text(), 'original evidence')
                    self.assertEqual(commands, [])
                    sysroot.assert_not_called()

    def test_failed_enrichment_does_not_replace_original_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / 'psonoci.runtime.json'
            evidence.write_text('original evidence')

            def run(command, **kwargs):
                if 'enrich' in command:
                    raise subprocess.CalledProcessError(1, command)

            with patch.object(helper, 'ROOT', root), patch.object(helper, 'run', side_effect=run), patch.object(helper.subprocess, 'check_output', return_value='/sysroot\n'):
                with self.assertRaises(subprocess.CalledProcessError):
                    helper.enrich_musl_runtime('aarch64-unknown-linux-musl', evidence, {})
            self.assertEqual(evidence.read_text(), 'original evidence')

    def test_modified_registry_archive_source_lock_and_sysroot_fail(self):
        for part in ('registry', 'lock', 'sysroot', 'toolchain'):
            with self.subTest(part=part), tempfile.TemporaryDirectory() as directory:
                evidence, catalog, sysroot = self.fixture(Path(directory))
                if part == 'registry':
                    next(catalog.glob('*.crate')).write_bytes(b'changed package')
                elif part == 'lock':
                    with (catalog / 'Cargo.lock').open('a') as stream:
                        stream.write('\n# changed source')
                elif part == 'sysroot':
                    next(sysroot.rglob('*.rlib')).write_bytes(b'different distribution archive')
                else:
                    evidence['rustc'] = evidence['rustc'].replace('a' * 40, 'b' * 40)
                with self.assertRaises(sbom.runtime_info.EvidenceError):
                    enrichment.enrich(evidence, catalog, sysroot)

    def test_enriched_evidence_rejects_changed_registry_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence, catalog, sysroot = self.fixture(Path(directory))
            result = enrichment.enrich(evidence, catalog, sysroot)
            result['rustStdRegistry']['packages'][0]['registryPackageSha256'] = 'f' * 64
            with self.assertRaisesRegex(sbom.runtime_info.EvidenceError, 'checksum proof differs'):
                sbom.runtime_info.validate_evidence(result, result['binarySha512'], result['target'], [])

    def test_shared_application_package_is_merged_and_conflicts_fail(self):
        existing = {'bom-ref': 'pkg:cargo/cfg-if@1.0.4', 'name': 'cfg-if', 'version': '1.0.4',
                    'purl': 'pkg:cargo/cfg-if@1.0.4', 'licenses': [{'expression': 'MIT OR Apache-2.0'}],
                    'properties': [{'name': 'application-evidence', 'value': 'yes'}]}
        runtime = dict(copy.deepcopy(existing), properties=[{'name': 'psonoci:runtime:delivery', 'value': 'bundled'}])
        components = [copy.deepcopy(existing)]
        qualified_ref = existing['bom-ref'] + '?package-id=012345'
        components[0]['bom-ref'] = qualified_ref
        aliases = sbom.merge_runtime_components(components, [runtime])
        self.assertEqual(len(components), 1)
        self.assertEqual(aliases, {qualified_ref: existing['bom-ref']})
        self.assertEqual(components[0]['bom-ref'], existing['bom-ref'])
        self.assertEqual(len(components[0]['properties']), 2)
        runtime['licenses'] = [{'expression': 'GPL-3.0-only'}]
        with self.assertRaisesRegex(sbom.SbomError, 'metadata disagree'):
            sbom.merge_runtime_components([existing], [runtime])

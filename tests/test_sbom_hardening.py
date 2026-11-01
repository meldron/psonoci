"""Regression cases from the independent SBOM review."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch
import zipfile

from test_sbom import minimal_document, sbom, ROOT
from test_sbom_runtime import elf

runtime = sbom.runtime_info


class ElfLoaderTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux') and Path('/bin/true').is_file(), 'requires host ELF executable')
    def test_runnable_elf_without_section_headers_keeps_all_imports(self):
        original = Path('/bin/true').read_bytes()
        self.assertEqual(original[:6], b'\x7fELF\x02\x01')
        changed = bytearray(original)
        changed[40:48] = b'\0' * 8
        changed[58:64] = b'\0' * 6
        expected = runtime.imports(original)
        self.assertTrue(any(i['name'].startswith('libc.so') for i in expected))
        self.assertEqual(runtime.imports(changed), expected)
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'true'
            executable.write_bytes(changed)
            executable.chmod(0o700)
            self.assertEqual(subprocess.run([str(executable)]).returncode, 0)

    def test_elf32_dynamic_addresses_without_sections(self):
        data = bytearray(512)
        data[:6] = b'\x7fELF\x01\x01'
        struct.pack_into('<I', data, 28, 52)
        struct.pack_into('<HH', data, 42, 32, 2)
        struct.pack_into('<IIIIIIII', data, 52, 1, 0, 0x10000, 0, len(data), len(data), 4, 4096)
        struct.pack_into('<IIIIIIII', data, 84, 2, 128, 0x10080, 0, 32, 32, 4, 4)
        strings = b'\0libc.so.6\0'
        struct.pack_into('<IIIIIIII', data, 128, 1, 1, 5, 0x10100, 10, len(strings), 0, 0)
        data[256:256 + len(strings)] = strings
        self.assertEqual(runtime.imports(data), [{'name': 'libc.so.6'}])
        struct.pack_into('<I', data, 128, 14)
        self.assertEqual(runtime.elf_soname(data), 'libc.so.6')

    def test_dynamic_string_bounds_and_truncated_headers_fail_closed(self):
        data = bytearray(elf(['libc.so.6']))
        struct.pack_into('<Q', data, 280, 0xffffffffffffffff)
        with self.assertRaises(runtime.EvidenceError):
            runtime.imports(data)
        with self.assertRaises(runtime.EvidenceError):
            runtime.imports(elf()[:100])


class ReviewedLicenseTests(unittest.TestCase):
    def setUp(self):
        self.release = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
        self.directory = ROOT / 'sbom/toolchain-sources' / self.release
        self.provenance = json.loads((self.directory / 'provenance.json').read_text())
        self.commit = self.provenance['rustCommit']

    def test_compiler_builtins_preserves_exact_source_declaration(self):
        package = tomllib.loads((self.directory / 'compiler-builtins.Cargo.toml').read_text())['package']
        component = runtime.toolchain_runtime('compiler-builtins', self.release, self.commit)
        self.assertEqual(component['license'], package['license'])
        self.assertIn('AND Apache-2.0 WITH LLVM-exception', component['license'])
        self.assertIn(package['version'], component['versionContext'])

    def test_startup_is_llvm_and_unwind_keeps_complete_notice(self):
        startup = runtime.toolchain_runtime('startup', self.release, self.commit)
        self.assertEqual(startup['license'], 'Apache-2.0 WITH LLVM-exception')
        unwind = runtime.toolchain_runtime('unwind', self.release, self.commit)
        self.assertEqual(unwind['licenseText'], (self.directory / 'libunwind.LICENSE.txt').read_text())
        self.assertIn('University of Illinois', unwind['licenseText'])

    def test_source_changes_and_wrong_toolchain_are_rejected(self):
        with self.assertRaises(runtime.EvidenceError):
            runtime.toolchain_runtime('compiler-builtins', self.release, 'a' * 40)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / 'sbom/toolchain-sources' / self.release
            shutil.copytree(self.directory, destination)
            (destination / 'compiler-builtins.Cargo.toml').write_text('[package]\nlicense="MIT"')
            with patch.object(runtime, '__file__', str(root / 'scripts/runtime_evidence.py')):
                with self.assertRaisesRegex(runtime.EvidenceError, 'checksum mismatch'):
                    runtime.toolchain_runtime('compiler-builtins', self.release, self.commit)


class ObjectCoverageTests(unittest.TestCase):
    def test_root_objects_require_explicit_output_ownership(self):
        output = '/target/release/deps/psonoci-123'
        entry = {'path': output + '.crate.rcgu.o', 'role': 'root-rust-object'}
        capture = {'output': output, 'arguments': [entry['path']]}
        self.assertIsNotNone(runtime.root_object_input(entry, capture, '1' * 128))
        for path in ('/target/release/deps/codec.o', '/foreign/psonoci-123.crate.rcgu.o'):
            with self.subTest(path=path), self.assertRaises(runtime.EvidenceError):
                runtime.root_object_input(dict(entry, path=path), dict(capture, arguments=[path]), '1' * 128)
        self.assertIsNone(runtime.root_object_input({'path': '/native/codec.o', 'role': 'provider'}, capture, '1' * 128))

    def test_an_unidentified_native_object_stops_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'binary').write_bytes(elf())
            (root / 'std.rlib').write_bytes(b'std')
            (root / 'codec.o').write_bytes(b'native code')
            (root / 'providers.json').write_text('{"format":1,"bySha512":{}}')
            (root / 'capture.json').write_text(json.dumps({'format': 1, 'target': 'x86_64-unknown-linux-gnu', 'builderImage': 'native',
                'rustc': 'release: 1.94.1\ncommit-hash: ' + 'a' * 40 + '\n', 'inputs': [
                    {'path': '/rust/lib/rustlib/target/lib/libstd-abc.rlib', 'copy': 'std.rlib'},
                    {'path': '/native/codec.o', 'copy': 'codec.o'}]}))
            with self.assertRaisesRegex(runtime.EvidenceError, 'unresolved native'):
                runtime.collect(root / 'binary', 'x86_64-unknown-linux-gnu', root, root / 'providers.json')
            unresolved = json.loads((root / 'unresolved-inputs.json').read_text())
            self.assertEqual(unresolved[0]['path'], '/native/codec.o')


class OpaqueGraphTests(unittest.TestCase):
    def document(self):
        document = minimal_document('0' * 128, '1' * 128)
        evidence = json.loads(document['metadata']['properties'][-1]['value'])
        item = runtime.identity('Example platform', '1.0', 'https://example.test/')
        proof = {'path': '/os/runtime', 'sha512': '4' * 128, 'method': 'fixture'}
        item.update(delivery='external', dependencyGraph='unknown', evidence=[proof])
        evidence['components'].append(item)
        evidence['inputs'].append({'path': proof['path'], 'sha512': proof['sha512']})
        document['metadata']['properties'][-1]['value'] = json.dumps(evidence)
        document['components'].append({'type': 'library', 'bom-ref': item['purl'], 'purl': item['purl'],
            'name': item['name'], 'version': item['version'],
            'externalReferences': [{'type': 'website', 'url': item['creator']}], 'properties': [
                {'name': 'psonoci:runtime:delivery', 'value': 'external'},
                {'name': 'psonoci:runtime:dependency-graph', 'value': 'unknown'},
                {'name': 'psonoci:runtime:evidence', 'value': json.dumps([proof], sort_keys=True)},
                {'name': 'psonoci:runtime:imports', 'value': '[]'}]})
        document['dependencies'][1]['dependsOn'].append(item['purl'])
        document['compositions'][0]['dependencies'] = [item['purl']]
        return document, item['purl']

    def test_unknown_runtime_is_a_referenced_component_without_a_leaf_record(self):
        document, _ = self.document()
        sbom.validate_document(document)

    def test_unknown_graph_cannot_masquerade_as_empty_or_lose_scope(self):
        for mutate in ('leaf', 'scope'):
            with self.subTest(mutate=mutate):
                document, ref = self.document()
                if mutate == 'leaf':
                    document['dependencies'].append({'ref': ref, 'dependsOn': []})
                else:
                    document['compositions'][0].pop('dependencies')
                with self.assertRaises(sbom.SbomError):
                    sbom.validate_document(document)


class ArchiveInventoryTests(unittest.TestCase):
    def test_tar_rejects_extra_files_links_and_traversal(self):
        for kind in ('extra', 'link', 'traversal'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'archive.tar.gz'
                with tarfile.open(path, 'w:gz') as archive:
                    binary = tarfile.TarInfo('app')
                    binary.size = 3
                    archive.addfile(binary, io.BytesIO(b'app'))
                    other = tarfile.TarInfo('../app' if kind == 'traversal' else 'extra')
                    if kind == 'link':
                        other.type = tarfile.SYMTYPE
                        other.linkname = 'app'
                    archive.addfile(other)
                with self.assertRaises(sbom.SbomError):
                    sbom.archive_member_hashes(path, 'app')

    def test_zip_rejects_uninventoried_members(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'archive.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('app', b'app')
                archive.writestr('LICENSE', b'new delivery file')
            with self.assertRaisesRegex(sbom.SbomError, 'uninventoried'):
                sbom.archive_member_hashes(path, 'app')


class AdvisoryIdentityTests(unittest.TestCase):
    def test_reviewed_native_names_and_uncertain_distributions(self):
        self.assertEqual(runtime.native_cpe('musl', '1.2.5'), 'cpe:2.3:a:musl-libc:musl:1.2.5:*:*:*:*:*:*:*')
        self.assertEqual(runtime.native_cpe('OpenSSL', '3.6.3'), 'cpe:2.3:a:openssl:openssl:3.6.3:*:*:*:*:*:*:*')
        self.assertIsNone(runtime.native_cpe('GCC runtime', '9.2.0'))
        with self.assertRaises(runtime.EvidenceError):
            runtime.native_cpe('musl', '1.2.5:*')


class OpenSSLSourceTests(unittest.TestCase):
    def test_reviewed_adapter_and_native_version_match_the_local_override(self):
        source = runtime.vendored_openssl_source()
        self.assertEqual(source['version'], '3.5.9')
        self.assertEqual(source['commit'], '45e844fa2a14ec92d146bd8f5778ac130b6625fb')

    def test_changed_adapter_or_package_identity_is_rejected(self):
        for part in ('adapter', 'version'):
            with self.subTest(part=part), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                destination = root / 'vendor/openssl-src'
                shutil.copytree(ROOT / 'vendor/openssl-src', destination,
                                ignore=shutil.ignore_patterns('openssl'))
                if part == 'adapter':
                    with (destination / 'src/lib.rs').open('a') as handle:
                        handle.write('// changed build adapter\n')
                else:
                    manifest = destination / 'Cargo.toml'
                    manifest.write_text(manifest.read_text().replace('+3.5.9', '+3.6.3'))
                with patch.object(runtime, '__file__', str(root / 'scripts/runtime_evidence.py')):
                    with self.assertRaises(runtime.EvidenceError):
                        runtime.vendored_openssl_source()

    def test_missing_submodule_and_wrong_source_commit_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / 'vendor/openssl-src'
            shutil.copytree(ROOT / 'vendor/openssl-src', destination,
                            ignore=shutil.ignore_patterns('openssl'))
            with patch.object(runtime, '__file__', str(root / 'scripts/runtime_evidence.py')):
                with self.assertRaisesRegex(runtime.EvidenceError, 'initialize OpenSSL source'):
                    runtime.vendored_openssl_source(verify_checkout=True)
                checkout = destination / 'openssl'
                checkout.mkdir()
                (checkout / 'VERSION.dat').write_text('MAJOR=3\nMINOR=5\nPATCH=9\n')
                with patch.object(runtime.subprocess, 'check_output', side_effect=['a' * 40, '']):
                    with self.assertRaisesRegex(runtime.EvidenceError, 'clean, pinned official release'):
                        runtime.vendored_openssl_source(verify_checkout=True)

"""Runtime coverage tests use binary-format fixtures, not target execution."""
import copy
import hashlib
import json
import struct
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from test_sbom import minimal_document, sbom

runtime = sbom.runtime_info


def elf(names=(), version=None):
    data = bytearray(512)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H', data, 18, 62)
    struct.pack_into('<Q', data, 40, 64)
    struct.pack_into('<HHH', data, 58, 64, 3, 2)
    if version is not None:
        value = version.encode() + b'\0'
        struct.pack_into('<I', data, 128 + 4, 1)
        struct.pack_into('<Q', data, 128 + 8, 2)
        struct.pack_into('<QQ', data, 128 + 24, 300, len(value))
        data[300:300 + len(value)] = value
    else:
        strings = b'\0'
        for index, name in enumerate(names):
            struct.pack_into('<QQ', data, 256 + index * 16, 1, len(strings))
            strings += name.encode() + b'\0'
        struct.pack_into('<I', data, 128 + 4, 6)
        struct.pack_into('<QQI', data, 128 + 24, 256, (len(names) + 1) * 16, 2)
        struct.pack_into('<I', data, 192 + 4, 3)
        struct.pack_into('<QQ', data, 192 + 24, 400, len(strings))
        data[400:400 + len(strings)] = strings
    return bytes(data)


def ar(name, payload):
    header = f'{name + "/":<16}{0:<12}{0:<6}{0:<6}{0:<8}{len(payload):<10}`\n'.encode()
    return b'!<arch>\n' + header + payload + (b'\n' if len(payload) % 2 else b'')


def macho():
    name = b'/usr/lib/libSystem.B.dylib\0'
    size = (24 + len(name) + 7) & ~7
    data = bytearray(32 + size)
    data[:4] = b'\xcf\xfa\xed\xfe'
    struct.pack_into('<I', data, 16, 1)
    struct.pack_into('<IIIIII', data, 32, 0xc, size, 24, 0, (1351 << 16) | 1, (1 << 16))
    data[56:56 + len(name)] = name
    return bytes(data)


def pe():
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<H', data, 134, 1)
    struct.pack_into('<H', data, 148, 240)
    struct.pack_into('<H', data, 152, 0x20b)
    struct.pack_into('<II', data, 152 + 112 + 8, 0x1000, 40)
    struct.pack_into('<II', data, 152 + 112 + 13 * 8, 0x1040, 64)
    struct.pack_into('<IIII', data, 152 + 240 + 8, 512, 0x1000, 512, 512)
    struct.pack_into('<I', data, 512 + 12, 0x1100)
    struct.pack_into('<II', data, 512 + 64, 1, 0x1120)
    data[768:781] = b'KERNEL32.dll\0'
    data[800:817] = b'VCRUNTIME140.dll\0'
    return bytes(data)


class BinaryRuntimeTests(unittest.TestCase):
    def test_elf_needed_names_and_static_binary(self):
        self.assertEqual(runtime.imports(elf()), [])
        self.assertEqual(runtime.imports(elf(['libc.so.6', 'libgcc_s.so.1'])),
                         [{'name': 'libc.so.6'}, {'name': 'libgcc_s.so.1'}])

    def test_elf_interpreter_is_a_direct_external_runtime(self):
        data = bytearray(elf())
        struct.pack_into('<Q', data, 32, 256)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<IIQ', data, 256, 3, 0, 320)
        value = b'/lib64/ld-linux-x86-64.so.2\0'
        data[320:320 + len(value)] = value
        self.assertEqual(runtime.imports(bytes(data)), [{'name': 'ld-linux-x86-64.so.2',
                         'interpreterPath': '/lib64/ld-linux-x86-64.so.2'}])

    def test_macho_preserves_link_interface_version_meaning(self):
        self.assertEqual(runtime.imports(macho()), [{'name': '/usr/lib/libSystem.B.dylib',
                         'linkInterfaceVersion': '1351.0.1', 'compatibilityVersion': '1.0.0'}])

    def test_pe_reads_normal_and_delay_imports(self):
        self.assertEqual(runtime.imports(pe()), [{'name': 'kernel32.dll'}, {'name': 'vcruntime140.dll'}])

    def test_musl_uses_allocated_version_object_not_debug_strings(self):
        object_data = elf(version='1.2.5') + b'99.98.97\0'
        self.assertEqual(runtime.musl_version(ar('version.lo', object_data)), '1.2.5')
        with self.assertRaisesRegex(runtime.EvidenceError, 'version.lo'):
            runtime.musl_version(ar('something.o', object_data))
        with self.assertRaises(runtime.EvidenceError):
            runtime.musl_version(ar('version.lo', elf()))

    def test_unknown_and_malformed_binary_fail(self):
        with self.assertRaises(runtime.EvidenceError):
            runtime.imports(b'not a supported binary')
        malformed = bytearray(macho())
        struct.pack_into('<I', malformed, 36, 0xffffffff)
        with self.assertRaises(runtime.EvidenceError):
            runtime.imports(bytes(malformed))

    def test_coff_import_library_descriptors(self):
        payload = b'Function\0KERNEL32.dll\0'
        header = struct.pack('<HHHHIIHH', 0, 0xffff, 0, 0x8664, 0, len(payload), 0, 0)
        self.assertEqual(runtime.import_library_names(ar('import.obj', header + payload)), {'kernel32.dll'})
        self.assertEqual(runtime.import_library_names(ar('native.obj', b'KERNEL32.dll\0')), set())


class EvidencePolicyTests(unittest.TestCase):
    def setUp(self):
        self.document = minimal_document('0' * 128, '1' * 128)
        self.evidence = json.loads(self.document['metadata']['properties'][-1]['value'])

    def test_valid_minimum_inventory(self):
        runtime.validate_evidence(self.evidence, '1' * 128, 'x86_64-unknown-linux-gnu', [])

    def test_binary_and_target_binding(self):
        for digest, target in [('0' * 128, 'x86_64-unknown-linux-gnu'), ('1' * 128, 'aarch64-apple-darwin')]:
            with self.subTest(target=target), self.assertRaises(runtime.EvidenceError):
                runtime.validate_evidence(self.evidence, digest, target, [])

    def test_unmapped_import_and_uncovered_input_fail(self):
        for change in ('import', 'input'):
            evidence = copy.deepcopy(self.evidence)
            if change == 'import':
                evidence['imports'] = [{'name': 'libc.so.6'}]
            else:
                evidence['inputs'].append({'path': '/native/libunknown.a', 'sha512': '3' * 128})
            with self.subTest(change=change), self.assertRaises(runtime.EvidenceError):
                runtime.validate_evidence(evidence, '1' * 128, 'x86_64-unknown-linux-gnu', evidence['imports'])

    def test_unknown_version_and_missing_musl_fail(self):
        bad = copy.deepcopy(self.evidence)
        bad['components'][0]['version'] = 'unknown'
        with self.assertRaises(runtime.EvidenceError):
            runtime.validate_evidence(bad, '1' * 128, 'x86_64-unknown-linux-gnu', [])
        bad = copy.deepcopy(self.evidence)
        bad['target'] = 'x86_64-unknown-linux-musl'
        with self.assertRaisesRegex(runtime.EvidenceError, 'musl'):
            runtime.validate_evidence(bad, '1' * 128, bad['target'], [])

    def test_sbom_runtime_cannot_be_removed_or_disconnected(self):
        for mutation in ('remove', 'disconnect', 'version'):
            document = copy.deepcopy(self.document)
            if mutation == 'remove':
                document['components'].pop()
            elif mutation == 'disconnect':
                document['dependencies'][1]['dependsOn'] = []
            else:
                document['components'][-1]['version'] = '1.0.0'
            with self.subTest(mutation=mutation), self.assertRaises(sbom.SbomError):
                sbom.validate_document(document)

    def test_release_rechecks_imports_independently(self):
        with self.assertRaisesRegex(runtime.EvidenceError, 'import list'):
            runtime.validate_evidence(self.evidence, '1' * 128, 'x86_64-unknown-linux-gnu', runtime.imports(elf(['libc.so.6'])))


class CaptureTests(unittest.TestCase):
    def capture(self, root, binary_data, target, native_name, native_data):
        (root / 'binary').write_bytes(binary_data)
        (root / 'std.rlib').write_bytes(b'exact standard library')
        (root / 'native.lib').write_bytes(native_data)
        (root / 'providers.json').write_text('{"format":1,"bySha512":{}}')
        (root / 'capture.json').write_text(json.dumps({
            'format': 1, 'target': target, 'builderImage': 'native',
            'rustc': 'release: 1.94.1\ncommit-hash: ' + 'a' * 40 + '\n',
            'inputs': [{'path': '/rust/lib/rustlib/target/lib/libstd-abc.rlib', 'copy': 'std.rlib'},
                       {'path': native_name, 'copy': 'native.lib'}],
        }))

    def test_macos_sdk_alias_and_interface_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.capture(root, macho(), 'x86_64-apple-darwin', '/SDKs/MacOSX.sdk/usr/lib/libSystem.tbd',
                         b"install-name: '/usr/lib/libSystem.B.dylib'\n")
            result = runtime.collect(root / 'binary', 'x86_64-apple-darwin', root, root / 'providers.json')
            component = next(c for c in result['components'] if c['delivery'] == 'external')
            self.assertEqual(component['version'], '1351.0.1')
            self.assertIn('link-interface', component['versionContext'])

    def test_windows_import_library_and_loader_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b'Function\0KERNEL32.dll\0'
            short = struct.pack('<HHHHIIHH', 0, 0xffff, 0, 0x8664, 0, len(payload), 0, 0)
            self.capture(root, pe(), 'x86_64-pc-windows-msvc', '/SDK/um/x64/kernel32.lib', ar('import.obj', short + payload))
            dll = root / 'resolved.dll'
            dll.write_bytes(b'exact build-host DLL')

            def observe(command, **kwargs):
                self.assertIn('0x801', command[-1])
                self.assertIn(kwargs['env']['PSONOCI_DLL_NAME'], ['kernel32.dll', 'vcruntime140.dll'])
                return type('Result', (), {'stdout': json.dumps({'path': str(dll), 'version': '10.0.1.2', 'company': 'Microsoft Corporation'})})()

            with patch.object(runtime.sys, 'platform', 'win32'), patch.object(runtime.subprocess, 'run', side_effect=observe):
                result = runtime.collect(root / 'binary', 'x86_64-pc-windows-msvc', root, root / 'providers.json')
            external = [c for c in result['components'] if c['delivery'] == 'external']
            self.assertEqual(len(external), 2)
            self.assertTrue(all('build host' in c['versionContext'] for c in external))
            kernel = next(c for c in external if c['name'] == 'kernel32.dll')
            self.assertEqual(len(kernel['evidence']), 2)

    def test_unresolved_input_requires_exact_hash_provider_and_rejects_stale_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            binary.write_bytes(elf())
            std = root / 'std.rlib'
            std.write_bytes(b'exact std library')
            native = root / 'native.a'
            native.write_bytes(b'exact native library')
            capture = {'format': 1, 'target': 'x86_64-unknown-linux-gnu', 'builderImage': 'native',
                       'rustc': 'release: 1.94.1\ncommit-hash: ' + 'a' * 40 + '\n',
                       'inputs': [{'path': '/rust/lib/rustlib/target/lib/libstd-abc.rlib', 'copy': 'std.rlib'},
                                  {'path': '/native/libunknown.a', 'copy': 'native.a'}]}
            (root / 'capture.json').write_text(json.dumps(capture))
            provider = root / 'providers.json'
            provider.write_text(json.dumps({'format': 1, 'bySha512': {}}))
            with self.assertRaisesRegex(runtime.EvidenceError, 'unresolved native'):
                runtime.collect(binary, capture['target'], root, provider)
            provider.write_text(json.dumps({'format': 1, 'bySha512': {runtime.digest(native): {
                'name': 'Example native library', 'version': '2.3.4', 'creator': 'https://example.test',
                'license': 'MIT', 'source': 'https://example.test/releases/2.3.4',
                'method': 'verified upstream release archive and source build manifest',
            }}}))
            result = runtime.collect(binary, capture['target'], root, provider)
            self.assertEqual(len(result['components']), 2)
            other = root / 'other'
            other.write_bytes(elf(['libc.so.6']))
            with self.assertRaisesRegex(runtime.EvidenceError, 'different executable'):
                runtime.collect(other, capture['target'], root, provider)


if __name__ == '__main__':
    unittest.main()

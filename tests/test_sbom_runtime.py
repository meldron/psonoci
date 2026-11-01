"""Runtime coverage tests use binary-format fixtures, not target execution."""
import copy
import hashlib
import json
import struct
import tempfile
import unittest
import importlib.util
from unittest.mock import patch
from pathlib import Path

from test_sbom import minimal_document, sbom

runtime = sbom.runtime_info


def elf(names=(), version=None):
    data = bytearray(1024)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H', data, 16, 3 if version is None else 1)
    struct.pack_into('<H', data, 18, 62)
    if version is not None:
        struct.pack_into('<Q', data, 40, 64)
        struct.pack_into('<HHH', data, 58, 64, 3, 2)
        value = version.encode() + b'\0'
        struct.pack_into('<I', data, 128 + 4, 1)
        struct.pack_into('<Q', data, 128 + 8, 2)
        struct.pack_into('<QQ', data, 128 + 24, 600, len(value))
        data[600:600 + len(value)] = value
    else:
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 2)
        struct.pack_into('<IIQQQQQQ', data, 64, 1, 4, 0, 0x400000, 0, len(data), len(data), 4096)
        strings = b'\0'
        for index, name in enumerate(names):
            struct.pack_into('<QQ', data, 256 + index * 16, 1, len(strings))
            strings += name.encode() + b'\0'
        location = 256 + len(names) * 16
        struct.pack_into('<QQQQQQ', data, location, 5, 0x400000 + 600, 10, len(strings), 0, 0)
        size = (len(names) + 3) * 16
        struct.pack_into('<IIQQQQQQ', data, 120, 2, 4, 256, 0x400100, 0, size, size, 8)
        data[600:600 + len(strings)] = strings
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


def macho_with_sections():
    data = bytearray(512)
    data[:4] = b'\xcf\xfa\xed\xfe'
    struct.pack_into('<I', data, 16, 2)
    struct.pack_into('<II', data, 32, 0x19, 152)
    data[40:46] = b'__TEXT'
    struct.pack_into('<QQQQIIII', data, 56, 4096, 4096, 0, 512, 7, 5, 1, 0)
    data[104:110] = b'__text'
    data[120:126] = b'__TEXT'
    struct.pack_into('<QQI', data, 136, 4096, 4, 300)
    struct.pack_into('<II', data, 184, 0x2, 24)
    data[300:304] = b'CODE'
    return data


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
    def test_shared_library_soname_is_distinct_from_linker_filename(self):
        data = bytearray(elf(['libm.so.6']))
        struct.pack_into('<Q', data, 256, 14)
        self.assertEqual(runtime.elf_soname(bytes(data)), 'libm.so.6')
        self.assertEqual(runtime.imports(bytes(data)), [])
        self.assertIsNone(runtime.elf_soname(elf()))
        self.assertIsNone(runtime.elf_soname(b'linker script'))

    def test_elf_needed_names_and_static_binary(self):
        self.assertEqual(runtime.imports(elf()), [])
        self.assertEqual(runtime.imports(elf(['libc.so.6', 'libgcc_s.so.1'])),
                         [{'name': 'libc.so.6'}, {'name': 'libgcc_s.so.1'}])

    def test_elf_interpreter_is_a_direct_external_runtime(self):
        data = bytearray(elf())
        struct.pack_into('<HH', data, 54, 56, 3)
        value = b'/lib64/ld-linux-x86-64.so.2\0'
        struct.pack_into('<IIQQQQQQ', data, 176, 3, 4, 700, 0, 0, len(value), len(value), 1)
        data[700:700 + len(value)] = value
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

    def test_macho_post_link_comparison_preserves_code_and_loader(self):
        original = macho_with_sections()
        changed = bytearray(original)
        changed[192:200] = b'DEBUG123'
        self.assertEqual(runtime.macho_runtime_fingerprint(original), runtime.macho_runtime_fingerprint(changed))
        changed[300] ^= 1
        self.assertNotEqual(runtime.macho_runtime_fingerprint(original), runtime.macho_runtime_fingerprint(changed))

    def test_windows_repeated_separators_normalize_to_cargo_paths(self):
        self.assertEqual(runtime.normalized_path(r'D:\\a\\repo\\target\\release\\deps\\liba.rlib'),
                         'D:/a/repo/target/release/deps/liba.rlib')


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
    def test_glibc_linker_alias_maps_to_actual_soname(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = bytearray(elf(['libm.so.6']))
            struct.pack_into('<Q', library, 256, 14)
            self.capture(root, elf(['libm.so.6']), 'armv7-unknown-linux-gnueabihf', '/lib/libm.so', library)
            (root / 'libc').write_bytes(b'stable release version 2.23')
            capture = json.loads((root / 'capture.json').read_text())
            capture['inputs'].append({'path': '/lib/libc.so.6', 'copy': 'libc'})
            (root / 'capture.json').write_text(json.dumps(capture))
            result = runtime.collect(root / 'binary', 'armv7-unknown-linux-gnueabihf', root, root / 'providers.json')
            glibc = next(c for c in result['components'] if c['name'] == 'glibc')
            self.assertEqual(glibc['version'], '2.23')
            self.assertEqual(glibc['imports'], ['libm.so.6'])
            self.assertEqual(glibc['delivery'], 'external')

    def test_unused_sdk_import_interface_keeps_package_identity_without_dll_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b'Function\0WINSPOOL.DRV\0'
            short = struct.pack('<HHHHIIHH', 0, 0xffff, 0, 0x8664, 0, len(payload), 0, 0)
            self.capture(root, elf(), 'x86_64-pc-windows-msvc',
                         'C:/Program Files (x86)/Windows Kits/10/lib/10.0.26100.0/um/x64/winspool.lib',
                         ar('import.obj', short + payload))
            with patch.object(runtime.sys, 'platform', 'win32'):
                result = runtime.collect(root / 'binary', 'x86_64-pc-windows-msvc', root, root / 'providers.json')
            sdk = next(c for c in result['components'] if c['name'] == 'Microsoft Windows SDK import interfaces')
            self.assertEqual(sdk['version'], '10.0.26100.0')
            self.assertEqual(sdk['imports'], [])
            self.assertIn('not a DLL version', sdk['versionContext'])

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
                         b"tbd-version: 4\ninstall-name: '/usr/lib/libSystem.B.dylib'\ncurrent-version: 1351.0.1\n")
            result = runtime.collect(root / 'binary', 'x86_64-apple-darwin', root, root / 'providers.json')
            component = next(c for c in result['components'] if c['delivery'] == 'external')
            self.assertEqual(component['version'], '1351.0.1')
            self.assertIn('link-interface', component['versionContext'])

    def test_native_cargo_asset_requires_matching_registry_file_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'registry/src/index/example-1.0'
            root.mkdir(parents=True)
            native = root / 'native.a'
            native.write_bytes(b'packaged native asset')
            (root / 'Cargo.toml').write_text('[package]\nname="example"\nversion="1.0"\n')
            expected = hashlib.sha256(native.read_bytes()).hexdigest()
            (root / '.cargo-checksum.json').write_text(json.dumps({'package': 'f' * 64, 'files': {'native.a': expected}}))
            result = runtime.cargo_native_input(native, native)
            self.assertEqual(result['package'], 'example')
            native.write_bytes(b'modified after unpacking')
            with self.assertRaisesRegex(runtime.EvidenceError, 'registry checksum'):
                runtime.cargo_native_input(native, native)

    def test_mingw_banner_retains_snapshot_identity_and_upstream_notices(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = bytearray(pe())
            struct.pack_into('<II', image, 152 + 112 + 8, 0, 0)
            struct.pack_into('<II', image, 152 + 112 + 13 * 8, 0, 0)
            banner = b'MinGW-W64 Runtime 13.0.0 (alpha - rev. 0) 0000-00-00\0'
            self.capture(root, image, 'x86_64-pc-windows-gnu', '/mingw/lib/libmingw32.a', banner)
            result = runtime.collect(root / 'binary', 'x86_64-pc-windows-gnu', root, root / 'providers.json')
            component = next(c for c in result['components'] if c['name'] == 'MinGW-w64 runtime')
            self.assertEqual(component['version'], banner.removeprefix(b'MinGW-W64 Runtime ').rstrip(b'\0').decode())
            self.assertIn('Copyright', component['licenseText'])
            self.assertIn('text', sbom.runtime_licenses(component)[0]['license'])

    def test_macos_metadata_change_keeps_link_binding_but_code_change_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = macho_with_sections()
            self.capture(root, original, 'x86_64-apple-darwin', '/SDK/libExample.tbd',
                         b"tbd-version: 4\ninstall-name: '/usr/lib/libExample.dylib'\n")
            final = root / 'final'
            changed = bytearray(original)
            changed[192:200] = b'DEBUG123'
            final.write_bytes(changed)
            result = runtime.collect(final, 'x86_64-apple-darwin', root, root / 'providers.json')
            self.assertEqual(result['postLink']['finalBinarySha512'], runtime.digest(final))
            self.assertEqual(result['postLink']['linkedBinarySha512'], runtime.digest(root / 'binary'))
            changed[300] ^= 1
            final.write_bytes(changed)
            with self.assertRaisesRegex(runtime.EvidenceError, 'runtime content changed'):
                runtime.collect(final, 'x86_64-apple-darwin', root, root / 'providers.json')

    def test_msvc_uses_batch_launcher_and_normalizes_environment_keys(self):
        spec = importlib.util.spec_from_file_location('build_runtime', Path(runtime.__file__).with_name('build-with-runtime-evidence.py'))
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(helper, 'ROOT', root), patch.object(helper.subprocess, 'check_output', return_value='C:/Program Files/Visual Studio\n'), patch.object(helper, 'run') as activate, patch.object(helper.shutil, 'which', return_value='C:/VC/link.exe'):
                activate.return_value.stdout = 'Path=C:/VC/bin\nLIB=C:/VC/lib\n'
                environment = {'PATH': 'old'}
                self.assertEqual(helper.msvc_environment(environment), 'C:/VC/link.exe')
                self.assertEqual(environment['PATH'], 'C:/VC/bin')
                self.assertNotIn('Path', environment)
                self.assertIn('call "C:/Program Files/Visual Studio/', (root / '.sbom-tools/msvc-environment.cmd').read_text())

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

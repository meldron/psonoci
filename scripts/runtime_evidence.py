#!/usr/bin/env python3
"""Collect hash-bound runtime identities from the final link and executable.

Uses only the Python standard library. Never executes the target executable.
Unknown providers are errors; provider overrides identify specific input hashes.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import functools
import json
import os
import posixpath
import re
import struct
import subprocess
import sys
import tarfile

if sys.version_info < (3, 11):
    raise SystemExit('psonoci SBOM tooling requires Python 3.11 or newer')
import tomllib
from pathlib import Path
from urllib.parse import quote

RUST_RUNTIME_TARGETS = frozenset({
    'x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl',
    'armv7-unknown-linux-musleabihf', 'armv7-unknown-linux-gnueabihf',
    'x86_64-apple-darwin', 'aarch64-apple-darwin',
    'x86_64-pc-windows-gnu', 'x86_64-pc-windows-msvc',
})


def pinned_tools() -> dict[str, str]:
    path = Path(__file__).resolve().parents[1] / 'sbom/tool-versions.env'
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if line and not line.startswith('#'))

class EvidenceError(RuntimeError):
    pass


def native_cpe(name: str, version: str) -> str | None:
    # Reviewed NVD product names (CVE-2025-26519 and OpenSSL's NVD product).
    # Do not infer identifiers for GCC/Rust distributions or build-host DLLs.
    products = {'musl': ('musl-libc', 'musl'), 'openssl': ('openssl', 'openssl')}
    if name.lower() not in products:
        return None
    if not re.fullmatch(r'\d+(?:\.\d+)+(?:[a-z])?', version):
        raise EvidenceError('reviewed native CPE requires an upstream release version')
    vendor, product = products[name.lower()]
    return f'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'


def toolchain_sources(release: str, commit: str) -> tuple[dict, Path]:
    if not re.fullmatch(r'\d+\.\d+\.\d+', release):
        raise EvidenceError('Rust toolchain license sources require a reviewed release')
    root = Path(__file__).resolve().parents[1] / 'sbom/toolchain-sources' / release
    try:
        record = json.loads((root / 'provenance.json').read_text())
    except FileNotFoundError as error:
        raise EvidenceError(f'Rust {release}: review bundled toolchain license sources first') from error
    if (record.get('format'), record.get('rustRelease'), record.get('rustCommit')) != (1, release, commit):
        raise EvidenceError('reviewed toolchain source identity differs from captured Rust')
    for name, source in record['files'].items():
        if Path(name).name != name or hashlib.sha256((root / name).read_bytes()).hexdigest() != source['sha256']:
            raise EvidenceError('reviewed toolchain source checksum mismatch')
    return record, root


def vendored_openssl_source(*, verify_checkout=False):
    root = Path(__file__).resolve().parents[1] / 'vendor/openssl-src'
    record = json.loads((root / 'upstream.json').read_text())
    source = record['openssl']
    package = tomllib.loads((root / 'Cargo.toml').read_text())['package']
    if record.get('format') != 1 or package['version'].split('+')[-1] != source['version']:
        raise EvidenceError('vendored OpenSSL source and Cargo package version differ')
    for name, expected in record['adapter']['files'].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise EvidenceError('vendored OpenSSL build adapter differs from reviewed upstream source')
    if verify_checkout:
        checkout = root / 'openssl'
        if not (checkout / 'VERSION.dat').is_file():
            raise EvidenceError('initialize OpenSSL source: git submodule update --init --depth 1 vendor/openssl-src/openssl')
        observed = dict(line.split('=', 1) for line in (checkout / 'VERSION.dat').read_text().splitlines()
                        if '=' in line and not line.startswith('#'))
        version = '.'.join(observed[key] for key in ('MAJOR', 'MINOR', 'PATCH'))
        commit = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
        dirty = subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain',
                                         '--untracked-files=all', '--ignore-submodules=all'], text=True)
        if version != source['version'] or commit != source['commit'] or dirty:
            raise EvidenceError('OpenSSL source checkout must match the clean, pinned official release')
    return dict(source, adapterCommit=record['adapter']['commit'],
                adapterFilesSha256=record['adapter']['files'])


def toolchain_runtime(kind: str, release: str, commit: str) -> dict:
    record, root = toolchain_sources(release, commit)
    if kind == 'compiler-builtins':
        package = tomllib.loads((root / 'compiler-builtins.Cargo.toml').read_text())['package']
        item = identity('Rust compiler builtins', release, package['repository'], package['license'])
        item['source'] = record['files']['compiler-builtins.Cargo.toml']['url']
        item['versionContext'] = f"Rust distribution release; in-tree compiler_builtins declares {package['version']}; no registry-byte equivalence asserted"
    elif kind == 'unwind':
        item = identity('Rust LLVM unwind runtime', release, 'https://llvm.org/', 'LicenseRef-LLVM-libunwind')
        item['licenseText'] = (root / 'libunwind.LICENSE.txt').read_text()
        item['source'] = record['files']['libunwind.LICENSE.txt']['url']
        item['versionContext'] = 'Rust target distribution release; in-tree LLVM libunwind source and complete license notice are recorded'
    elif kind == 'startup':
        licenses = set()
        for name in ('crtbegin.c', 'crtend.c'):
            match = re.search(r'SPDX-License-Identifier:\s*([^\r\n]+)', (root / name).read_text())
            if not match:
                raise EvidenceError('reviewed startup source has no license declaration')
            licenses.add(match[1].strip())
        if len(licenses) != 1:
            raise EvidenceError('startup source licenses require separate attribution')
        item = identity('Rust target startup runtime', release, 'https://llvm.org/', licenses.pop())
        item['source'] = record['crtBuildSource']
        item['versionContext'] = 'Rust target distribution release; startup objects are built from the pinned LLVM compiler-rt sources'
    else:
        raise EvidenceError('unknown reviewed toolchain runtime')
    item['licenseSource'] = record
    return item


def digest(path: Path) -> str:
    value = hashlib.sha512()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def normalized_path(value: str) -> str:
    return posixpath.normpath(value.replace('\\', '/'))


def root_object_input(entry: dict, capture: dict, sha: str) -> dict | None:
    role = entry.get('role')
    if role not in ('root-rust-object', 'rustc-symbol-object', 'auditable-metadata-object'):
        return None
    path = normalized_path(entry['path'])
    output = normalized_path(capture.get('output', ''))
    directory = posixpath.dirname(output)
    name = posixpath.basename(path)
    stem = posixpath.splitext(posixpath.basename(output))[0]
    explicit = path in {normalized_path(a) for a in capture['arguments']}
    same_directory = posixpath.dirname(path) == directory
    valid = explicit and (
        (role == 'root-rust-object' and same_directory and name.startswith(stem + '.') and name.endswith(('.rcgu.o', '.rcgu.obj')))
        or (role == 'auditable-metadata-object' and same_directory and name == 'psonoci_audit_data.o')
        or (role == 'rustc-symbol-object' and name == 'symbols.o'
            and posixpath.dirname(posixpath.dirname(path)) == directory
            and posixpath.basename(posixpath.dirname(path)).startswith('rustc')))
    if not valid:
        raise EvidenceError('root object is not a recognized explicit compiler output')
    return {'path': path, 'sha512': sha, 'role': role,
            'method': 'explicit final root-crate link object; compiler/auditable output layout verified'}


@functools.lru_cache(maxsize=16)
def registry_archive_checksums(archive: Path) -> tuple[str, dict]:
    package_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    files = {}
    with tarfile.open(archive, 'r:gz') as handle:
        for member in handle.getmembers():
            if member.isfile():
                with handle.extractfile(member) as stream:
                    files[member.name] = hashlib.sha256(stream.read()).hexdigest()
    return package_hash, files


def cargo_native_input(original: Path, copied: Path) -> dict | None:
    """Recognize packaged native assets only after checking Cargo's file checksum."""
    if '/registry/src/' not in normalized_path(str(original)) or not original.is_file():
        return None
    import tomllib
    for parent in original.parents:
        manifest = parent / 'Cargo.toml'
        checksums = parent / '.cargo-checksum.json'
        if not manifest.is_file():
            continue
        relative = original.relative_to(parent).as_posix()
        if checksums.is_file():
            record = json.loads(checksums.read_text())
            expected = record.get('files', {}).get(relative)
            package_hash = record['package']
        else:
            # New Cargo versions retain the .crate archive instead of writing
            # .cargo-checksum.json in every unpacked source directory.
            archive = parent.parents[2] / 'cache' / parent.parent.name / (parent.name + '.crate')
            if not archive.is_file():
                continue
            package_hash, files = registry_archive_checksums(archive)
            expected = files.get(parent.name + '/' + relative)
        if not expected or hashlib.sha256(copied.read_bytes()).hexdigest() != expected or digest(original) != digest(copied):
            raise EvidenceError('native Cargo asset does not match its registry checksum')
        package = tomllib.loads(manifest.read_text())['package']
        return {'sha512': digest(copied), 'package': package['name'], 'version': package['version'],
                'registryFileSha256': expected, 'registryPackageSha256': package_hash,
                'path': normalized_path(str(original)), 'method': 'Cargo registry file checksum; package identity must also exist in the runtime graph'}
    return None


def cstring(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        raise EvidenceError('binary string offset is outside the file')
    end = data.find(b'\0', offset)
    if end < 0:
        raise EvidenceError('unterminated binary string')
    return data[offset:end].decode('utf-8')


def macho_runtime_fingerprint(data: bytes) -> str:
    """Bind runtime sections, loader settings and dyld payloads across stripping.

    Rust may strip Mach-O debug/link metadata after the linker exits. Ignore
    symbol/debug/signature bookkeeping; preserve code, data and loader behavior.
    """
    if data[:4] != b'\xcf\xfa\xed\xfe':
        raise EvidenceError('post-link comparison requires a 64-bit Mach-O image')
    identity = {'header': data[4:16].hex() + data[24:32].hex(), 'segments': [], 'sections': [], 'loader': []}
    count = struct.unpack_from('<I', data, 16)[0]
    offset = 32
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, offset)
        if size < 8 or offset + size > len(data):
            raise EvidenceError('invalid Mach-O post-link load command')
        if command == 0x19:
            segment = data[offset + 8:offset + 24].split(b'\0', 1)[0].decode()
            if segment not in ('__LINKEDIT', '__DWARF'):
                identity['segments'].append([segment, data[offset + 24:offset + 64].hex()])
                sections = struct.unpack_from('<I', data, offset + 64)[0]
                for i in range(sections):
                    start = offset + 72 + i * 80
                    name = data[start:start + 16].split(b'\0', 1)[0].decode()
                    address, length, location = struct.unpack_from('<QQI', data, start + 32)
                    flags = struct.unpack_from('<I', data, start + 64)[0]
                    if flags & 0x02000000:
                        continue
                    payload = b'' if flags & 255 in (1, 0x12) else data[location:location + length]
                    identity['sections'].append([segment, name, address, length, flags, hashlib.sha512(payload).hexdigest()])
        elif command in (0x2, 0xb, 0x1b, 0x1d, 0x26, 0x29):
            pass  # Symbol tables, UUID, signature, function starts and debug data.
        elif command in (0x22, 0x80000022):
            pairs = struct.unpack_from('<' + 'I' * 10, data, offset + 8)
            identity['loader'].append([command, [hashlib.sha512(data[p:p + n]).hexdigest() for p, n in zip(pairs[::2], pairs[1::2])]])
        elif command in (0x80000033, 0x80000034):
            location, length = struct.unpack_from('<II', data, offset + 8)
            identity['loader'].append([command, hashlib.sha512(data[location:location + length]).hexdigest()])
        else:
            identity['loader'].append([command, data[offset + 8:offset + size].hex()])
        offset += size
    if not identity['sections']:
        raise EvidenceError('Mach-O comparison has no runtime sections')
    return hashlib.sha512(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def elf_runtime(data: bytes) -> tuple[list[str], str | None, str | None]:
    """Read the loader's PT_DYNAMIC data; section headers are optional in ELF."""
    if len(data) < 52 or data[:4] != b'\x7fELF' or data[5] != 1 or data[4] not in (1, 2):
        raise EvidenceError('unsupported or truncated ELF header')
    wide = data[4] == 2
    header_size, entry_size = (64, 56) if wide else (52, 32)
    if len(data) < header_size:
        raise EvidenceError('truncated ELF header')
    offset = struct.unpack_from('<Q' if wide else '<I', data, 32 if wide else 28)[0]
    size, count = struct.unpack_from('<HH', data, 54 if wide else 42)
    if count == 0xffff or (count and (not offset or size < entry_size or offset + size * count > len(data))):
        raise EvidenceError('unsupported or invalid ELF program headers')
    segments = []
    dynamic = None
    interpreter = None
    for i in range(count):
        start = offset + i * size
        kind = struct.unpack_from('<I', data, start)[0]
        if wide:
            location, address, _, length = struct.unpack_from('<QQQQ', data, start + 8)
        else:
            location, address, _, length = struct.unpack_from('<IIII', data, start + 4)
        if location + length > len(data):
            raise EvidenceError('ELF segment extends beyond the file')
        if kind == 1:
            segments.append((address, length, location))
        elif kind == 2:
            if dynamic is not None:
                raise EvidenceError('multiple ELF dynamic segments')
            dynamic = (location, length)
        elif kind == 3:
            value = data[location:location + length]
            if interpreter is not None or not value.endswith(b'\0') or b'\0' in value[:-1]:
                raise EvidenceError('invalid ELF interpreter')
            interpreter = value[:-1].decode('utf-8')
    if dynamic is None:
        # An executable with no PT_DYNAMIC is static. Relocatable objects are
        # inspected separately for musl's allocated version data.
        return [], None, interpreter
    location, length = dynamic
    stride = 16 if wide else 8
    if not length or length % stride:
        raise EvidenceError('invalid ELF dynamic segment size')
    tags = {}
    terminated = False
    for start in range(location, location + length, stride):
        tag, value = struct.unpack_from('<qQ' if wide else '<iI', data, start)
        if tag == 0:
            terminated = True
            break
        tags.setdefault(tag, []).append(value)
    if not terminated:
        raise EvidenceError('unterminated ELF dynamic segment')
    if not (tags.get(1) or tags.get(14)):
        return [], None, interpreter
    if len(tags.get(5, [])) != 1 or len(tags.get(10, [])) != 1 or len(tags.get(14, [])) > 1:
        raise EvidenceError('ELF dynamic strings have no unambiguous address/size')
    address, string_size = tags[5][0], tags[10][0]
    locations = {base + address - virtual for virtual, length, base in segments
                 if virtual <= address and address + string_size <= virtual + length}
    if len(locations) != 1 or not string_size:
        raise EvidenceError('ELF dynamic string table is outside file-backed load segments')
    base = locations.pop()
    strings = data[base:base + string_size]
    def dynamic_string(value):
        return cstring(strings, value)
    names = [dynamic_string(value) for value in tags.get(1, [])]
    soname = dynamic_string(tags[14][0]) if tags.get(14) else None
    return names, soname, interpreter


def elf_soname(data: bytes) -> str | None:
    return elf_runtime(data)[1] if data[:4] == b'\x7fELF' else None


def imports(data: bytes) -> list[dict]:
    """Read ELF DT_NEEDED, Mach-O load commands, and PE normal/delay imports."""
    result = []
    if data[:4] == b'\x7fELF':
        names, _, interpreter = elf_runtime(data)
        result.extend({'name': name} for name in names)
        if interpreter is not None:
            result.append({'name': interpreter.rsplit('/', 1)[-1], 'interpreterPath': interpreter})
    elif data[:4] == b'\xcf\xfa\xed\xfe':
        commands = struct.unpack_from('<I', data, 16)[0]
        offset = 32
        for _ in range(commands):
            command, size = struct.unpack_from('<II', data, offset)
            if size < 8 or offset + size > len(data):
                raise EvidenceError('invalid Mach-O load command')
            if command in (0xc, 0x80000018, 0x8000001f, 0x80000023):
                name_offset, _, version, compatibility = struct.unpack_from('<IIII', data, offset + 8)
                result.append({'name': cstring(data, offset + name_offset),
                               'linkInterfaceVersion': f'{version >> 16}.{(version >> 8) & 255}.{version & 255}',
                               'compatibilityVersion': f'{compatibility >> 16}.{(compatibility >> 8) & 255}.{compatibility & 255}'})
            offset += size
    elif data[:2] == b'MZ':
        pe = struct.unpack_from('<I', data, 60)[0]
        if data[pe:pe + 4] != b'PE\0\0':
            raise EvidenceError('invalid PE signature')
        count = struct.unpack_from('<H', data, pe + 6)[0]
        optional_size = struct.unpack_from('<H', data, pe + 20)[0]
        optional = pe + 24
        magic = struct.unpack_from('<H', data, optional)[0]
        if magic not in (0x10b, 0x20b):
            raise EvidenceError('unsupported PE optional header')
        directories = optional + (112 if magic == 0x20b else 96)
        sections = []
        for i in range(count):
            start = optional + optional_size + i * 40
            virtual_size, address, raw_size, raw = struct.unpack_from('<IIII', data, start + 8)
            sections.append((address, max(virtual_size, raw_size), raw))

        def rva(address):
            for start, size, raw in sections:
                if start <= address < start + size:
                    return raw + address - start
            raise EvidenceError(f'PE import RVA {address:#x} is outside the image')

        for index, record_size, name_field in ((1, 20, 12), (13, 32, 4)):
            address, length = struct.unpack_from('<II', data, directories + index * 8)
            if not address:
                continue
            start = rva(address)
            for offset in range(start, start + length, record_size):
                record = data[offset:offset + record_size]
                if not any(record):
                    break
                if index == 13 and struct.unpack_from('<I', record)[0] != 1:
                    raise EvidenceError('legacy VA-based PE delay imports need an explicit parser')
                name = struct.unpack_from('<I', record, name_field)[0]
                result.append({'name': cstring(data, rva(name)).lower()})
    else:
        raise EvidenceError('unsupported executable format for runtime dependency inspection')
    return sorted({entry['name']: entry for entry in result}.values(), key=lambda entry: entry['name'])


def ar_member(data: bytes, wanted: str) -> bytes:
    if not data.startswith(b'!<arch>\n'):
        raise EvidenceError('runtime archive is not a regular ar archive')
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset:offset + 60]
        if header[58:60] != b'`\n':
            raise EvidenceError('invalid ar member header')
        size = int(header[48:58].strip())
        name = header[:16].decode('ascii').strip().rstrip('/')
        member = data[offset + 60:offset + 60 + size]
        if name == wanted:
            return member
        offset += 60 + size + size % 2
    raise EvidenceError(f'no {wanted} version object in linked libc archive')


def import_library_names(data: bytes) -> set[str]:
    """Identify COFF import descriptors, not arbitrary DLL-looking strings."""
    if not data.startswith(b'!<arch>\n'):
        return set()
    names = set()
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset:offset + 60]
        size = int(header[48:58].strip())
        member = data[offset + 60:offset + 60 + size]
        if member[:4] == b'\0\0\xff\xff' and len(member) >= 20:
            strings = member[20:].split(b'\0')
            if len(strings) >= 2 and re.fullmatch(rb'[A-Za-z0-9_.-]+\.(?:dll|drv)', strings[1], re.I):
                names.add(strings[1].decode().lower())
        elif len(member) >= 20 and member[:2] in (b'\x64\x86', b'\x4c\x01'):
            count = struct.unpack_from('<H', member, 2)[0]
            optional = struct.unpack_from('<H', member, 16)[0]
            for i in range(count):
                start = 20 + optional + i * 40
                if start + 40 > len(member):
                    break
                if member[start:start + 8] == b'.idata$7':
                    length, location = struct.unpack_from('<II', member, start + 16)
                    value = member[location:location + length].rstrip(b'\0')
                    if re.fullmatch(rb'[A-Za-z0-9_.-]+\.(?:dll|drv)', value, re.I):
                        names.add(value.decode().lower())
        offset += 60 + size + size % 2
    return names


def musl_version(data: bytes) -> str:
    member = ar_member(data, 'version.lo')
    # Read the actual allocated bytes of __libc_version, not arbitrary debug strings.
    if member[:4] != b'\x7fELF' or member[5] != 1:
        raise EvidenceError('unsupported musl version object')
    wide = member[4] == 2
    offset = struct.unpack_from('<Q' if wide else '<I', member, 40 if wide else 32)[0]
    size, count, _ = struct.unpack_from('<HHH', member, 58 if wide else 46)
    versions = set()
    for i in range(count):
        start = offset + i * size
        flags = struct.unpack_from('<Q' if wide else '<I', member, start + 8)[0]
        location, length = struct.unpack_from('<QQ' if wide else '<II', member, start + (24 if wide else 16))
        if flags & 2:
            versions.update(v.decode() for v in re.findall(rb'(?<![\d.])(\d+\.\d+\.\d+)\x00', member[location:location + length]))
    if len(versions) != 1:
        raise EvidenceError('linked musl version object does not identify one exact version')
    return versions.pop()


def identity(name, version, creator, license_id=None):
    item = {'name': name, 'version': version, 'creator': creator,
            'purl': f'pkg:generic/{quote(name.lower(), safe=".-_")}@{quote(version, safe=".-_+")}',
            'evidence': [], 'imports': []}
    if license_id:
        item['license'] = license_id
    if cpe := native_cpe(name, version):
        item['cpe'] = cpe
    return item


def validate_evidence(document: dict, binary_hash: str, target: str, required_imports: list[dict]) -> None:
    if document.get('format') != 1 or document.get('target') != target or document.get('binarySha512') != binary_hash:
        raise EvidenceError('runtime evidence does not match the executable and target')
    if document.get('imports') != required_imports:
        raise EvidenceError('runtime evidence import list does not match the executable')
    rust_release = re.search(r'^release: (\S+)$', document.get('rustc', ''), re.M)
    rust_commit = re.search(r'^commit-hash: [0-9a-f]{40}$', document.get('rustc', ''), re.M)
    if not rust_release or not rust_commit:
        raise EvidenceError('runtime evidence must identify the Rust release and source commit')
    inputs = document.get('inputs', [])
    if not inputs or any(not re.fullmatch(r'[0-9a-f]{128}', item.get('sha512', '')) for item in inputs):
        raise EvidenceError('runtime evidence requires SHA-512 identities for link inputs')
    inventory = {i['sha512'] for i in inputs}
    covered = set(document.get('cargoInputHashes', []))
    for item in document.get('rootObjectInputs', []):
        if item.get('role') not in ('root-rust-object', 'rustc-symbol-object', 'auditable-metadata-object') or not item.get('method'):
            raise EvidenceError('root object ownership evidence is missing')
        covered.add(item['sha512'])
    for item in document.get('cargoNativeInputs', []):
        if not item.get('package') or not item.get('version') or not all(re.fullmatch(r'[0-9a-f]{64}', item.get(field, '')) for field in ('registryFileSha256', 'registryPackageSha256')):
            raise EvidenceError('native Cargo input lacks registry identity evidence')
        covered.add(item['sha512'])
    mapped_imports = []
    components = document.get('components', [])
    keys = []
    for item in components:
        if not all(isinstance(item.get(field), str) and item[field].strip() for field in ('name', 'version', 'creator', 'purl')):
            raise EvidenceError('runtime component lacks an exact identity')
        if item['version'].lower() in ('unknown', 'unspecified', '*'):
            raise EvidenceError('runtime component version is unresolved')
        if item['name'] in ('Rust standard library', 'Rust target startup runtime', 'Rust compiler builtins', 'Rust LLVM unwind runtime') and item['version'] != rust_release[1]:
            raise EvidenceError('runtime component version differs from the captured Rust release')
        if item.get('delivery') not in ('bundled', 'external'):
            raise EvidenceError('runtime component delivery boundary is required')
        if expected_cpe := native_cpe(item['name'], item['version']):
            if item.get('cpe') != expected_cpe:
                raise EvidenceError('native advisory identity differs from reviewed mapping')
        if item.get('dependencyGraph') not in (None, 'unknown', 'incomplete', 'complete'):
            raise EvidenceError('invalid runtime dependency graph knowledge')
        if item['delivery'] == 'bundled' and not item.get('license'):
            raise EvidenceError('bundled runtime component requires license metadata')
        if not item.get('evidence'):
            raise EvidenceError('runtime component requires identity evidence')
        kinds = {'Rust compiler builtins': 'compiler-builtins', 'Rust LLVM unwind runtime': 'unwind',
                 'Rust target startup runtime': 'startup'}
        if item['name'] in kinds:
            expected = toolchain_runtime(kinds[item['name']], rust_release[1], rust_commit[0].split(': ', 1)[1])
            for field in ('license', 'licenseText', 'licenseSource'):
                if item.get(field) != expected.get(field):
                    raise EvidenceError('toolchain runtime licensing differs from reviewed source')
        for proof in item['evidence']:
            if not re.fullmatch(r'[0-9a-f]{128}', proof.get('sha512', '')) or not proof.get('method'):
                raise EvidenceError('runtime component evidence lacks a hash or identification method')
            covered.add(proof['sha512'])
        mapped_imports.extend(item.get('imports', []))
        keys.append(item['purl'])
    if len(keys) != len(set(keys)):
        raise EvidenceError('duplicate runtime component identities')
    if inventory - covered or covered - inventory:
        raise EvidenceError('runtime link input coverage is incomplete or contains unrecorded inputs')
    if sorted(mapped_imports) != sorted(i['name'] for i in required_imports):
        raise EvidenceError('each executable import must map to exactly one runtime component')
    if not any(c['name'] == 'Rust standard library' and c['delivery'] == 'bundled' for c in components):
        raise EvidenceError('runtime evidence omits the linked Rust standard library')
    if 'musl' in target and not any(c['name'] == 'musl' and c['delivery'] == 'bundled' for c in components):
        raise EvidenceError('runtime evidence omits the linked musl libc')
    registry_components = [c for c in components if c.get('origin') == 'rust-std-registry']
    if registry_components:
        provenance = document.get('rustStdRegistry', {})
        commit = rust_commit[0].split(': ', 1)[1]
        if (provenance.get('format') != 1 or provenance.get('rustCommit') != commit
                or provenance.get('rustRelease') != rust_release[1]
                or not re.fullmatch(r'[0-9a-f]{64}', provenance.get('lockSha256', ''))
                or provenance.get('lockUrl') != f'https://raw.githubusercontent.com/rust-lang/rust/{commit}/library/Cargo.lock'
                or provenance.get('tool') != {'name': 'psonoci-rust-runtime-enricher', 'version': '1.1.0'}):
            raise EvidenceError('Rust runtime registry provenance differs from captured toolchain')
        records = provenance.get('packages', [])
        if len(records) != sum(len(c['evidence']) for c in registry_components):
            raise EvidenceError('Rust runtime registry proof inventory is incomplete')
        for item in registry_components:
            if item['purl'] != f"pkg:cargo/{quote(item['name'], safe='.-_')}@{quote(item['version'], safe='.-_+')}":
                raise EvidenceError('Rust registry runtime requires its canonical Cargo identity')
            parent = next((c for c in components if c['purl'] == item.get('parentPurl')), None)
            if not parent or parent['name'] != 'Rust standard library':
                raise EvidenceError('Rust registry runtime must identify its standard-library parent')
            if set(item.get('dependsOn', [])) - set(keys):
                raise EvidenceError('Rust runtime dependency evidence has dangling references')
            for proof in item['evidence']:
                matching = [r for r in records if r.get('purl') == item['purl'] and r.get('archiveSha512') == proof['sha512']]
                if (len(matching) != 1
                        or matching[0].get('archive') != Path(normalized_path(proof['path'])).name
                        or not re.fullmatch(r'[0-9a-f]{64}', proof.get('registryPackageSha256', ''))):
                    raise EvidenceError('Rust registry package checksum proof is missing')
                if (proof.get('rustCommit') != commit
                        or proof.get('libraryLockSha256') != provenance['lockSha256']
                        or matching[0].get('registryPackageSha256') != proof['registryPackageSha256']):
                    raise EvidenceError('Rust registry package checksum proof differs from source provenance')


def collect(binary: Path, target: str, directory: Path, provider_path: Path) -> dict:
    capture = json.loads((directory / 'capture.json').read_text())
    binary_hash = digest(binary)
    if capture.get('format') != 1 or capture.get('target') != target:
        raise EvidenceError('link capture belongs to a different executable or target')
    linked_hash = digest(directory / 'binary')
    post_link = None
    if linked_hash != binary_hash:
        if 'apple' not in target:
            raise EvidenceError('link capture belongs to a different executable or target')
        original_fingerprint = macho_runtime_fingerprint((directory / 'binary').read_bytes())
        if original_fingerprint != macho_runtime_fingerprint(binary.read_bytes()):
            raise EvidenceError('Mach-O runtime content changed after the captured link')
        post_link = {'linkedBinarySha512': linked_hash, 'finalBinarySha512': binary_hash,
                     'runtimeSectionsSha512': original_fingerprint,
                     'method': 'Mach-O runtime sections, loader commands and dyld payloads match across post-link metadata processing'}
    release = re.search(r'^release: (\S+)$', capture['rustc'], re.M)
    commit = re.search(r'^commit-hash: ([0-9a-f]{40})$', capture['rustc'], re.M)
    if not release or not commit:
        raise EvidenceError('link capture does not identify the exact Rust toolchain')
    providers = json.loads(provider_path.read_text())
    if providers.get('format') != 1:
        raise EvidenceError('unsupported runtime provider metadata format')
    registry = providers.get('bySha512', {})
    components = {}
    inputs = []
    cargo_hashes = []
    cargo_native = []
    root_objects = []
    unknown = []
    gcc = capture.get('compiler') or {}
    gcc_hashes = {digest(directory / file) for file in gcc.get('files', [])}
    copied = [(entry, directory / entry['copy']) for entry in capture['inputs']]
    glibc_versions = set()
    for entry, file in copied:
        if Path(entry['path']).name == 'libc.so.6':
            glibc_versions.update(v.decode() for v in re.findall(rb'stable release version (\d+\.\d+(?:\.\d+)?)', file.read_bytes()))
    imported = imports(binary.read_bytes())
    musl_archives = [file for entry, file in copied if Path(entry['path']).name == 'libc.a']
    linked_musl = musl_version(musl_archives[0].read_bytes()) if 'musl' in target and len(musl_archives) == 1 else None
    mingw = []
    for entry, file in copied:
        if Path(normalized_path(entry['path'])).name == 'libmingw32.a':
            banners = re.findall(rb'MinGW-W64 Runtime ([ -~]+)\x00', file.read_bytes())
            if len(set(banners)) == 1:
                mingw.append((str(Path(normalized_path(entry['path'])).parent), banners[0].decode()))

    def register(component, proof, delivery='bundled', imported_names=()):
        component['delivery'] = delivery
        component.setdefault('dependencyGraph', 'unknown')
        existing = components.setdefault(component['purl'], component)
        if existing['delivery'] != delivery:
            raise EvidenceError('one runtime identity crosses delivery boundaries')
        existing['evidence'].append(proof)
        existing['imports'].extend(name for name in imported_names if name not in existing['imports'])

    for entry, file in copied:
        path = normalized_path(entry['path'])
        name = Path(path).name
        sha = digest(file)
        inputs.append({'path': path, 'sha512': sha})
        proof = {'path': path, 'sha512': sha, 'method': ''}
        if root_object := root_object_input(entry, capture, sha):
            root_objects.append(root_object)
        elif sha in registry:
            provider = registry[sha]
            if not provider.get('source') or not provider.get('method'):
                raise EvidenceError('provider override requires an identity source and method')
            component = identity(provider['name'], provider['version'], provider['creator'], provider.get('license'))
            component['source'] = provider['source']
            proof['method'] = provider['method']
            register(component, proof, provider.get('delivery', 'bundled'), provider.get('imports', []))
        elif name == 'libc.a' and 'musl' in target:
            component = identity('musl', musl_version(file.read_bytes()), 'https://musl.libc.org/', 'MIT')
            proof['method'] = 'linked libc.a allocated version.lo data'
            register(component, proof)
        elif 'musl' in target and linked_musl and '/rustlib/' in path and re.fullmatch(r'(?:S?crt\d*|rcrt\d*|crti|crtn)\.o', name):
            component = identity('musl', linked_musl, 'https://musl.libc.org/', 'MIT')
            proof['method'] = 'musl startup object beside the linked, versioned libc.a in the target sysroot'
            register(component, proof)
        elif '/rustlib/' in path and re.fullmatch(r'crt(?:begin|end)\w*\.o', name):
            component = toolchain_runtime('startup', release[1], commit[1])
            proof['method'] = 'startup object delivered in the exact Rust target distribution, bound by input hash'
            register(component, proof)
        elif '/rustlib/' in path and re.fullmatch(r'libcompiler_builtins-[0-9a-f]+\.rlib', name):
            component = toolchain_runtime('compiler-builtins', release[1], commit[1])
            proof['method'] = 'linked compiler-builtins sysroot archive; reviewed exact-commit in-tree manifest license'
            register(component, proof)
        elif '/rustlib/' in path and name == 'libunwind.a':
            component = toolchain_runtime('unwind', release[1], commit[1])
            proof['method'] = 'linked native unwind archive in the Rust distribution; pinned bootstrap recipe and complete LLVM libunwind license'
            register(component, proof)
        elif '/rustlib/' in path and (name.endswith('.rlib') or name in ('libunwind.a',)):
            component = identity('Rust standard library', release[1], 'https://www.rust-lang.org/', 'MIT OR Apache-2.0')
            component['source'] = f'https://github.com/rust-lang/rust/tree/{commit[1]}/library'
            proof['method'] = 'linked Rust sysroot runtime input; captured rustc release and source commit'
            register(component, proof)
        elif name.endswith('.rlib') and '/release/deps/' in path:
            cargo_hashes.append(sha)
        elif name.endswith('.a') and (native_input := cargo_native_input(Path(entry['path']), file)):
            cargo_native.append(native_input)
        elif len(mingw) == 1 and str(Path(path).parent) == mingw[0][0] and name in ('crt2.o', 'dllcrt2.o', 'libmingw32.a', 'libmingwex.a', 'libpthread.a', 'libwinpthread.a', 'libdbghelp.a'):
            if not mingw[0][1].startswith('13.'):
                raise EvidenceError('this MinGW runtime version needs its upstream license notice reviewed')
            component = identity('MinGW-w64 runtime', mingw[0][1], 'https://www.mingw-w64.org/', 'LicenseRef-MinGW-w64-runtime')
            component['source'] = 'https://github.com/mingw-w64/mingw-w64'
            component['licenseText'] = (Path(__file__).resolve().parents[1] / 'sbom/licenses/mingw-w64-runtime-13.txt').read_text()
            component['versionContext'] = 'MinGW-w64 distribution runtime banner, including snapshot qualifier; exact linked library inputs are hashed'
            proof['method'] = 'linked libmingw32.a runtime banner; native input supplied by the same target runtime directory'
            register(component, proof)
        elif name.endswith('.lib') and (package_version := re.search(r'/VC/Tools/MSVC/(\d+\.\d+\.\d+)/', path, re.I)) and not import_library_names(file.read_bytes()):
            component = identity('Microsoft VC static runtime', package_version[1], 'https://visualstudio.microsoft.com/', 'LicenseRef-Microsoft-Visual-Studio')
            component['source'] = 'https://visualstudio.microsoft.com/license-terms/'
            component['versionContext'] = 'installed VC tools package version; exact linked inputs are hashed'
            proof['method'] = 'resolved static library in versioned MSVC package'
            register(component, proof)
        elif re.fullmatch(r'lib(?:c|m|mvec|pthread|rt|dl|util|resolv)\.so(?:\.[\d.]+)?|ld-linux[^/]*\.so(?:\.[\d.]+)?|lib(?:c_nonshared|pthread_nonshared|pthread|dl|rt|m|util)\.a|(?:S?crt\d*|crti|crtn)\.o', name) and len(glibc_versions) == 1:
            component = identity('glibc', next(iter(glibc_versions)), 'https://www.gnu.org/software/libc/', 'LGPL-2.1-or-later')
            proof['method'] = 'resolved linker input and linked libc.so.6 release banner'
            soname = elf_soname(file.read_bytes())
            matches = [i['name'] for i in imported if Path(i['name']).name in (name, soname)]
            bundled = name.endswith(('.o', '.a'))
            component['purl'] += '?linkage=' + ('static' if bundled else 'dynamic')
            register(component, proof, 'bundled' if bundled else 'external', matches)
        elif sha in gcc_hashes and re.fullmatch(r'\d+(?:\.\d+){1,2}', gcc.get('version', '')):
            component = identity('GCC runtime', gcc['version'], 'https://gcc.gnu.org/', 'GPL-3.0-or-later WITH GCC-exception-3.1')
            proof['method'] = 'input hash matches GCC -print-file-name runtime; GCC -dumpfullversion'
            soname = elf_soname(file.read_bytes())
            matches = [i['name'] for i in imported if Path(i['name']).name in (name, soname)]
            bundled = name.endswith(('.o', '.a'))
            component['versionContext'] = 'GCC distribution version; exact runtime inputs verified against compiler-owned files'
            component['purl'] += '?linkage=' + ('static' if bundled else 'dynamic')
            register(component, proof, 'bundled' if bundled else 'external', matches)
        else:
            unknown.append({'path': path, 'sha512': sha})

    mapped = {name for component in components.values() for name in component['imports']}
    # A native Windows runner can identify the actual DLLs used on that build
    # host. This is recorded as build-host evidence, never a minimum OS version.
    if sys.platform == 'win32':
        for imported_item in imported:
            name = imported_item['name']
            if name in mapped:
                continue
            if not re.fullmatch(r'[a-z0-9_.-]+\.(?:dll|drv)', name):
                raise EvidenceError('Windows runtime import is not a simple DLL name')
            environment = dict(os.environ, PSONOCI_DLL_NAME=name)
            script = r'''$n=$env:PSONOCI_DLL_NAME; $h=[IntPtr]::Zero
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class NativeRuntime { [DllImport("kernel32", CharSet=CharSet.Unicode)] public static extern IntPtr LoadLibraryEx(string n, IntPtr f, uint flags); [DllImport("kernel32", CharSet=CharSet.Unicode)] public static extern uint GetModuleFileName(IntPtr h, System.Text.StringBuilder s, uint n); [DllImport("kernel32")] public static extern bool FreeLibrary(IntPtr h); }'
$h=[NativeRuntime]::LoadLibraryEx($n,[IntPtr]::Zero,0x801)
if ($h -eq [IntPtr]::Zero) { throw "Cannot resolve runtime $n" }
try { $s=New-Object System.Text.StringBuilder 32768; if ([NativeRuntime]::GetModuleFileName($h,$s,32768) -eq 0) { throw 'No module path' }; $p=$s.ToString(); $v=[Diagnostics.FileVersionInfo]::GetVersionInfo($p); @{path=$p;version=$v.FileVersion;company=$v.CompanyName} | ConvertTo-Json -Compress } finally { [void][NativeRuntime]::FreeLibrary($h) }'''
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], env=environment, capture_output=True, text=True, check=True)
            observed = json.loads(result.stdout)
            if not observed['version'] or 'Microsoft' not in (observed['company'] or ''):
                raise EvidenceError(f'{name}: DLL identity needs explicit provider metadata')
            sha = digest(Path(observed['path']))
            inputs.append({'path': observed['path'], 'sha512': sha})
            component = identity(name, observed['version'], 'https://www.microsoft.com/')
            component['versionContext'] = 'observed on build host; not a minimum deployment version'
            register(component, {'path': observed['path'], 'sha512': sha, 'method': 'Windows loader resolution and DLL file-version resource on build host'}, 'external', [name])
            for unresolved in list(unknown):
                original = next(file for entry, file in copied if normalized_path(entry['path']) == unresolved['path'])
                if name in import_library_names(original.read_bytes()):
                    register(component, dict(unresolved, method='COFF import descriptor in the linked import library'), 'external', [name])
        # One import library can supply several DLL imports. Record every
        # selected relationship before removing the library from unresolved inputs.
        covered_hashes = {proof['sha512'] for component in components.values() for proof in component['evidence']}
        unknown = [item for item in unknown if item['sha512'] not in covered_hashes]

        # SDK libraries can be searched without providing an executable import.
        # Preserve their package provenance as interfaces, without inventing a
        # runtime DLL version or adding an import absent from the executable.
        for candidate in list(unknown):
            package = re.search(r'/Windows Kits/10/lib/(\d+\.\d+\.\d+\.\d+)/', candidate['path'], re.I)
            file = next(file for entry, file in copied if normalized_path(entry['path']) == candidate['path'])
            if not package or not import_library_names(file.read_bytes()):
                continue
            component = identity('Microsoft Windows SDK import interfaces', package[1], 'https://developer.microsoft.com/windows/')
            component['versionContext'] = 'installed SDK package version for searched import libraries; not a DLL version or deployment requirement'
            register(component, dict(candidate, method='COFF import library resolved inside a versioned Windows SDK package'), 'external')
            unknown.remove(candidate)

    # Preserve SDK interface identities for all stubs consumed by the linker,
    # including reexports that do not become direct executable load commands.
    if 'apple' in target:
        for candidate in list(unknown):
            if Path(candidate['path']).suffix != '.tbd':
                continue
            file = next(file for entry, file in copied if normalized_path(entry['path']) == candidate['path'])
            text = file.read_text()
            name_match = re.search(r'^install-name:\s*[\'"]?([^\'"\n]+)', text, re.M)
            version_match = re.search(r'^current-version:\s*([\d.]+)\s*$', text, re.M)
            if not name_match or (not version_match and not re.search(r'^tbd-version:\s*4\s*$', text, re.M)):
                raise EvidenceError(f'{candidate["path"]}: SDK stub needs an explicit interface identity')
            name = name_match[1].strip()
            if not name.startswith(('/usr/lib/', '/System/Library/Frameworks/')):
                raise EvidenceError(f'{name}: non-system macOS runtime requires explicit provider metadata')
            # TBD v4 defines an omitted current-version as 1.0, not unknown.
            # llvm/lib/TextAPI/TextStub.cpp documents and implements this default.
            version = '.'.join(((version_match[1] if version_match else '1.0').split('.') + ['0', '0'])[:3])
            direct = next((item for item in imported if item['name'] == name), None)
            if direct:
                version = direct['linkInterfaceVersion']
            component = identity(name, version, 'https://developer.apple.com/')
            component['versionContext'] = 'SDK link-interface current-version (Mach-O command for direct imports); not an OS or upstream source version'
            matches = [item['name'] for item in imported if item['name'] == name]
            register(component, dict(candidate, method='linked SDK stub install-name and current-version'), 'external', matches)
            unknown.remove(candidate)

    if unknown:
        (directory / 'unresolved-inputs.json').write_text(json.dumps(unknown, indent=2) + '\n')
        raise EvidenceError(f'{len(unknown)} unresolved native link inputs; review {directory}/unresolved-inputs.json and add hash-bound provider metadata')
    document = {'format': 1, 'target': target, 'binarySha512': binary_hash,
                'capturedAt': dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z'),
                'rustc': capture['rustc'], 'builderImage': capture['builderImage'],
                'imports': imported, 'inputs': inputs, 'cargoInputHashes': cargo_hashes, 'cargoNativeInputs': cargo_native,
                'rootObjectInputs': root_objects,
                'components': sorted(components.values(), key=lambda item: item['purl'])}
    if 'buildPolicy' in capture:
        document['buildPolicy'] = capture['buildPolicy']
    if 'cargoAuditableVersion' in capture:
        document['cargoAuditableVersion'] = capture['cargoAuditableVersion']
    if capture.get('opensslSource') is not None:
        document['opensslSource'] = capture['opensslSource']
    if post_link:
        document['postLink'] = post_link
    validate_evidence(document, binary_hash, target, imported)
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--target', required=True)
    parser.add_argument('--capture', required=True, type=Path)
    parser.add_argument('--providers', type=Path, default=Path(__file__).resolve().parents[1] / 'sbom/runtime-providers.json')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = collect(args.binary, args.target, args.capture, args.providers)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    except (EvidenceError, ValueError, KeyError, OSError, struct.error, subprocess.CalledProcessError) as error:
        parser.exit(1, f'runtime evidence: {error}\n')


if __name__ == '__main__':
    main()

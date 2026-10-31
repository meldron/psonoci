#!/usr/bin/env python3
"""Collect hash-bound runtime identities from the final link and executable.

Uses only the Python standard library. Never executes the target executable.
Unknown providers are errors; provider overrides identify specific input hashes.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote


class EvidenceError(RuntimeError):
    pass


def digest(path: Path) -> str:
    value = hashlib.sha512()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def cstring(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        raise EvidenceError('binary string offset is outside the file')
    end = data.find(b'\0', offset)
    if end < 0:
        raise EvidenceError('unterminated binary string')
    return data[offset:end].decode('utf-8')


def imports(data: bytes) -> list[dict]:
    """Read ELF DT_NEEDED, Mach-O load commands, and PE normal/delay imports."""
    result = []
    if data[:4] == b'\x7fELF':
        if data[5] != 1 or data[4] not in (1, 2):
            raise EvidenceError('unsupported ELF byte order or class')
        wide = data[4] == 2
        offset = struct.unpack_from('<Q' if wide else '<I', data, 40 if wide else 32)[0]
        size, count, _ = struct.unpack_from('<HHH', data, 58 if wide else 46)
        sections = []
        for i in range(count):
            start = offset + i * size
            kind = struct.unpack_from('<I', data, start + 4)[0]
            location, length = struct.unpack_from('<QQ' if wide else '<II', data, start + (24 if wide else 16))
            link = struct.unpack_from('<I', data, start + (40 if wide else 24))[0]
            sections.append((kind, location, length, link))
        for kind, location, length, link in sections:
            if kind == 6:
                strings = sections[link][1]
                for entry in range(location, location + length, 16 if wide else 8):
                    tag, value = struct.unpack_from('<QQ' if wide else '<II', data, entry)
                    if tag == 1:
                        result.append({'name': cstring(data, strings + value)})
        program_offset = struct.unpack_from('<Q' if wide else '<I', data, 32 if wide else 28)[0]
        program_size, program_count = struct.unpack_from('<HH', data, 54 if wide else 42)
        for i in range(program_count):
            start = program_offset + i * program_size
            if struct.unpack_from('<I', data, start)[0] == 3:
                location = struct.unpack_from('<Q' if wide else '<I', data, start + (8 if wide else 4))[0]
                interpreter = cstring(data, location)
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
            if len(strings) >= 2 and re.fullmatch(rb'[A-Za-z0-9_.-]+\.dll', strings[1], re.I):
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
                    if re.fullmatch(rb'[A-Za-z0-9_.-]+\.dll', value, re.I):
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
    mapped_imports = []
    components = document.get('components', [])
    keys = []
    for item in components:
        if not all(isinstance(item.get(field), str) and item[field].strip() for field in ('name', 'version', 'creator', 'purl')):
            raise EvidenceError('runtime component lacks an exact identity')
        if item['version'].lower() in ('unknown', 'unspecified', '*'):
            raise EvidenceError('runtime component version is unresolved')
        if item['name'] in ('Rust standard library', 'Rust target startup runtime') and item['version'] != rust_release[1]:
            raise EvidenceError('runtime component version differs from the captured Rust release')
        if item.get('delivery') not in ('bundled', 'external'):
            raise EvidenceError('runtime component delivery boundary is required')
        if item['delivery'] == 'bundled' and not item.get('license'):
            raise EvidenceError('bundled runtime component requires license metadata')
        if not item.get('evidence'):
            raise EvidenceError('runtime component requires identity evidence')
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


def collect(binary: Path, target: str, directory: Path, provider_path: Path) -> dict:
    capture = json.loads((directory / 'capture.json').read_text())
    binary_hash = digest(binary)
    if capture.get('format') != 1 or capture.get('target') != target or digest(directory / 'binary') != binary_hash:
        raise EvidenceError('link capture belongs to a different executable or target')
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

    def register(component, proof, delivery='bundled', imported_names=()):
        component['delivery'] = delivery
        existing = components.setdefault(component['purl'], component)
        if existing['delivery'] != delivery:
            raise EvidenceError('one runtime identity crosses delivery boundaries')
        existing['evidence'].append(proof)
        existing['imports'].extend(name for name in imported_names if name not in existing['imports'])

    for entry, file in copied:
        path = entry['path'].replace('\\', '/')
        name = Path(path).name
        sha = digest(file)
        inputs.append({'path': path, 'sha512': sha})
        proof = {'path': path, 'sha512': sha, 'method': ''}
        if sha in registry:
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
            component = identity('Rust target startup runtime', release[1], 'https://www.rust-lang.org/', 'GPL-3.0-or-later WITH GCC-exception-3.1')
            component['source'] = f'https://github.com/rust-lang/rust/tree/{commit[1]}/src/ci'
            component['versionContext'] = 'Rust target distribution release; this is not a claim about the upstream GCC source version'
            proof['method'] = 'startup object delivered in the exact Rust target distribution, bound by input hash'
            register(component, proof)
        elif '/rustlib/' in path and (name.endswith('.rlib') or name in ('libunwind.a',)):
            component = identity('Rust standard library', release[1], 'https://www.rust-lang.org/', 'MIT OR Apache-2.0')
            component['source'] = f'https://github.com/rust-lang/rust/tree/{commit[1]}/library'
            proof['method'] = 'linked Rust sysroot runtime input; captured rustc release and source commit'
            register(component, proof)
        elif name.endswith('.rlib') and '/release/deps/' in path:
            cargo_hashes.append(sha)
        elif name.endswith('.lib') and (package_version := re.search(r'/VC/Tools/MSVC/(\d+\.\d+\.\d+)/', path, re.I)) and not import_library_names(file.read_bytes()):
            component = identity('Microsoft VC static runtime', package_version[1], 'https://visualstudio.microsoft.com/', 'LicenseRef-Microsoft-Visual-Studio')
            component['source'] = 'https://visualstudio.microsoft.com/license-terms/'
            component['versionContext'] = 'installed VC tools package version; exact linked inputs are hashed'
            proof['method'] = 'resolved static library in versioned MSVC package'
            register(component, proof)
        elif re.fullmatch(r'lib(?:c|m|mvec|pthread|rt|dl|util|resolv)\.so(?:\.[\d.]+)?|ld-linux[^/]*\.so(?:\.[\d.]+)?|lib(?:c_nonshared|pthread_nonshared|pthread|dl|rt|m|util)\.a|(?:S?crt\d*|crti|crtn)\.o', name) and len(glibc_versions) == 1:
            component = identity('glibc', next(iter(glibc_versions)), 'https://www.gnu.org/software/libc/', 'LGPL-2.1-or-later')
            proof['method'] = 'resolved linker input and linked libc.so.6 release banner'
            matches = [i['name'] for i in imported if Path(i['name']).name == name]
            bundled = name.endswith(('.o', '.a'))
            component['purl'] += '?linkage=' + ('static' if bundled else 'dynamic')
            register(component, proof, 'bundled' if bundled else 'external', matches)
        elif sha in gcc_hashes and re.fullmatch(r'\d+(?:\.\d+){1,2}', gcc.get('version', '')):
            component = identity('GCC runtime', gcc['version'], 'https://gcc.gnu.org/', 'GPL-3.0-or-later WITH GCC-exception-3.1')
            proof['method'] = 'input hash matches GCC -print-file-name runtime; GCC -dumpfullversion'
            matches = [i['name'] for i in imported if Path(i['name']).name == name or
                       (name.startswith('libgcc_s.so') and i['name'].startswith('libgcc_s.so'))]
            component['purl'] += '?linkage=' + ('dynamic' if matches else 'static')
            register(component, proof, 'external' if matches else 'bundled', matches)
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
            if not re.fullmatch(r'[a-z0-9_.-]+\.dll', name):
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
                original = next(file for entry, file in copied if entry['path'].replace('\\', '/') == unresolved['path'])
                if name in import_library_names(original.read_bytes()):
                    register(component, dict(unresolved, method='COFF import descriptor in the linked import library'), 'external', [name])
        # One import library can supply several DLL imports. Record every
        # selected relationship before removing the library from unresolved inputs.
        covered_hashes = {proof['sha512'] for component in components.values() for proof in component['evidence']}
        unknown = [item for item in unknown if item['sha512'] not in covered_hashes]

    # Mach-O embeds the exact SDK link-interface version for its external load
    # commands. Preserve its meaning; it is not an upstream package release.
    if 'apple' in target:
        for imported_item in imported:
            name = imported_item['name']
            if name in mapped:
                continue
            if not name.startswith(('/usr/lib/', '/System/Library/Frameworks/')):
                raise EvidenceError(f'{name}: non-system macOS runtime requires explicit provider metadata')
            candidates = [item for item in unknown if Path(item['path']).stem == Path(name).stem or
                          ('.framework/' in name and Path(item['path']).stem == name.rsplit('/', 1)[-1]) or
                          (Path(item['path']).suffix == '.tbd' and any(
                              entry['path'].replace('\\', '/') == item['path'] and name in file.read_text(errors='replace')
                              for entry, file in copied))]
            if not candidates or imported_item['linkInterfaceVersion'] == '0.0.0':
                raise EvidenceError(f'{name}: SDK link interface needs explicit provider metadata')
            component = identity(name, imported_item['linkInterfaceVersion'], 'https://developer.apple.com/')
            component['versionContext'] = 'Mach-O SDK link-interface version; not an OS or upstream source version'
            for candidate in candidates:
                register(component, dict(candidate, method='linked SDK stub and Mach-O dylib current_version'), 'external', [name])
                unknown.remove(candidate)

    if unknown:
        (directory / 'unresolved-inputs.json').write_text(json.dumps(unknown, indent=2) + '\n')
        raise EvidenceError(f'{len(unknown)} unresolved native link inputs; review {directory}/unresolved-inputs.json and add hash-bound provider metadata')
    document = {'format': 1, 'target': target, 'binarySha512': binary_hash,
                'capturedAt': dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z'),
                'rustc': capture['rustc'], 'builderImage': capture['builderImage'],
                'imports': imported, 'inputs': inputs, 'cargoInputHashes': cargo_hashes,
                'components': sorted(components.values(), key=lambda item: item['purl'])}
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

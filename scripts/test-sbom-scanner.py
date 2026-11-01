#!/usr/bin/env python3
"""Check advisory matching with isolated controls, never release inventory.

These intentionally old versions must be detected by the pinned scanner. This
tests identity ingestion, not the security or exploitability of our binaries.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

import runtime_evidence as runtime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--grype', default='grype')
    parser.add_argument('--offline', action='store_true', help='require an existing database; never update it')
    args = parser.parse_args()
    version = json.loads(subprocess.check_output([args.grype, 'version', '-o', 'json'], text=True))
    expected = runtime.pinned_tools()['GRYPE_VERSION']
    if version.get('version') != expected:
        raise RuntimeError(f'Grype {expected} required, found {version.get("version")}')
    components = [
        {'type': 'library', 'bom-ref': 'cargo-control', 'name': 'time', 'version': '0.1.12',
         'purl': 'pkg:cargo/time@0.1.12'},
        {'type': 'library', 'bom-ref': 'openssl-control', 'name': 'OpenSSL', 'version': '1.0.1',
         'purl': 'pkg:generic/openssl@1.0.1', 'cpe': runtime.native_cpe('OpenSSL', '1.0.1')},
        {'type': 'library', 'bom-ref': 'musl-control', 'name': 'musl', 'version': '1.1.15',
         'purl': 'pkg:generic/musl@1.1.15', 'cpe': runtime.native_cpe('musl', '1.1.15')},
        {'type': 'library', 'bom-ref': 'negative-control', 'name': 'psonoci-scanner-negative-control',
         'version': '0.0.0', 'purl': 'pkg:generic/psonoci-scanner-negative-control@0.0.0'},
    ]
    environment = dict(os.environ, GRYPE_CHECK_FOR_APP_UPDATE='false', GRYPE_SEARCH_SCOPE='squashed',
                       GRYPE_MATCH_JAVA_USING_CPES='false', GRYPE_MATCH_RUST_USING_CPES='false',
                       GRYPE_MATCH_DOTNET_USING_CPES='false', GRYPE_ADD_CPES_IF_NONE='false')
    if args.offline:
        environment['GRYPE_DB_AUTO_UPDATE'] = 'false'
    with tempfile.TemporaryDirectory(prefix='psonoci-scanner-controls-') as directory:
        path = Path(directory) / 'controls.cdx.json'
        path.write_text(json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
                                    'components': components}))
        result = json.loads(subprocess.check_output([args.grype, f'sbom:{path}', '-o', 'json'],
                                                     env=environment, text=True))
    matches = result.get('matches', [])
    names = {match['artifact']['name'] for match in matches}
    if not {'time', 'OpenSSL', 'musl'} <= names or 'psonoci-scanner-negative-control' in names:
        raise RuntimeError(f'Advisory matching controls failed: matched {sorted(names)}')
    print(json.dumps({'scanner': version['version'], 'database': result.get('descriptor', {}).get('db'),
                      'controlMatchCounts': {name: sum(m['artifact']['name'] == name for m in matches)
                                             for name in ('time', 'OpenSSL', 'musl')},
                      'negativeControlMatches': 0}, indent=2))


if __name__ == '__main__':
    main()

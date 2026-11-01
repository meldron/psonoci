#!/usr/bin/env python3
"""Exercise a real psonoci executable against an isolated local HTTPS API.

Uses only disposable certificates and dummy credentials. No target files change.
The OpenSSL command is the test certificate generator, not the client's library.
"""
import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time

API_KEY_ID = '00000000-0000-4000-8000-000000000001'
RESPONSE = {'allow_insecure_access': False, 'restrict_to_secrets': True,
            'read': True, 'write': False, 'api_key_secrets': []}


@contextmanager
def https_server(certificate, key, protocol):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            requests.append({'path': self.path, 'body': body, 'tls': self.connection.version()})
            payload = json.dumps(RESPONSE).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = protocol
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    original_hash = hashlib.sha512(binary.read_bytes()).hexdigest()
    environment = {key: value for key, value in os.environ.items() if not key.startswith('PSONO_CI_')}
    environment.update(NO_PROXY='localhost,127.0.0.1', no_proxy='localhost,127.0.0.1')
    results = []
    with tempfile.TemporaryDirectory(prefix='psonoci-binary-tls-') as directory:
        root = Path(directory)
        certificate, key = root / 'localhost.pem', root / 'localhost.key'
        authority, authority_key = root / 'ca.pem', root / 'ca.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=Disposable psonoci TLS test CA',
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                        '-keyout', str(authority_key), '-out', str(authority)], check=True, capture_output=True)
        request = root / 'localhost.csr'
        extensions = root / 'extensions.cnf'
        extensions.write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\n'
                              'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                        '-subj', '/CN=localhost', '-keyout', str(key), '-out', str(request)],
                       check=True, capture_output=True)
        subprocess.run(['openssl', 'x509', '-req', '-in', str(request), '-CA', str(authority),
                        '-CAkey', str(authority_key), '-CAcreateserial', '-days', '1',
                        '-extfile', str(extensions), '-out', str(certificate)], check=True, capture_output=True)
        cases = [
            ('native TLS 1.2', True, ssl.TLSVersion.TLSv1_2, True, 'localhost', True),
            ('native TLS 1.3', True, ssl.TLSVersion.TLSv1_3, True, 'localhost', True),
            ('Rustls TLS 1.3', False, ssl.TLSVersion.TLSv1_3, True, 'localhost', True),
            ('native rejects untrusted certificate', True, ssl.TLSVersion.TLSv1_3, False, 'localhost', False),
            ('native rejects wrong hostname', True, ssl.TLSVersion.TLSv1_3, True, '127.0.0.1', False),
        ]
        for name, native, protocol, trusted, hostname, success in cases:
            with https_server(certificate, key, protocol) as (port, requests):
                command = [str(binary), '--api-key-id', API_KEY_ID,
                           '--api-secret-key-hex', '00' * 32,
                           '--server-url', f'https://{hostname}:{port}', '--timeout', '5']
                if native:
                    command.append('--use-native-tls')
                if trusted:
                    command += ['--pem-root-certificate-path', str(authority)]
                start = time.perf_counter()
                result = subprocess.run([*command, 'api-key', 'info'], env=environment,
                                        capture_output=True, text=True, timeout=15)
                if success:
                    if result.returncode != 0:
                        raise RuntimeError(f'{name}: {result.stderr}')
                    response = json.loads(result.stdout)
                    expected_protocol = 'TLSv1.2' if protocol == ssl.TLSVersion.TLSv1_2 else 'TLSv1.3'
                    expected_request = {'path': '/api-key-access/inspect/',
                                        'body': {'api_key_id': API_KEY_ID}, 'tls': expected_protocol}
                    if (requests != [expected_request] or response.get('read') is not True
                            or response.get('write') is not False or response.get('num_api_key_secrets') != 0):
                        raise RuntimeError(f'{name}: API response/request validation failed')
                elif result.returncode == 0 or requests or 'certificate' not in result.stderr.lower():
                    raise RuntimeError(f'{name}: certificate rejection failed: {result.stderr}')
                results.append({'test': name, 'status': 'passed',
                                'seconds': round(time.perf_counter() - start, 3)})
    if hashlib.sha512(binary.read_bytes()).hexdigest() != original_hash:
        raise RuntimeError('Binary changed during the test')
    report = {'binary': str(binary), 'sha512': original_hash, 'tests': results}
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()

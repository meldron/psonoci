#!/usr/bin/env python3
"""Run an isolated Psono API server for CLI testing, with disposable Postgres."""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
from wsgiref.simple_server import make_server

ROOT = Path(__file__).resolve().parent.parent


def load_manifest(state):
    path = state / "server.json"
    try:
        manifest = json.loads(path.read_text())
    except FileNotFoundError as error:
        raise RuntimeError(f"No local Psono state at {path}. Start the server with 'serve' first.") from error
    except (ValueError, UnicodeError) as error:
        raise RuntimeError(f"Invalid local Psono state at {path}. Use a new --state-dir to start 'serve'.") from error
    fields = {"status": str, "pid": int, "run_id": str, "url": str, "binary": str,
              "fixtures": dict, "hashes": dict}
    if (not isinstance(manifest, dict)
            or any(type(manifest.get(key)) is not kind for key, kind in fields.items())
            or manifest["status"] not in ("running", "stopped") or manifest["pid"] <= 0):
        raise RuntimeError(f"Invalid local Psono state at {path}. Use a new --state-dir to start 'serve'.")
    return manifest


def running_manifest(state):
    manifest = load_manifest(state)
    if manifest["status"] != "running":
        raise RuntimeError("The local Psono server is stopped. Start it with 'serve' first.")
    try:
        health(manifest)
    except (OSError, ValueError, RuntimeError) as error:
        raise RuntimeError(f"Local Psono state is stale or the server is unavailable: {error}. "
                           "Check the server terminal or start 'serve' again.") from error
    return manifest


def private_file(path, text):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}-", delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def health(manifest):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(manifest["url"] + "__psonoci_local__/health", timeout=3) as response:
        actual = json.load(response)
    if actual != {"pid": manifest["pid"], "run_id": manifest["run_id"]}:
        raise RuntimeError("the server at this address does not match this test setup")


def cli(state, manifest, *args):
    if not (state / "psonoci.toml").is_file():
        raise RuntimeError(f"Local Psono config is missing from {state}. Restart the server with 'serve'.")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("PSONO_CI_")}
    environment.update(NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
    result = subprocess.run([manifest["binary"], "--config-path", str(state / "psonoci.toml"),
                             *map(str, args)], env=environment, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout


def check(state):
    manifest = running_manifest(state)
    info = json.loads(cli(state, manifest, "api-key", "info"))
    assert info["read"] and info["write"]
    assert info["num_api_key_secrets"] >= len(manifest["fixtures"])
    for name, nested in [("ssh", "ssh_key"), ("elster", "elster_certificate")]:
        payload = json.loads(cli(state, manifest, "secret", "get", manifest["fixtures"][name], "json"))
        for field, expected in manifest["hashes"][name].items():
            assert hashlib.sha256(payload[nested][field].encode()).hexdigest() == expected, (name, field)
        for internal in ["raw", "write_date", "secret_type"]:
            assert internal not in payload
        print(f"PASS: {name} JSON includes every seeded field", flush=True)
    note_id = manifest["fixtures"]["note"]
    previous = cli(state, manifest, "secret", "get", note_id, "notes")
    try:
        cli(state, manifest, "secret", "set", note_id, "notes", "Local Psono write check")
        assert cli(state, manifest, "secret", "get", note_id, "notes") == "Local Psono write check"
    finally:
        cli(state, manifest, "secret", "set", note_id, "notes", previous)
    print("PASS: encrypted read, update and reread", flush=True)
    website_id = manifest["fixtures"]["website"]
    token = cli(state, manifest, "totp", "get-token", website_id)
    cli(state, manifest, "totp", "validate-token", website_id, token)
    print("PASS: website TOTP generation and validation", flush=True)
    assert cli(state, manifest, "run", "--filter", manifest["fixtures"]["environment"],
               "--clear-env", "--", "/bin/sh", "-c", 'printf "%s" "$PSONOCI_LOCAL_TEST"') == "local-server-ok"
    assert json.loads(cli(state, manifest, "secret", "get", manifest["fixtures"]["connection"], "json"))["ssh_connection_host"] == "fixture.invalid"
    print("PASS: filtered environment injection and unsupported-secret JSON", flush=True)


def seed(compatibility, binary, url, home):
    fixture = compatibility.Fixture(binary, url)
    root = Path(home)
    key = root / "fixture_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "psonoci-local-fixture", "-f", str(key)],
                   check=True, capture_output=True)
    cert_key, cert, p12 = root / "cert.key", root / "cert.pem", root / "fixture.p12"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=psonoci-local-fixture", "-keyout", str(cert_key), "-out", str(cert)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkcs12", "-export", "-inkey", str(cert_key), "-in", str(cert),
                    "-out", str(p12), "-passout", "pass:local-fixture-only"], check=True, capture_output=True)
    ssh = {"key_private": key.read_text(), "key_public": key.with_suffix(".pub").read_text().strip()}
    elster = {"file_content": base64.b64encode(p12.read_bytes()).decode(),
              "password": "local-fixture-only", "retrieval_code": "local-retrieval-code"}
    payloads = {
        "ssh": {"ssh_own_key_title": "Local SSH fixture", "ssh_own_key_notes": "Disposable Ed25519 key",
                "ssh_own_key_private": ssh["key_private"], "ssh_own_key_public": ssh["key_public"]},
        "elster": {"elster_certificate_title": "Local Elster fixture",
                   **{"elster_certificate_" + field: value for field, value in elster.items()}},
        "note": {"note_title": "Local note fixture", "note_notes": "Original local fixture note"},
        "website": {"website_password_title": "Local website fixture", "website_password_username": "fixture",
                    "website_password_password": "local-password-only", "website_password_totp_code": "JBSWY3DPEHPK3PXP",
                    "website_password_totp_period": "30", "website_password_totp_digits": "6",
                    "custom_fields": [{"name": "owner", "value": "local-test"}], "tags": ["local-test"]},
        "environment": {"environment_variables_title": "Local environment fixture",
                        "environment_variables_variables": [{"key": "PSONOCI_LOCAL_TEST", "value": "local-server-ok"}]},
        "connection": {"ssh_connection_title": "Unsupported connection fixture", "ssh_connection_host": "fixture.invalid"},
    }
    fixtures = {name: str(fixture.create(payload)[0].id) for name, payload in payloads.items()}
    hashes = {name: {field: hashlib.sha256(value.encode()).hexdigest() for field, value in fields.items()}
              for name, fields in [("ssh", ssh), ("elster", elster)]}
    return fixture, fixtures, hashes


def serve(args, state):
    binary = args.binary.resolve(strict=True)
    source = args.server_source.resolve(strict=True)
    # Check the interpreter before creating state or starting the database.
    try:
        from django.core.wsgi import get_wsgi_application
        from django.db import connections
    except ImportError as error:
        raise RuntimeError("Django is unavailable in this Python environment. Run 'serve' with "
                           f"{source / '.venv/bin/python'} and the Psono server dependencies installed.") from error
    spec = importlib.util.spec_from_file_location("compatibility", Path(__file__).with_name("test-psono-compatibility.py"))
    compatibility = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compatibility)
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    state.chmod(0o700)
    manifest_path = state / "server.json"
    if manifest_path.exists():
        old = load_manifest(state)
        if old["status"] == "running":
            try:
                health(old)
            except (OSError, RuntimeError):
                pass
            else:
                raise RuntimeError("a test server is already running in this state directory")
    stop = threading.Event()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(sig, lambda *_: stop.set())
    manifest = None
    try:
        with tempfile.TemporaryDirectory(prefix="run-", dir=state) as home, compatibility.database() as port:
            compatibility.configure_server(source, home, port)
            application = get_wsgi_application()
            run_id = uuid.uuid4().hex

            def wsgi(environ, start_response):
                if environ.get("PATH_INFO") == "/__psonoci_local__/health":
                    data = json.dumps({"pid": os.getpid(), "run_id": run_id}).encode()
                    start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(data)))])
                    return [data]
                return application(environ, start_response)

            server = make_server("127.0.0.1", args.port, wsgi, handler_class=compatibility.QuietHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}/"
                fixture, fixtures, hashes = seed(compatibility, binary, url, home)
                private_file(state / "psonoci.toml", f'''version = "1"
[psono_settings]
api_key_id = "{fixture.api_key.id}"
api_secret_key_hex = "{bytes(fixture.key).hex()}"
server_url = "{url}"
[http_options]
timeout = 5
max_redirects = 0
use_native_tls = false
danger_disable_tls_verification = false
''')
                manifest = {"status": "running", "pid": os.getpid(), "run_id": run_id, "url": url,
                            "binary": str(binary), "source": str(source), "fixtures": fixtures, "hashes": hashes}
                private_file(manifest_path, json.dumps(manifest, indent=2) + "\n")
                if args.full_validation:
                    compatibility.password_checks(fixture)
                    compatibility.totp_checks(fixture)
                check(state)
                print(f"READY: Psono API at {url}", flush=True)
                print(f"CLI config: {state / 'psonoci.toml'}", flush=True)
                print(f"Fixture IDs: {manifest_path}", flush=True)
                stop.wait()
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()
                connections.close_all()
    finally:
        if manifest is not None:
            manifest["status"] = "stopped"
            private_file(manifest_path, json.dumps(manifest, indent=2) + "\n")
            (state / "psonoci.toml").unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=ROOT / ".local-psono")
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("serve", help="Start the real API server; Ctrl-C stops it and removes the database")
    start.add_argument("--server-source", type=Path, required=True)
    start.add_argument("--binary", type=Path, default=ROOT / "target/debug/psonoci")
    start.add_argument("--port", type=int, default=18183)
    start.add_argument("--full-validation", action="store_true")
    sub.add_parser("check", help="Check the running server through the saved CLI config")
    runner = sub.add_parser("cli", help="Run CLI commands with the local config and without inherited PSONO_CI settings")
    runner.add_argument("arguments", nargs=argparse.REMAINDER)
    sub.add_parser("stop", help="Stop this setup after verifying the running server identity")
    args = parser.parse_args()
    state = args.state_dir.resolve()
    try:
        run(args, state, parser)
    except ImportError as error:
        parser.exit(1, f"error: Missing Python dependency: {error}. Run 'serve' with the Psono server's Python environment.\n")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"error: {error}\n")


def run(args, state, parser):
    if args.command == "serve":
        serve(args, state)
    elif args.command == "check":
        check(state)
    elif args.command == "cli":
        if args.arguments[:1] == ["--"]:
            args.arguments = args.arguments[1:]
        if not args.arguments:
            parser.error("cli requires a psonoci command")
        manifest = running_manifest(state)
        print(cli(state, manifest, *args.arguments), end="")
    else:
        manifest = running_manifest(state)
        os.kill(manifest["pid"], signal.SIGTERM)
        for _ in range(100):
            if load_manifest(state)["status"] == "stopped":
                print("Stopped the local Psono server and removed its disposable database")
                return
            time.sleep(0.1)
        raise RuntimeError("stop requested, but cleanup did not finish within 10 seconds")


if __name__ == "__main__":
    main()

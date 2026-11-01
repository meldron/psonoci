#!/usr/bin/env python3
"""Exercise the built CLI against a local Psono checkout and disposable Postgres.

Run with the server's Python environment, which must have its dependencies:
  /path/to/psono-server/.venv/bin/python -B scripts/test-psono-compatibility.py \
      --server-source /path/to/psono-server --binary target/debug/psonoci

Requires Docker and a cached postgres:17 image. No existing Psono config,
accounts or databases are used. The container is removed even if a check fails.
"""

import argparse
import base64
import contextlib
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from urllib.parse import parse_qs, unquote, urlparse
from wsgiref.simple_server import WSGIRequestHandler, make_server


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=60).strip()


@contextlib.contextmanager
def database():
    name = f"psonoci-compatibility-{uuid.uuid4().hex[:12]}"
    try:
        docker("run", "--detach", "--rm", "--pull=never", "--name", name,
               "--publish", "127.0.0.1::5432", "--tmpfs", "/var/lib/postgresql/data",
               "--env", "POSTGRES_PASSWORD=psonoci-test-only",
               "--env", "POSTGRES_DB=psonoci_test", "postgres:17")
        for _ in range(120):
            if subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=10).returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError("disposable Postgres did not start")
        yield int(docker("port", name, "5432/tcp").rsplit(":", 1)[1])
    finally:
        subprocess.run(["docker", "rm", "--force", name], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def configure_server(source, home, port):
    import nacl.signing

    # Settings can also be overridden individually by PSONO_* variables.
    for key in list(os.environ):
        if key.startswith("PSONO_") or key == "DJANGO_SETTINGS_MODULE":
            del os.environ[key]
    signing_key = nacl.signing.SigningKey.generate()
    config = {
        "SECRET_KEY": secrets.token_hex(32),
        "ACTIVATION_LINK_SECRET": secrets.token_hex(32),
        "DB_SECRET": secrets.token_hex(32),
        "EMAIL_SECRET_SALT": "$2b$12$XUG.sKxC2jmkUvWQjg53.e",
        "PRIVATE_KEY": signing_key.encode().hex(),
        "PUBLIC_KEY": signing_key.verify_key.encode().hex(),
        "HOST_URL": "http://127.0.0.1", "ALLOWED_HOSTS": ["127.0.0.1"],
        "ALLOWED_DOMAINS": ["example.com"], "THROTTLING": False,
        "CACHE_ENABLE": False, "DISABLE_CALLBACKS": True,
        "DATABASES": {"default": {
            "ENGINE": "django.db.backends.postgresql", "NAME": "psonoci_test",
            "USER": "postgres", "PASSWORD": "psonoci-test-only",
            "HOST": "127.0.0.1", "PORT": str(port),
        }},
    }
    directory = Path(home) / ".psono_server"
    directory.mkdir()
    (directory / "settings.yaml").write_text(json.dumps(config))
    os.environ["PSONO_HOME"] = home
    os.environ["DJANGO_SETTINGS_MODULE"] = "psono.settings"
    sys.path.insert(0, str(source / "psono"))
    sys.dont_write_bytecode = True
    import django
    django.setup()
    from django.core.management import call_command
    call_command("migrate", interactive=False, verbosity=0)


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


class Fixture:
    def __init__(self, binary, url):
        from restapi import models
        import nacl.secret

        self.binary = str(binary)
        self.url = url
        self.key = nacl.secret.SecretBox(secrets.token_bytes(32))
        self.user = models.User.objects.create(
            username="psonoci-test@example.com", email="psonoci-test@example.com",
            email_bcrypt="test", authkey="test", public_key=secrets.token_hex(32),
            private_key="test", private_key_nonce=secrets.token_hex(24),
            secret_key="test", secret_key_nonce=secrets.token_hex(24),
            user_sauce=secrets.token_hex(32), is_email_active=True,
        )
        self.api_key = models.API_Key.objects.create(
            user=self.user, title="Disposable CLI test", read=True, write=True,
            restrict_to_secrets=True, allow_insecure_access=False,
            private_key_nonce=secrets.token_hex(24), secret_key_nonce=secrets.token_hex(24),
            user_private_key_nonce=secrets.token_hex(24), user_secret_key_nonce=secrets.token_hex(24),
        )
        self.datastore = models.Data_Store.objects.create(user=self.user, type="password")

    def create(self, payload):
        from restapi import models
        import nacl.secret

        box = nacl.secret.SecretBox(secrets.token_bytes(32))
        encrypted = box.encrypt(json.dumps(payload).encode())
        secret = models.Secret.objects.create(
            user=self.user, data=encrypted.ciphertext.hex().encode(),
            data_nonce=encrypted.nonce.hex(),
        )
        models.Secret_Link.objects.create(
            link_id=uuid.uuid4(), secret=secret, parent_datastore=self.datastore,
        )
        encrypted_key = self.key.encrypt(bytes(box).hex().encode())
        models.API_Key_Secret.objects.create(
            api_key=self.api_key, secret=secret, secret_key=encrypted_key.ciphertext.hex(),
            secret_key_nonce=encrypted_key.nonce.hex(),
        )
        return secret, box

    def cli(self, *args, success=True):
        result = subprocess.run([
            self.binary, "--api-key-id", str(self.api_key.id),
            "--api-secret-key-hex", bytes(self.key).hex(), "--server-url", self.url,
            *map(str, args),
        ], capture_output=True, text=True, timeout=15)
        if (result.returncode == 0) != success:
            raise AssertionError(f"CLI failed: {result.stderr}")
        return result.stdout if success else result.stderr

    @staticmethod
    def payload(secret, box):
        secret.refresh_from_db()
        return json.loads(box.decrypt(bytes.fromhex(bytes(secret.data).decode()),
                                      bytes.fromhex(secret.data_nonce)))


def password_checks(fixture):
    old = "2025-01-01T09:00:00.123456Z"
    count = 0
    for field, value_type in [
        ("website_password_password", "password"),
        ("application_password_password", "password"),
        ("elster_certificate_password", "elster-certificate-password"),
    ]:
        for timestamp in [old, None, "invalid"]:
            original = {field: "before", "custom_fields": [{"name": "owner", "value": "fixture"}],
                        "tags": ["test"], "future": {"keep": [True, None]}}
            if timestamp is not None:
                original["password_modification_datetime"] = timestamp
            secret, box = fixture.create(original)
            previous_write = secret.write_date
            fixture.cli("secret", "set", secret.id, "notes", "new notes")
            unchanged = fixture.payload(secret, box)
            date = datetime.fromisoformat(unchanged["password_modification_datetime"].replace("Z", "+00:00"))
            expected = datetime.fromisoformat(old.replace("Z", "+00:00")) if timestamp == old else previous_write
            assert date == expected, "notes edit changed password age"
            for password in ["before", "after", ""]:
                before = fixture.payload(secret, box)
                start = datetime.now(timezone.utc)
                fixture.cli("secret", "set", secret.id, value_type, password)
                after = fixture.payload(secret, box)
                if password == "before":
                    assert after == before, "unchanged password modified payload"
                else:
                    date = datetime.fromisoformat(after["password_modification_datetime"].replace("Z", "+00:00"))
                    # CLI writes milliseconds; allow truncation at the lower bound.
                    assert start.timestamp() - 0.001 <= date.timestamp() <= time.time()
                    expected_payload = {**before, field: password,
                                        "password_modification_datetime": after["password_modification_datetime"]}
                    assert after == expected_payload, "password update changed unrelated fields"
            count += 1
    secret, box = fixture.create({"note_title": "Test", "note_notes": "before"})
    fixture.cli("secret", "set", secret.id, "notes", "after")
    assert fixture.payload(secret, box) == {"note_title": "Test", "note_notes": "after"}
    print(f"PASS: {count} password scenarios and unrelated note, through CLI/HTTP/Psono/Postgres")


def token(seed, algorithm, digits, period, timestamp):
    """Independent RFC 6238 calculation, without the Rust TOTP library."""
    counter = int(timestamp // period).to_bytes(8, "big")
    digest = hmac.new(base64.b32decode(seed), counter,
                      getattr(hashlib, algorithm.lower())).digest()
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
    return str(number % (10 ** digits)).zfill(digits)


def totp_checks(fixture):
    seed = base64.b32encode(b"12345678901234567890").decode()
    replacement_seed = base64.b32encode(b"09876543210987654321").decode()
    cases = [
        ("website_password_totp", {}, "SHA1", 6, 30),
        ("website_password_totp", {"code": "JBSWY3DPEHPK3PXP"}, "SHA1", 6, 30),
        ("website_password_totp", {"period": None, "algorithm": None, "digits": None}, "SHA1", 6, 30),
        ("website_password_totp", {"period": 0, "algorithm": "", "digits": 0}, "SHA1", 6, 30),
        ("website_password_totp", {"period": 60, "algorithm": "SHA256", "digits": 8}, "SHA256", 8, 60),
        ("website_password_totp", {"period": "60", "algorithm": "SHA256", "digits": "7"}, "SHA256", 7, 60),
        ("website_password_totp", {"period": "", "algorithm": "", "digits": ""}, "SHA1", 6, 30),
        ("website_password_totp", {"period": 45, "algorithm": "SHA512", "digits": 7}, "SHA512", 7, 45),
        ("totp", {"period": 30, "algorithm": "SHA1", "digits": 6}, "SHA1", 6, 30),
    ]
    for prefix, settings, algorithm, digits, period in cases:
        original = {f"{prefix}_code": seed, **{f"{prefix}_{key}": value for key, value in settings.items()}}
        secret_seed = original[f"{prefix}_code"]
        if prefix == "website_password_totp":
            original.update(website_password_title="Fixture", website_password_password="before",
                            password_modification_datetime="2025-01-01T00:00:00Z",
                            custom_fields=[{"name": "owner", "value": "fixture"}])
        secret, box = fixture.create(original)
        start = time.time()
        generated = fixture.cli("totp", "get-token", secret.id)
        assert generated in {token(secret_seed, algorithm, digits, period, start),
                             token(secret_seed, algorithm, digits, period, time.time())}
        fixture.cli("totp", "validate-token", secret.id,
                    token(secret_seed, algorithm, digits, period, time.time()))
        error = fixture.cli("totp", "validate-token", secret.id, "not-a-token", success=False)
        assert "token invalid" in error
        uri = fixture.cli("totp", "get-url", secret.id, "--issuer", "Fixture", "--account-name", "test@example.com")
        parsed = urlparse(uri)
        query = parse_qs(parsed.query)
        assert parsed.scheme == "otpauth" and parsed.netloc == "totp"
        assert unquote(parsed.path) == "/Fixture:test@example.com"
        assert query["secret"] == [secret_seed]
        assert query.get("algorithm", ["SHA1"]) == [algorithm]
        assert query.get("digits", ["6"]) == [str(digits)]
        assert query.get("period", ["30"]) == [str(period)]
        assert fixture.payload(secret, box) == original, "TOTP read modified stored payload"
        assert fixture.cli("secret", "get", secret.id, "totp-code") == secret_seed
        if prefix == "website_password_totp":
            for key, value in [("period", "90"), ("algorithm", "SHA256"), ("digits", "8"), ("code", replacement_seed)]:
                before = fixture.payload(secret, box)
                fixture.cli("secret", "set", secret.id, f"totp-{key}", value)
                expected = {**before, f"{prefix}_{key}": int(value) if key in {"period", "digits"} else value}
                assert fixture.payload(secret, box) == expected, "TOTP edit modified unrelated fields"

    # Adding an authenticator to a website must not require an existing TOTP object.
    secret, box = fixture.create({"website_password_title": "No authenticator"})
    assert "TOTP data is not set" in fixture.cli("totp", "get-token", secret.id, success=False)
    fixture.cli("secret", "set", secret.id, "totp-code", seed)
    assert fixture.payload(secret, box) == {"website_password_title": "No authenticator", "website_password_totp_code": seed}
    fixture.cli("totp", "get-token", secret.id)

    for payload, message in [
        ({"note_title": "Not TOTP"}, "not a TOTP or website secret"),
        ({"website_password_totp_code": "invalid!"}, "Could not decode base32 secret"),
        ({"website_password_totp_code": ""}, "TOTP seed is empty"),
        ({"website_password_totp_code": seed, "website_password_totp_algorithm": "MD5"}, "Unsupported Algorithm"),
        ({"website_password_totp_code": seed, "website_password_totp_digits": 5}, "Could not create TOTP Instance"),
        ({"website_password_totp_code": seed, "website_password_totp_period": "bad"}, "parsing decrypted secret payload fields failed"),
        ({"totp_code": seed, "totp_period": 0, "totp_algorithm": "SHA1", "totp_digits": 6}, "period must be greater than zero"),
    ]:
        secret, box = fixture.create(payload)
        error = fixture.cli("totp", "get-token", secret.id, success=False)
        assert message in error, error
        assert seed not in error
        assert fixture.payload(secret, box) == payload
    print(f"PASS: {len(cases)} TOTP configurations, independent HMAC checks, edits and failure cases")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-source", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    source = args.server_source.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="psonoci-compatibility-") as home, database() as port:
        configure_server(source, home, port)
        from django.core.wsgi import get_wsgi_application
        from django.db import connections
        server = make_server("127.0.0.1", 0, get_wsgi_application(), handler_class=QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            fixture = Fixture(binary, f"http://127.0.0.1:{server.server_port}/")
            password_checks(fixture)
            totp_checks(fixture)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
            connections.close_all()


if __name__ == "__main__":
    main()

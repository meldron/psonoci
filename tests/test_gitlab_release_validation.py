"""Exercise validation isolation without credentials or external side effects."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEST_TAGS = ('gitlab-release-test-tag', 'gitlab-release-test-tag2')


@unittest.skipUnless(shutil.which('bash') and os.name != 'nt', 'requires Unix Bash')
class ReleaseValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commands = self.root / 'commands'
        self.commands.mkdir()
        self.log = self.root / 'external-calls'
        self.environment = {
            'PATH': str(self.commands) + os.pathsep + os.environ['PATH'],
            'CALL_LOG': str(self.log),
        }
        for name in ('apt-get', 'curl', 'gcloud', 'gsutil', 'sh'):
            self.stub(name, 'echo external-command >> "$CALL_LOG"\nexit 97\n')

    def stub(self, name, body):
        path = self.commands / name
        path.write_text('#!/bin/bash\n' + body)
        path.chmod(0o755)

    def run_script(self, script, *args, **environment):
        return subprocess.run(
            ['bash', str(ROOT / script), *args], cwd=self.root,
            env=self.environment | environment, capture_output=True, text=True,
        )

    def test_only_version_tags_allow_production_publication(self):
        for tag in (*TEST_TAGS, '', 'master', 'v1.2.3-rc1', 'v1.2.3/path'):
            with self.subTest(tag=tag):
                result = self.run_script('var/release-mode.sh', 'production', CI_COMMIT_TAG=tag)
                self.assertNotEqual(result.returncode, 0)
        result = self.run_script('var/release-mode.sh', 'production', CI_COMMIT_TAG='v1.2.3')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_both_test_tags_select_validation_mode(self):
        for tag in TEST_TAGS:
            result = self.run_script('var/release-mode.sh', 'validation', CI_COMMIT_TAG=tag)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.run_script(
            'var/release-mode.sh', 'validation', CI_COMMIT_TAG='v1.2.3').returncode, 0)

    def test_publish_and_login_refuse_validation_before_any_external_command(self):
        for script in ('var/publish_release_artifacts.sh', 'var/login_gcp.sh'):
            for tag in (*TEST_TAGS, ''):
                with self.subTest(script=script, tag=tag):
                    result = self.run_script(script, CI_COMMIT_TAG=tag)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Refusing production', result.stderr)
                    self.assertFalse(self.log.exists())

    def signing_environment(self):
        key = self.root / 'dummy-signing-key'
        key.write_text('test fixture, not a private key')
        return dict(CI_COMMIT_TAG=TEST_TAGS[0], CI_COMMIT_REF_PROTECTED='true',
                    GPG_PRIVATE_KEY=str(key), GPG_PRIVATE_KEY_PASSPHRASE='')

    def test_preflight_accepts_signing_without_upload_credentials(self):
        environment = self.signing_environment()
        for tag in TEST_TAGS:
            result = self.run_script('var/check_release_validation.sh',
                                     **(environment | {'CI_COMMIT_TAG': tag}))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_preflight_rejects_even_an_empty_upload_credential(self):
        for credential in ('', 'dummy-test-value'):
            result = self.run_script('var/check_release_validation.sh',
                                     **(self.signing_environment() |
                                        {'GOOGLE_APPLICATION_CREDENTIALS': credential}))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('must not receive', result.stderr)
            self.assertNotIn('dummy-test-value', result.stdout + result.stderr)

    def test_preflight_requires_protected_tag_and_existing_signing_configuration(self):
        environment = self.signing_environment()
        for overrides in ({'CI_COMMIT_REF_PROTECTED': 'false'},
                          {'GPG_PRIVATE_KEY': '/missing/signing-key'}):
            self.assertNotEqual(self.run_script(
                'var/check_release_validation.sh', **(environment | overrides)).returncode, 0)
        environment.pop('GPG_PRIVATE_KEY_PASSPHRASE')
        self.assertNotEqual(self.run_script(
            'var/check_release_validation.sh', **environment).returncode, 0)

    def test_validation_sboms_do_not_claim_download_server_urls(self):
        # Run the real packaging loop with inert substitutes for signing and
        # archiving; inspect the arguments passed to the real SBOM entry point.
        for name in ('apt-get', 'gpg', 'tar', 'zip'):
            self.stub(name, 'exit 0\n')
        (self.root / 'var').mkdir()
        shutil.copyfile(ROOT / 'var/release-mode.sh', self.root / 'var/release-mode.sh')
        scripts = self.root / 'scripts'
        scripts.mkdir()
        generator = scripts / 'generate-sbom.sh'
        generator.write_text(
            '#!/usr/bin/env python3\nimport json, os, sys\n'
            'with open(os.environ["CALL_LOG"], "a") as out:\n'
            '    out.write(json.dumps(sys.argv[1:]) + "\\n")\n')
        generator.chmod(0o755)
        targets = ('x86_64-unknown-linux-musl', 'armv7-unknown-linux-gnueabihf',
                   'aarch64-unknown-linux-musl', 'x86_64-apple-darwin',
                   'aarch64-apple-darwin', 'x86_64-pc-windows-gnu',
                   'x86_64-pc-windows-msvc')
        for target in targets:
            binary = self.root / 'target' / target / 'release' / (
                'psonoci.exe' if 'windows' in target else 'psonoci')
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'test fixture')
        for tag in (*TEST_TAGS, 'v1.2.3'):
            with self.subTest(tag=tag):
                self.log.unlink(missing_ok=True)
                environment = self.signing_environment() | {
                    'CI_COMMIT_TAG': tag, 'CI_COMMIT_SHA': 'a' * 40,
                    'CI_PROJECT_PATH': 'esaqa/psono/psono-ci', 'SOURCE_DATE_EPOCH': '0',
                }
                result = self.run_script('var/upload_artifacts.sh', **environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [json.loads(line) for line in self.log.read_text().splitlines()]
                self.assertEqual(len(calls), 7)
                for call in calls:
                    self.assertEqual('--artifact-url' in call, tag == 'v1.2.3')
                    self.assertEqual('--release-version' in call, tag == 'v1.2.3')


if __name__ == '__main__':
    unittest.main()

"""Exercise prerelease publication failures without contacting either host."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("publisher", ROOT / "scripts/publish-gitlab-prerelease.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class FakeGitLab:
    base = "https://gitlab.example/api/v4/projects/123"

    def __init__(self):
        self.files = {}
        self.calls = []
        self.release = None
        self.corrupt = False
        self.fail_upload = False

    def request(self, method, path, data=None, content_type=None):
        self.calls.append((method, path))
        if method == "GET":
            return self.release if path.startswith("/releases/") else self.files.get(path)
        if method == "PUT":
            if self.fail_upload:
                raise RuntimeError("upload failed")
            self.files[path] = b"corrupt" if self.corrupt else data
            return b""
        if method == "POST":
            self.release = json.loads(data)
            return b""
        raise AssertionError(method)


class PrereleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.artifacts = self.root / "collected_artifacts"
        self.artifacts.mkdir()
        self.tag = "v0.7.0-rc.1"
        for target in publisher.TARGETS:
            base = f"psonoci-{self.tag}-{target}"
            archive = base + (".zip" if "windows" in target else ".tar.gz")
            for name in (archive, archive + ".sig", base + ".cdx.json", base + ".cdx.json.sig"):
                (self.artifacts / name).write_bytes(name.encode())
        self.changelog = self.root / "CHANGELOG.md"
        self.changelog.write_text("# Current\n\n- Added: prereleases\n\n# Old\n\n- Old changes\n")
        self.environment = {
            "CI_COMMIT_TAG": self.tag, "CI_COMMIT_SHA": "a" * 40,
            "CI_COMMIT_REF_PROTECTED": "true", "CI_PROJECT_URL": "https://gitlab.example/project",
        }
        self.client = FakeGitLab()

    def publish(self, environment=None):
        publisher.publish(self.client, environment or self.environment, self.artifacts, self.changelog)

    def test_complete_downloads_are_verified_before_release_creation(self):
        self.publish()
        self.assertEqual(len(self.client.files), 32)
        self.assertEqual(self.client.calls[-1], ("POST", "/releases"))
        release = self.client.release
        self.assertIn("Prerelease", release["name"])
        self.assertEqual(release["tag_name"], self.tag)
        self.assertIn("a" * 40, release["description"])
        self.assertIn("- Added: prereleases", release["description"])
        self.assertNotIn("Old changes", release["description"])
        self.assertEqual(len(release["assets"]["links"]), 32)
        for link in release["assets"]["links"]:
            self.assertTrue(link["url"].startswith(self.client.base + "/packages/generic/psonoci/"))
            self.assertNotIn("get.psono.com", link["url"])

    def test_partial_upload_can_resume_without_duplicate_files(self):
        first = next(self.artifacts.iterdir())
        path = f"/packages/generic/psonoci/{self.tag}/{first.name}"
        self.client.files[path] = first.read_bytes()
        self.publish()
        self.assertEqual(sum(method == "PUT" for method, _ in self.client.calls), 31)

    def test_corruption_or_upload_failure_never_creates_release(self):
        for failure in ("corrupt", "fail_upload"):
            with self.subTest(failure=failure):
                self.client = FakeGitLab()
                setattr(self.client, failure, True)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.publish()
                self.assertIsNone(self.client.release)

    def test_published_release_is_immutable(self):
        self.client.release = {"tag_name": self.tag}
        with self.assertRaisesRegex(ValueError, "already published"):
            self.publish()
        self.assertFalse(any(method in ("PUT", "POST") for method, _ in self.client.calls))

    def test_incomplete_artifacts_are_rejected_before_network(self):
        next(self.artifacts.iterdir()).unlink()
        with self.assertRaisesRegex(RuntimeError, "missing release files"):
            self.publish()
        self.assertEqual(self.client.calls, [])

    def test_wrong_tag_or_credentials_are_rejected_before_network(self):
        for overrides in ({"CI_COMMIT_TAG": "v0.7.0"}, {"CI_COMMIT_TAG": "master"},
                          {"CI_COMMIT_REF_PROTECTED": "false"},
                          {"GOOGLE_APPLICATION_CREDENTIALS": ""}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.publish(self.environment | overrides)
        self.assertEqual(self.client.calls, [])

    def test_shell_and_publisher_agree_on_tag_modes(self):
        for tag in (self.tag, "v1.2.3-alpha.0", "v1.2.3-beta.12", "v1.2.3", "v1.2.3-rc1",
                    "v1.2.3-rc.01", "v1.2.3-rc.1/path", "master", ""):
            with self.subTest(tag=tag):
                result = subprocess.run(["bash", str(ROOT / "var/release-mode.sh"), "prerelease"],
                                        env=os.environ | {"CI_COMMIT_TAG": tag}, capture_output=True)
                self.assertEqual(result.returncode == 0, bool(publisher.PRERELEASE.fullmatch(tag)))

    def test_gitlab_build_collection_and_release_links_cover_both_platforms(self):
        workflow = (ROOT / ".gitlab-ci.yml").read_text()
        github = (ROOT / ".github/workflows/release.yml").read_text()
        expected = set(publisher.TARGETS)
        self.assertIn("armv7-unknown-linux-musleabihf", expected)
        self.assertEqual(set(re.findall(r"^    BUILD_ENV: (\S+)$", workflow, re.MULTILINE)), expected)
        self.assertEqual(set(re.findall(r"^\s+target: (\S+)$", github, re.MULTILINE)), expected)
        collection = workflow.split("\ncollect-artifacts:\n", 1)[1].split("\n.sbom-schema-validator:", 1)[0]
        dependencies = re.findall(r"^    - build-(\S+)$", collection, re.MULTILINE)
        self.assertEqual(set(dependencies), expected)
        release = workflow.split("\ngitlab-release:\n", 1)[1].split("\n  only:", 1)[0]
        links = re.findall(r'^        - name: "([^"]+)"$', release, re.MULTILINE)
        names = set()
        for target in expected:
            base = f"psonoci-${{CI_COMMIT_TAG}}-{target}"
            archive = base + (".zip" if "windows" in target else ".tar.gz")
            names.update((archive, archive + ".sig", base + ".cdx.json", base + ".cdx.json.sig"))
        self.assertEqual(set(links), names)
        self.assertEqual(len(links), len(names))


if __name__ == "__main__":
    unittest.main()

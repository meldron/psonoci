from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "sbom"
SPEC = importlib.util.spec_from_file_location("psonoci_sbom", ROOT / "scripts" / "sbom.py")
assert SPEC and SPEC.loader
sbom = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sbom)


def properties(*, executable: bool, archive: bool, filename: str | None = None):
    return sbom.bsi_properties(
        executable=executable,
        archive=archive,
        structured=archive,
        license_id="MIT",
        filename=filename,
    )


def minimal_document(archive_hash: str, binary_hash: str, archive_name: str = "app.tar.gz"):
    archive_ref = "pkg:generic/app-release@1.0.0"
    binary_ref = "pkg:generic/app@1.0.0"
    primary = {
        "type": "file",
        "bom-ref": archive_ref,
        "name": archive_name,
        "version": "1.0.0",
        "licenses": [{"expression": "MIT"}],
        "externalReferences": [{"type": "website", "url": "https://example.test"}],
        "hashes": [{"alg": "SHA-512", "content": archive_hash}],
        "properties": properties(executable=False, archive=True, filename=archive_name),
    }
    executable = {
        "type": "application",
        "bom-ref": binary_ref,
        "name": "app",
        "version": "1.0.0",
        "licenses": [{"expression": "MIT"}],
        "externalReferences": [{"type": "website", "url": "https://example.test"}],
        "hashes": [{"alg": "SHA-512", "content": binary_hash}],
        "properties": properties(executable=True, archive=False, filename="app")
        + [
            {"name": "psonoci:release:commit", "value": "a" * 40},
            {"name": "psonoci:release:target", "value": "x86_64-unknown-linux-gnu"},
        ],
    }
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:4d36e96e-e325-11ce-bfc1-08002be10318",
        "version": 1,
        "metadata": {
            "timestamp": "2023-11-14T22:13:20Z",
            "authors": [{"name": "Psono", "email": "psonoci@example.test"}],
            "tools": {"components": [
                {"name": "syft", "version": "1.50.0"},
                {"name": "cargo-auditable", "version": "0.7.5"},
                {"name": sbom.TOOL_NAME, "version": sbom.TOOL_VERSION},
            ]},
            "component": primary,
            "properties": [{
                "name": "psonoci:sbom:dependency-graph",
                "value": "cargo-runtime-edges-verified-against-syft",
            }],
        },
        "components": [executable],
        "dependencies": [
            {"ref": archive_ref, "dependsOn": [binary_ref]},
            {"ref": binary_ref, "dependsOn": []},
        ],
        "compositions": [{"aggregate": "incomplete", "assemblies": [archive_ref]}],
    }
    runtime_ref = "pkg:generic/rust-standard-library@1.94.1"
    proof = {"path": "/rust/libstd.rlib", "sha512": "2" * 128, "method": "test link fixture"}
    runtime_component = {
        "type": "library", "bom-ref": runtime_ref, "name": "Rust standard library", "version": "1.94.1",
        "purl": runtime_ref, "licenses": [{"expression": "MIT"}],
        "externalReferences": [{"type": "website", "url": "https://www.rust-lang.org/"}],
        "properties": properties(executable=False, archive=False)
        + [{"name": "psonoci:runtime:delivery", "value": "bundled"},
           {"name": "psonoci:runtime:evidence", "value": json.dumps([proof], sort_keys=True)},
           {"name": "psonoci:runtime:imports", "value": "[]"}],
    }
    evidence = {
        "format": 1, "target": "x86_64-unknown-linux-gnu", "binarySha512": binary_hash,
        "rustc": "release: 1.94.1\ncommit-hash: " + "a" * 40 + "\n",
        "imports": [], "inputs": [{"path": proof["path"], "sha512": proof["sha512"]}],
        "cargoInputHashes": [], "components": [{
            "name": runtime_component["name"], "version": runtime_component["version"], "purl": runtime_ref,
            "creator": "https://www.rust-lang.org/", "license": "MIT", "delivery": "bundled",
            "evidence": [proof], "imports": [],
        }],
    }
    document["metadata"]["properties"].append({"name": "psonoci:sbom:runtime-evidence", "value": json.dumps(evidence)})
    document["components"].append(runtime_component)
    document["dependencies"][1]["dependsOn"].append(runtime_ref)
    document["dependencies"].append({"ref": runtime_ref, "dependsOn": []})
    return document


class DependencyGraphTests(unittest.TestCase):
    def setUp(self):
        self.tree = (FIXTURES / "cargo-tree.txt").read_text(encoding="utf-8")
        self.raw = json.loads((FIXTURES / "syft-small.cdx.json").read_text(encoding="utf-8"))
        self.graph = sbom.parse_runtime_graph(self.tree)
        self.scanned = {
            (item["name"], item["version"]): item for item in self.raw["components"]
        }

    def test_cargo_tree_builds_direct_edges(self):
        self.assertEqual(
            self.graph[("app", "1.0.0")],
            {("dep-a", "2.0.0"), ("dep-b", "4.0.0")},
        )
        self.assertEqual(self.graph[("dep-a", "2.0.0")], {("leaf", "3.0.0")})

    def test_syft_may_omit_leaf_records_and_include_build_edges(self):
        result = sbom.validate_syft_runtime_graph(
            self.raw["dependencies"], self.scanned, self.graph
        )
        self.assertNotIn("leaf-ref", result)

    def test_missing_entire_syft_graph_fails(self):
        with self.assertRaisesRegex(sbom.SbomError, "omitted runtime dependency record"):
            sbom.validate_syft_runtime_graph([], self.scanned, self.graph)

    def test_missing_runtime_edge_fails(self):
        dependencies = copy.deepcopy(self.raw["dependencies"])
        dependencies[0]["dependsOn"].remove("dep-b-ref")
        with self.assertRaisesRegex(sbom.SbomError, "dep-b"):
            sbom.validate_syft_runtime_graph(dependencies, self.scanned, self.graph)

    def test_duplicate_dependency_record_fails(self):
        dependencies = self.raw["dependencies"] * 2
        with self.assertRaisesRegex(sbom.SbomError, "duplicate dependency record"):
            sbom.validate_syft_runtime_graph(dependencies, self.scanned, self.graph)


class BinaryAndArchiveTests(unittest.TestCase):
    def test_elf_architecture_and_unsupported_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "app"
            data = bytearray(20)
            data[:4] = b"\x7fELF"
            data[18:20] = (62).to_bytes(2, "little")
            binary.write_bytes(data)
            sbom.verify_binary_target(binary, "x86_64-unknown-linux-musl")
            with self.assertRaisesRegex(sbom.SbomError, "unsupported Linux architecture"):
                sbom.verify_binary_target(binary, "riscv64gc-unknown-linux-musl")

    def test_macho_architecture(self):
        magic = b"\xcf\xfa\xed\xfe"  # MH_MAGIC_64 in little-endian byte order.
        architectures = {
            "x86_64-apple-darwin": 0x01000007,
            "aarch64-apple-darwin": 0x0100000C,
        }
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "app"

            for target, cpu_type in architectures.items():
                with self.subTest(target=target):
                    binary.write_bytes(magic + cpu_type.to_bytes(4, "little"))
                    sbom.verify_binary_target(binary, target)

            binary.write_bytes(
                magic + architectures["x86_64-apple-darwin"].to_bytes(4, "little")
            )
            with self.assertRaisesRegex(sbom.SbomError, "machine type .* does not match"):
                sbom.verify_binary_target(binary, "aarch64-apple-darwin")
            with self.assertRaisesRegex(sbom.SbomError, "unsupported Apple architecture"):
                sbom.verify_binary_target(binary, "riscv64gc-apple-darwin")

            for malformed in (b"", magic, b"\xca\xfe\xba\xbe" + b"\0" * 4):
                with self.subTest(malformed=malformed):
                    binary.write_bytes(malformed)
                    with self.assertRaisesRegex(sbom.SbomError, "not a 64-bit Mach-O"):
                        sbom.verify_binary_target(binary, "x86_64-apple-darwin")

    def test_pe_header_can_be_beyond_first_four_kibibytes(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "app.exe"
            data = bytearray(5006)
            data[:2] = b"MZ"
            data[0x3C:0x40] = (5000).to_bytes(4, "little")
            data[5000:5004] = b"PE\0\0"
            data[5004:5006] = (0x8664).to_bytes(2, "little")
            binary.write_bytes(data)
            sbom.verify_binary_target(binary, "x86_64-pc-windows-msvc")

    def test_zip_and_tar_archive_hash_members_as_streams(self):
        payload = b"release executable"
        expected = hashlib.sha512(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            zip_path = root / "app.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("nested/app", payload)
            self.assertEqual(sbom.archive_member_hashes(zip_path, "app"), [expected])

            tar_path = root / "app.tar.gz"
            with tarfile.open(tar_path, "w:gz") as archive:
                info = tarfile.TarInfo("nested/app")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            self.assertEqual(sbom.archive_member_hashes(tar_path, "app"), [expected])


class PolicyAndReleaseTests(unittest.TestCase):
    def test_policy_and_release_binding_pass(self):
        payload = bytearray(64)
        payload[:6] = b"\x7fELF\x02\x01"
        payload = bytes(payload)
        binary_hash = hashlib.sha512(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "app.tar.gz"
            with tarfile.open(artifact, "w:gz") as archive:
                info = tarfile.TarInfo("app")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            document = minimal_document(sbom.sha512(artifact), binary_hash)
            sbom.validate_document(document)
            sbom.verify_release(document, artifact)

    def test_swapped_archive_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "app.tar.gz"
            with tarfile.open(artifact, "w:gz") as archive:
                payload = b"different"
                info = tarfile.TarInfo("app")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            document = minimal_document("0" * 128, "1" * 128)
            with self.assertRaisesRegex(sbom.SbomError, "SHA-512 does not match"):
                sbom.verify_release(document, artifact)

    def test_unknown_commit_and_duplicate_graph_record_fail_policy(self):
        document = minimal_document("0" * 128, "1" * 128)
        document["components"][0]["properties"][-2]["value"] = "unknown"
        document["dependencies"].append(copy.deepcopy(document["dependencies"][0]))
        with self.assertRaises(sbom.SbomError) as raised:
            sbom.validate_document(document)
        self.assertIn("full source commit", str(raised.exception))
        self.assertIn("duplicate component records", str(raised.exception))


class ReleaseSetTests(unittest.TestCase):
    targets = ["x86_64-unknown-linux-musl", "x86_64-pc-windows-msvc"]

    def create_release_files(self, directory, suffix=".asc"):
        for target in self.targets:
            base = f"psonoci-v1.0.0-{target}"
            for name in [base + (".zip" if "windows" in target else ".tar.gz"), base + ".cdx.json"]:
                (directory / name).touch()
                (directory / (name + suffix)).touch()

    def test_complete_unix_and_windows_sets_pass_with_each_signature_format(self):
        for suffix in [".asc", ".sig"]:
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.create_release_files(root, suffix)
                sbom.validate_release_set(root, suffix, "v1.0.0", self.targets)

    def test_each_missing_file_and_entire_missing_target_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_release_files(root)
            for path in list(root.iterdir()):
                with self.subTest(missing=path.name):
                    path.unlink()
                    with self.assertRaisesRegex(sbom.SbomError, "missing release files"):
                        sbom.validate_release_set(root, ".asc", "v1.0.0", self.targets)
                    path.touch()
            for path in root.glob("*windows*"):
                path.unlink()
            with self.assertRaisesRegex(sbom.SbomError, "missing release files"):
                sbom.validate_release_set(root, ".asc", "v1.0.0", self.targets)

    def test_unsigned_extra_archive_and_other_unexpected_files_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_release_files(root)
            for name in ["orphan.tar.gz", "orphan.zip", "orphan.cdx.json", "orphan.asc", ".hidden"]:
                with self.subTest(extra=name):
                    extra = root / name
                    extra.touch()
                    with self.assertRaisesRegex(sbom.SbomError, "unexpected release files"):
                        sbom.validate_release_set(root, ".asc", "v1.0.0", self.targets)
                    extra.unlink()

    def test_wrong_archive_format_and_non_regular_entries_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_release_files(root)
            archive = root / "psonoci-v1.0.0-x86_64-pc-windows-msvc.zip"
            archive.rename(archive.with_suffix(".tar.gz"))
            with self.assertRaisesRegex(sbom.SbomError, "missing release files"):
                sbom.validate_release_set(root, ".asc", "v1.0.0", self.targets)
            archive.with_suffix(".tar.gz").rename(archive)
            archive.unlink()
            archive.mkdir()
            with self.assertRaisesRegex(sbom.SbomError, "regular files"):
                sbom.validate_release_set(root, ".asc", "v1.0.0", self.targets)

    @unittest.skipUnless(shutil.which("bash"), "requires bash")
    def test_shell_verifier_rejects_orphan_before_running_gpg(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_release_files(root)
            (root / "orphan.tar.gz").touch()
            result = subprocess.run(
                ["bash", str(ROOT / "scripts" / "verify-release-sboms.sh"),
                 str(root), ".asc", "v1.0.0", *self.targets],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected release files: orphan.tar.gz", result.stderr)


def workflow_script(name):
    lines = (ROOT / ".github" / "workflows" / "release.yml").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == f"- name: {name}")
    start = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "run: |")
    script = []
    for line in lines[start + 1:]:
        if line and not line.startswith("          "):
            break
        script.append(line[10:])
    return "\n".join(script)


@unittest.skipUnless(shutil.which("bash"), "requires bash")
class GithubReleaseTests(unittest.TestCase):
    def run_step(self, name, state, release_tag="v1.0.0"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = root / "gh"
            shutil.copy2(FIXTURES / "fake-gh.py", command)
            command.chmod(0o755)
            (root / "state.json").write_text(json.dumps(state))
            assets = root / "release-assets"
            assets.mkdir()
            (assets / "archive.tar.gz").touch()
            env = os.environ | {
                "PATH": str(root) + os.pathsep + os.environ["PATH"],
                "GH_REPO": "example/psonoci", "RELEASE_TAG": release_tag,
                "RUNNER_TEMP": str(root), "FAKE_GH_STATE": str(root / "state.json"),
            }
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", workflow_script(name)],
                cwd=root, env=env, capture_output=True, text=True, check=False,
            )
            return result, json.loads((root / "state.json").read_text())

    def test_creation_leaves_release_in_draft(self):
        result, state = self.run_step("Create draft release", {"exists": False})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(state["draft"])
        self.assertIn("--verify-tag", state["commands"][-1])
        self.assertIn("https://github.com/example/psonoci/blob/v1.0.0/SBOM.md", state["notes"])

    def test_publish_happens_after_upload_and_remote_inventory_check(self):
        result, state = self.run_step(
            "Upload validated files and publish release", {"exists": True, "draft": True}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(state["draft"])
        self.assertEqual([command[1] for command in state["commands"]], ["view", "upload", "view", "edit"])

    def test_test_tags_and_release_candidates_are_prereleases(self):
        for tag in ["release-test", "v1.0.0-rc1"]:
            with self.subTest(tag=tag):
                result, state = self.run_step(
                    "Upload validated files and publish release",
                    {"exists": True, "draft": True}, release_tag=tag,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--prerelease", state["commands"][-1])
                self.assertIn("--latest=false", state["commands"][-1])

    def test_upload_or_inventory_failures_leave_draft_unpublished(self):
        for failure in [{"fail_upload": True}, {"fail_asset_list": True}, {"assets": ["stale.zip"]}]:
            with self.subTest(failure=failure):
                result, state = self.run_step(
                    "Upload validated files and publish release",
                    {"exists": True, "draft": True, **failure},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(state["draft"])
                self.assertNotIn("edit", [command[1] for command in state["commands"]])

    def test_published_release_is_not_modified(self):
        for name in ["Create draft release", "Upload validated files and publish release"]:
            with self.subTest(step=name):
                result, state = self.run_step(name, {"exists": True, "draft": False})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([command[1] for command in state["commands"]], ["view"])


class NativeAndNormalizationTests(unittest.TestCase):
    def test_native_component_uses_locked_source_version_and_edge(self):
        metadata = {
            "packages": [
                {"id": "openssl-sys-id", "name": "openssl-sys", "version": "0.9.111"},
                {"id": "openssl-src-id", "name": "openssl-src", "version": "300.5.4+3.5.4"},
            ],
            "resolve": {"nodes": [
                {"id": "openssl-sys-id", "features": ["vendored"], "deps": [{"pkg": "openssl-src-id"}]},
                {"id": "openssl-src-id", "deps": []},
            ]},
        }
        overrides = json.loads((ROOT / "sbom" / "overrides.json").read_text(encoding="utf-8"))
        components, edges = sbom.native_components(
            metadata, {("openssl-sys", "0.9.111")}, overrides
        )
        self.assertEqual(components[0]["version"], "3.5.4")
        self.assertEqual(edges[0][0], ("openssl-sys", "0.9.111"))
        self.assertEqual(components[0]['cpe'], 'cpe:2.3:a:openssl:openssl:3.5.4:*:*:*:*:*:*:*')
        metadata['resolve']['nodes'][0]['features'] = []
        with self.assertRaisesRegex(sbom.SbomError, 'active openssl-sys vendored feature'):
            sbom.native_components(metadata, {('openssl-sys', '0.9.111')}, overrides)

    def test_license_and_purl_normalization(self):
        self.assertEqual(sbom.normalize_license("MIT/Apache-2.0"), "MIT OR Apache-2.0")
        self.assertEqual(
            sbom.purl("generic", "release", "1+2", {"target": "x86_64 linux"}),
            "pkg:generic/release@1+2?target=x86_64%20linux",
        )

    def test_evidence_serial_is_deterministic_and_content_bound(self):
        first = sbom.evidence_serial("commit", "target", "archive-hash", "timestamp")
        self.assertEqual(
            first,
            sbom.evidence_serial("commit", "target", "archive-hash", "timestamp"),
        )
        self.assertNotEqual(
            first,
            sbom.evidence_serial("commit", "target", "different-hash", "timestamp"),
        )

    def test_cross_auditable_pins_match_tool_versions(self):
        versions = dict(
            line.split("=", 1)
            for line in (ROOT / "sbom" / "tool-versions.env")
            .read_text(encoding="utf-8")
            .splitlines()
            if line and not line.startswith("#")
        )
        cross_config = (ROOT / "Cross.toml").read_text(encoding="utf-8")
        pins = set(re.findall(r'auditable_version="([^"]+)"', cross_config))
        self.assertEqual(pins, {versions["CARGO_AUDITABLE_VERSION"]})
        self.assertNotIn("${CARGO_AUDITABLE_VERSION", cross_config)

    def test_all_github_cross_targets_embed_audit_data(self):
        config = tomllib.loads((ROOT / "Cross.toml").read_text())
        for workflow in ["ci.yml", "release.yml"]:
            text = (ROOT / ".github" / "workflows" / workflow).read_text()
            targets = re.findall(r"target: (\S+)\n\s+target_type: \S+\n\s+use_cross: true", text)
            self.assertTrue(targets)
            for target in targets:
                with self.subTest(workflow=workflow, target=target):
                    commands = "\n".join(config["target"][target]["pre-build"])
                    self.assertIn(f"rustup target add {target}", commands)
                    self.assertIn('auditable "$@"', commands)

    def test_github_release_inventory_covers_the_build_matrix(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        matrix_targets = set(re.findall(r"^\s+target: (\S+)$", workflow, re.MULTILINE))
        script = workflow_script("Verify signed release evidence and validate every CycloneDX SBOM")
        targets = re.search(r"targets=\((.*?)\)", script, re.DOTALL).group(1).split()
        self.assertEqual(set(targets), matrix_targets)
        self.assertEqual(len(targets), len(matrix_targets))

    def test_gitlab_release_inventory_covers_the_packaged_targets(self):
        workflow = (ROOT / ".gitlab-ci.yml").read_text()
        policy = workflow.split("\nvalidate-release-policy:\n", 1)[1].split("\n  dependencies:", 1)[0]
        expected = re.findall(r"^      ([a-z0-9_-]+)$", policy, re.MULTILINE)
        uploader = (ROOT / "var" / "upload_artifacts.sh").read_text()
        packaged = re.search(r"TARGETS=\((.*?)\)", uploader, re.DOTALL).group(1)
        targets = re.findall(r'"([a-z0-9_-]+)"', packaged)
        self.assertEqual(set(expected), set(targets))
        self.assertEqual(len(expected), len(targets))


if __name__ == "__main__":
    unittest.main()

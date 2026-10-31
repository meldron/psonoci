#!/usr/bin/env python3
"""Turn a Syft scan of a cargo-auditable binary into psonoci release evidence.

Syft owns binary package discovery, package references, and dependency edges.
This standard-library-only adapter adds release context and the fields required
by psonoci's CRA/BSI SBOM policy. It deliberately fails when Syft and Cargo do
not describe the same runtime packages.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import uuid
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime_evidence as runtime_info  # noqa: E402


TOOL_NAME = "psonoci-sbom-adapter"
TOOL_VERSION = "3.0.0"
CDX_SCHEMA = "https://cyclonedx.org/schema/bom-1.6.schema.json"
BSI_TAXONOMY_VERSION = "0.1.2"
BSI_TR_VERSION = "2.1.0"
AUDITABLE_CATALOGER = "cargo-auditable-binary-cataloger"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
PackageKey = tuple[str, str]


class SbomError(RuntimeError):
    pass


def run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise SbomError(f"command failed: {' '.join(command)}\n{detail.strip()}") from error
    return result.stdout


def sha512(path: Path) -> str:
    with path.open("rb") as handle:
        return sha512_stream(handle)


def sha512_stream(handle: Any) -> str:
    digest = hashlib.sha512()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def verify_binary_target(path: Path, target: str) -> None:
    architecture = target.split("-", 1)[0]
    if "windows" in target:
        expected = {"x86_64": 0x8664}.get(architecture)
        if expected is None:
            raise SbomError(f"unsupported Windows architecture in target {target}")
        with path.open("rb") as handle:
            data = handle.read(64)
            if len(data) < 64 or data[:2] != b"MZ":
                raise SbomError(f"{path} is not a PE executable for {target}")
            offset = int.from_bytes(data[0x3C:0x40], "little")
            handle.seek(offset)
            pe_header = handle.read(6)
        if len(pe_header) != 6 or pe_header[:4] != b"PE\0\0":
            raise SbomError(f"{path} has an invalid PE header")
        machine = int.from_bytes(pe_header[4:6], "little")
    elif "apple" in target:
        expected = {"x86_64": 0x01000007, "aarch64": 0x0100000C}.get(architecture)
        if expected is None:
            raise SbomError(f"unsupported Apple architecture in target {target}")
        with path.open("rb") as handle:
            data = handle.read(8)
        if len(data) < 8 or data[:4] != b"\xcf\xfa\xed\xfe":
            raise SbomError(f"{path} is not a 64-bit Mach-O executable for {target}")
        machine = int.from_bytes(data[4:8], "little")
    elif "linux" in target:
        expected = {"x86_64": 62, "armv7": 40, "aarch64": 183}.get(architecture)
        if expected is None:
            raise SbomError(f"unsupported Linux architecture in target {target}")
        with path.open("rb") as handle:
            data = handle.read(20)
        if len(data) < 20 or data[:4] != b"\x7fELF":
            raise SbomError(f"{path} is not an ELF executable for {target}")
        machine = int.from_bytes(data[18:20], "little")
    else:
        raise SbomError(f"unsupported target operating system in {target}")
    if machine != expected:
        raise SbomError(
            f"{path} machine type {machine:#x} does not match {target} ({expected:#x})"
        )


def archive_member_hashes(artifact: Path, filename: str) -> list[str]:
    hashes: list[str] = []
    if artifact.suffix == ".zip":
        with zipfile.ZipFile(artifact) as archive:
            for name in archive.namelist():
                if Path(name).name == filename and not name.endswith("/"):
                    with archive.open(name) as handle:
                        hashes.append(sha512_stream(handle))
    elif artifact.name.endswith(".tar.gz"):
        with tarfile.open(artifact, "r:gz") as archive:
            for member in archive.getmembers():
                if member.isfile() and Path(member.name).name == filename:
                    handle = archive.extractfile(member)
                    if handle:
                        with handle:
                            hashes.append(sha512_stream(handle))
    else:
        raise SbomError(f"unsupported release archive format: {artifact}")
    return hashes


def artifact_mime_type(artifact: Path) -> str:
    if artifact.suffix == ".zip":
        return "application/zip"
    if artifact.name.endswith(".tar.gz"):
        return "application/gzip"
    raise SbomError(f"unsupported release archive format: {artifact}")


def evidence_serial(*identity: str) -> str:
    value = uuid.uuid5(uuid.NAMESPACE_URL, "\n".join(identity))
    return f"urn:uuid:{value}"


def verify_archive(artifact: Path, binary: Path) -> None:
    if archive_member_hashes(artifact, binary.name) != [sha512(binary)]:
        raise SbomError(f"{artifact} must contain exactly the supplied {binary.name}")


def cargo_metadata(manifest: Path, target: str) -> dict[str, Any]:
    return json.loads(
        run(
            [
                "cargo", "metadata", "--locked", "--filter-platform", target,
                "--format-version", "1", "--manifest-path", str(manifest),
            ]
        )
    )


def parse_runtime_graph(output: str) -> dict[PackageKey, set[PackageKey]]:
    """Parse Cargo's depth-prefixed tree into the expected runtime graph."""
    graph: dict[PackageKey, set[PackageKey]] = {}
    stack: list[PackageKey] = []
    pattern = re.compile(r"^(\d+)\|(\S+) v(\S+)(?: .*)?$")
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            raise SbomError(f"cannot parse cargo tree line: {line!r}")
        depth = int(match.group(1))
        package = (match.group(2), match.group(3))
        if depth > len(stack):
            raise SbomError(f"invalid depth in cargo tree line: {line!r}")
        graph.setdefault(package, set())
        if depth:
            graph.setdefault(stack[depth - 1], set()).add(package)
        stack[depth:] = [package]
    if not graph:
        raise SbomError("cargo tree returned an empty runtime dependency graph")
    return graph


def runtime_graph(manifest: Path, target: str) -> dict[PackageKey, set[PackageKey]]:
    """Use Cargo to define runtime packages and the minimum expected edges."""
    return parse_runtime_graph(run(
        [
            "cargo", "tree", "--locked", "--target", target, "--edges",
            "normal,no-proc-macro", "--no-dedupe", "--prefix", "depth",
            "--format", "|{p}", "--manifest-path", str(manifest),
        ]
    ))


def validate_syft_runtime_graph(
    raw_dependencies: Any,
    scanned: dict[PackageKey, dict[str, Any]],
    expected: dict[PackageKey, set[PackageKey]],
) -> dict[str, list[str]]:
    """Require Syft to retain every runtime edge reported by Cargo.

    Syft may omit records for leaves and may expose additional edges recovered
    from the compiled binary, so expected Cargo edges are a required subset.
    """
    if not isinstance(raw_dependencies, list):
        raise SbomError("Syft dependencies must be an array")
    dependencies: dict[str, list[str]] = {}
    for item in raw_dependencies:
        if not isinstance(item, dict) or not isinstance(item.get("ref"), str):
            raise SbomError("Syft dependency records require a string ref")
        children = item.get("dependsOn", [])
        if not isinstance(children, list) or not all(isinstance(child, str) for child in children):
            raise SbomError(f"Syft dependency record {item['ref']} has invalid dependsOn")
        if item["ref"] in dependencies:
            raise SbomError(f"Syft returned duplicate dependency record {item['ref']}")
        dependencies[item["ref"]] = children

    ref_to_key = {component["bom-ref"]: key for key, component in scanned.items()}
    for parent, expected_children in expected.items():
        if not expected_children:
            continue
        parent_ref = scanned[parent]["bom-ref"]
        if parent_ref not in dependencies:
            raise SbomError(f"Syft omitted runtime dependency record for {parent[0]} {parent[1]}")
        actual_children = {
            ref_to_key[child]
            for child in dependencies[parent_ref]
            if child in ref_to_key
        }
        if missing := sorted(expected_children - actual_children):
            raise SbomError(
                f"Syft omitted runtime dependencies of {parent[0]} {parent[1]}: {missing}"
            )
    return dependencies


def normalize_license(value: str | None) -> str:
    normalized = " ".join((value or "").split())
    return {
        "MIT/Apache-2.0": "MIT OR Apache-2.0",
        "Apache-2.0/MIT": "Apache-2.0 OR MIT",
        "Apache-2.0 / MIT": "Apache-2.0 OR MIT",
    }.get(normalized, normalized)


def author(value: str) -> dict[str, str]:
    match = re.match(r"^\s*(.*?)\s*<([^<>]+)>\s*$", value)
    if match and EMAIL_RE.match(match.group(2)):
        return {key: val for key, val in (("name", match.group(1)), ("email", match.group(2))) if val}
    return {"name": value.strip()}


def purl(kind: str, name: str, version: str, qualifiers: dict[str, str] | None = None) -> str:
    result = f"pkg:{kind}/{quote(name, safe='._-~')}@{quote(version, safe='._-~+')}"
    if qualifiers:
        result += "?" + "&".join(
            f"{quote(key, safe='._-~')}={quote(value, safe='._-~')}"
            for key, value in sorted(qualifiers.items())
        )
    return result


def references(repository: str | None, homepage: str | None, distribution: str | None = None) -> list[dict[str, str]]:
    values = [("vcs", repository), ("website", homepage), ("distribution", distribution)]
    return [{"type": kind, "url": url} for kind, url in dict.fromkeys(values) if url]


def bsi_properties(*, executable: bool, archive: bool, structured: bool, license_id: str, filename: str | None = None) -> list[dict[str, str]]:
    result = [
        {"name": "bsi:component:executable", "value": "executable" if executable else "non-executable"},
        {"name": "bsi:component:archive", "value": "archive" if archive else "no archive"},
        {"name": "bsi:component:structured", "value": "structured" if structured else "unstructured"},
        {"name": "bsi:component:effectiveLicence", "value": license_id},
    ]
    if filename:
        result.append({"name": "bsi:component:filename", "value": filename})
    return result


def found_by_auditable(component: dict[str, Any]) -> bool:
    return any(
        item.get("name") == "syft:package:foundBy" and item.get("value") == AUDITABLE_CATALOGER
        for item in component.get("properties", [])
    )


def package_component(syft_component: dict[str, Any], package: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    license_id = normalize_license(override.get("license", package.get("license")))
    repository = override.get("repository", package.get("repository"))
    homepage = override.get("creator_url", package.get("homepage"))
    authors = [author(item) for item in package.get("authors", []) if item.strip()]
    if not license_id:
        raise SbomError(f"{package['name']} {package['version']} has no SPDX license")
    if not any(item.get("email") for item in authors) and not (repository or homepage):
        raise SbomError(f"{package['name']} {package['version']} has no creator identity")
    component: dict[str, Any] = {
        "type": "library", "bom-ref": syft_component["bom-ref"],
        "name": package["name"], "version": package["version"], "scope": "required",
        "licenses": [{"expression": license_id}], "purl": syft_component["purl"],
        "properties": bsi_properties(
            executable=False, archive=False, structured=False, license_id=license_id
        ) + [{"name": "psonoci:sbom:found-by", "value": f"syft:{AUDITABLE_CATALOGER}"}],
    }
    if package.get("description"):
        component["description"] = package["description"].strip()
    if authors:
        component["authors"] = authors
    if refs := references(repository, homepage):
        component["externalReferences"] = refs
    return component


def native_components(
    metadata: dict[str, Any], runtime: set[PackageKey], overrides: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[tuple[PackageKey, str]]]:
    packages = {item["id"]: item for item in metadata["packages"]}
    nodes = {item["id"]: item for item in metadata["resolve"]["nodes"]}
    runtime_ids = {
        (item["name"], item["version"]): package_id
        for package_id, item in packages.items()
        if (item["name"], item["version"]) in runtime
    }
    components: list[dict[str, Any]] = []
    edges: list[tuple[PackageKey, str]] = []
    for native in overrides.get("native_components", []):
        trigger = next((key for key in runtime_ids if key[0] == native["trigger_package"]), None)
        if not trigger:
            continue
        source = next(
            (packages[dep["pkg"]] for dep in nodes[runtime_ids[trigger]].get("deps", [])
             if packages[dep["pkg"]]["name"] == native["source_package"]),
            None,
        )
        if not source:
            raise SbomError(f"cannot resolve source for native component {native['name']}")
        if native.get("version_from_cargo_build_metadata") and "+" not in source["version"]:
            raise SbomError(f"cannot derive {native['name']} version from {source['version']}")
        version = source["version"].split("+", 1)[-1]
        license_id = normalize_license(native.get("license"))
        ref = purl(native.get("purl_type", "generic"), native["name"].lower(), version)
        components.append(
            {
                "type": "library", "bom-ref": ref, "name": native["name"],
                "version": version, "scope": "required", "purl": ref,
                "description": native["description"],
                "licenses": [{"expression": license_id}],
                "externalReferences": references(native.get("repository"), native.get("creator_url")),
                "properties": bsi_properties(
                    executable=False, archive=False, structured=False, license_id=license_id
                ),
            }
        )
        edges.append((trigger, ref))
    return components, edges


def runtime_licenses(item: dict[str, Any]) -> list[dict[str, Any]]:
    if item.get('licenseText'):
        return [{"license": {"name": item['license'], "text": {"contentType": "text/plain", "content": item['licenseText']}}}]
    return [{"expression": item['license']}]


def _generate(args: argparse.Namespace) -> dict[str, Any]:
    paths = [args.manifest_path, args.binary, args.artifact, args.syft_input, args.overrides]
    if missing := [str(path) for path in paths if not path.is_file()]:
        raise SbomError(f"missing inputs: {', '.join(missing)}")
    if not COMMIT_RE.fullmatch(args.commit):
        raise SbomError("commit must be a full hexadecimal Git object ID")
    if not args.cargo_auditable_version.strip():
        raise SbomError("cargo-auditable version is required")
    verify_binary_target(args.binary, args.target)
    verify_archive(args.artifact, args.binary)
    evidence_path = args.runtime_evidence or args.binary.with_name("psonoci.runtime.json")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    runtime_info.validate_evidence(evidence, sha512(args.binary), args.target, runtime_info.imports(args.binary.read_bytes()))

    raw = json.loads(args.syft_input.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise SbomError("Syft input must be a JSON object")
    if raw.get("bomFormat") != "CycloneDX" or raw.get("specVersion") != "1.6":
        raise SbomError("Syft input must be CycloneDX 1.6 JSON")
    syft_tools = raw.get("metadata", {}).get("tools", {}).get("components", [])
    if not any(item.get("name") == "syft" for item in syft_tools):
        raise SbomError("input does not identify Syft as its generator")

    metadata = cargo_metadata(args.manifest_path, args.target)
    expected_graph = runtime_graph(args.manifest_path, args.target)
    runtime = set(expected_graph)
    if evidence.get('cargoNativeInputs'):
        import tomllib
        lock = tomllib.loads((args.manifest_path.parent / 'Cargo.lock').read_text())
        checksums = {(item['name'], item['version']): item.get('checksum') for item in lock['package']}
    for item in evidence.get('cargoNativeInputs', []):
        if (item['package'], item['version']) not in runtime:
            raise SbomError('native Cargo input is not covered by the runtime dependency graph')
        if checksums.get((item['package'], item['version'])) != item['registryPackageSha256']:
            raise SbomError('native Cargo input does not match the locked registry package checksum')
    cargo_names = {
        target["name"].replace("-", "_")
        for package in metadata["packages"] if (package["name"], package["version"]) in runtime
        for target in package.get("targets", []) if set(target.get("kind", [])) & {"lib", "rlib"}
    }
    for item in evidence["inputs"]:
        if item["sha512"] in evidence["cargoInputHashes"]:
            filename = Path(item["path"]).name
            match = re.fullmatch(r"lib(.+)-[0-9a-f]+\.rlib", filename)
            if not match or match[1] not in cargo_names:
                raise SbomError(f"linked Rust archive is not covered by the Cargo runtime graph: {filename}")
    packages: dict[PackageKey, dict[str, Any]] = {}
    for package in metadata["packages"]:
        key = (package["name"], package["version"])
        if key in packages and key in runtime:
            raise SbomError(f"ambiguous Cargo package identity {key}")
        packages[key] = package
    root = next(item for item in metadata["packages"] if item["id"] == metadata["resolve"]["root"])
    if args.release_version and args.release_version.removeprefix("v") != root["version"]:
        raise SbomError(f"release version does not match Cargo package version {root['version']}")
    overrides = json.loads(args.overrides.read_text(encoding="utf-8"))

    scanned: dict[PackageKey, dict[str, Any]] = {}
    raw_components = raw.get("components", [])
    if not isinstance(raw_components, list):
        raise SbomError("Syft components must be an array")
    for component in raw_components:
        if not isinstance(component, dict):
            raise SbomError("Syft components must contain objects")
        key = (component.get("name", ""), component.get("version", ""))
        if key in runtime and found_by_auditable(component):
            if key in scanned:
                raise SbomError(f"Syft returned duplicate cargo-auditable component {key}")
            scanned[key] = component
    if missing := sorted(runtime - scanned.keys()):
        raise SbomError(f"Syft did not recover runtime packages from the binary: {missing}")
    if missing := sorted(runtime - packages.keys()):
        raise SbomError(f"Cargo metadata is missing runtime packages: {missing}")
    raw_dependencies = validate_syft_runtime_graph(
        raw.get("dependencies"), scanned, expected_graph
    )

    root_key = (root["name"], root["version"])
    package_overrides = overrides.get("packages", {})
    components = [
        package_component(scanned[key], packages[key], package_overrides.get(key[0], {}))
        for key in sorted(runtime - {root_key})
    ]
    extra_components, native_edges = native_components(metadata, runtime, overrides)
    components.extend(extra_components)
    runtime_components = []
    for item in evidence["components"]:
        component = {
            "type": "library", "bom-ref": item["purl"], "name": item["name"],
            "version": item["version"], "scope": "required", "purl": item["purl"],
            "externalReferences": references(item.get("source"), item["creator"]),
            "properties": [
                {"name": "psonoci:runtime:delivery", "value": item["delivery"]},
                {"name": "psonoci:runtime:evidence", "value": json.dumps(item["evidence"], sort_keys=True)},
                {"name": "psonoci:runtime:imports", "value": json.dumps(item["imports"], sort_keys=True)},
            ],
        }
        if item.get("versionContext"):
            component["properties"].append({"name": "psonoci:runtime:version-context", "value": item["versionContext"]})
        if item.get("license"):
            component["licenses"] = runtime_licenses(item)
        if item["delivery"] == "bundled":
            component["properties"] += bsi_properties(executable=False, archive=False, structured=False, license_id=item["license"])
        runtime_components.append(component)
    components.extend(runtime_components)

    root_license = normalize_license(root.get("license"))
    root_authors = [author(item) for item in root.get("authors", []) if item.strip()]
    binary_ref = purl("generic", root["name"], root["version"], {"target": args.target})
    archive_ref = purl("generic", f"{root['name']}-release", root["version"], {"target": args.target})
    binary_hash = sha512(args.binary)
    archive_hash = sha512(args.artifact)
    binary_component = {
        "type": "application", "bom-ref": binary_ref, "name": root["name"],
        "version": root["version"], "scope": "required", "authors": root_authors,
        "description": root.get("description", ""), "purl": binary_ref,
        "hashes": [{"alg": "SHA-512", "content": binary_hash}],
        "licenses": [{"expression": root_license}],
        "externalReferences": references(root.get("repository"), root.get("homepage")),
        "properties": bsi_properties(
            executable=True, archive=False, structured=False,
            license_id=root_license, filename=args.binary.name,
        ) + [
            {"name": "psonoci:sbom:found-by", "value": f"syft:{AUDITABLE_CATALOGER}"},
            {"name": "psonoci:release:target", "value": args.target},
            {"name": "psonoci:release:commit", "value": args.commit.lower()},
        ],
    }
    components.append(binary_component)
    archive_component = {
        "type": "file", "bom-ref": archive_ref, "name": args.artifact.name,
        "version": root["version"], "mime-type": artifact_mime_type(args.artifact),
        "authors": root_authors, "description": f"psonoci release archive for {args.target}",
        "hashes": [{"alg": "SHA-512", "content": archive_hash}],
        "licenses": [{"expression": root_license}], "purl": archive_ref,
        "externalReferences": references(root.get("repository"), root.get("homepage"), args.artifact_url),
        "properties": bsi_properties(
            executable=False, archive=True, structured=True,
            license_id=root_license, filename=args.artifact.name,
        ) + [{"name": "psonoci:release:target", "value": args.target}],
    }

    ref_map = {
        scanned[key]["bom-ref"]: (
            binary_ref if key == root_key else scanned[key]["bom-ref"]
        )
        for key in runtime
    }
    dependencies: dict[str, set[str]] = {archive_ref: {binary_ref}}
    dependencies.update({ref: set() for ref in ref_map.values()})
    for old_ref, new_ref in ref_map.items():
        dependencies[new_ref].update(ref_map[child] for child in raw_dependencies.get(old_ref, []) if child in ref_map)
    component_ref_by_key = {key: ref_map[scanned[key]["bom-ref"]] for key in runtime}
    for trigger, native_ref in native_edges:
        dependencies[component_ref_by_key[trigger]].add(native_ref)
        dependencies[native_ref] = set()
    for component in runtime_components:
        dependencies[binary_ref].add(component["bom-ref"])
        dependencies[component["bom-ref"]] = set()

    now = (
        dt.datetime.fromtimestamp(int(os.environ["SOURCE_DATE_EPOCH"]), dt.timezone.utc)
        if "SOURCE_DATE_EPOCH" in os.environ
        else dt.datetime.now(dt.timezone.utc)
    )
    timestamp = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    metadata_properties = [
        {"name": "psonoci:sbom:profile", "value": "CRA / BSI TR-03183-2"},
        {"name": "psonoci:sbom:bsi-tr-version", "value": BSI_TR_VERSION},
        {"name": "psonoci:sbom:bsi-taxonomy-version", "value": BSI_TAXONOMY_VERSION},
        {"name": "psonoci:sbom:dependency-graph", "value": "cargo-runtime-edges-verified-against-syft"},
        {
            "name": "psonoci:sbom:boundary",
            "value": "release archive and identified direct external runtimes; external runtime dependency subgraphs are not resolved",
        },
        {"name": "psonoci:sbom:runtime-evidence", "value": json.dumps(evidence, sort_keys=True, separators=(",", ":"))},
    ]
    bom = {
        "$schema": CDX_SCHEMA, "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": evidence_serial(
            args.commit.lower(), args.target, root["version"],
            binary_hash, archive_hash, timestamp,
            hashlib.sha512(json.dumps(evidence, sort_keys=True).encode()).hexdigest(),
        ), "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "lifecycles": [{"phase": "post-build"}],
            "tools": {"components": syft_tools + [
                {"type": "application", "name": "cargo-auditable", "version": args.cargo_auditable_version},
                {"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION},
            ]},
            "authors": [{"name": "Psono SBOM automation", "email": "psonoci@dfjk.eu"}],
            "component": archive_component,
            "properties": metadata_properties,
        },
        "components": sorted(components, key=lambda item: item["bom-ref"]),
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(children)}
            for ref, children in sorted(dependencies.items())
        ],
        "compositions": [{
            "aggregate": "incomplete", "assemblies": [archive_ref],
            "dependencies": sorted(item["bom-ref"] for item in components if item["bom-ref"] != binary_ref),
        }],
    }
    validate_document(bom)
    return bom


def generate(args: argparse.Namespace) -> dict[str, Any]:
    try:
        return _generate(args)
    except (AttributeError, IndexError, KeyError, StopIteration, TypeError) as error:
        raise SbomError(f"malformed Syft, Cargo, or override data: {error}") from error


def property_values(component: dict[str, Any], name: str) -> list[str]:
    return [item.get("value", "") for item in component.get("properties", []) if item.get("name") == name]


def metadata_property_values(metadata: dict[str, Any], name: str) -> list[str]:
    return [item.get("value", "") for item in metadata.get("properties", []) if item.get("name") == name]


def component_sha512(component: dict[str, Any], label: str) -> str:
    values = [item.get("content") for item in component.get("hashes", []) if item.get("alg") == "SHA-512"]
    if len(values) != 1 or not isinstance(values[0], str):
        raise SbomError(f"{label} must contain exactly one SHA-512 hash")
    return values[0]


def validate_document(bom: dict[str, Any]) -> None:
    errors: list[str] = []
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        errors.append("document must be CycloneDX 1.6")
    if "vulnerabilities" in bom:
        errors.append("publish vulnerabilities separately as VEX or CSAF")
    metadata = bom.get("metadata", {})
    if not metadata.get("timestamp") or not metadata.get("authors"):
        errors.append("metadata timestamp and author are required")
    tools = metadata.get("tools", {}).get("components", [])
    tool_names = {item.get("name") for item in tools}
    if not {"syft", "cargo-auditable", TOOL_NAME}.issubset(tool_names):
        errors.append("Syft, cargo-auditable, and the compliance adapter must be identified")
    for name in ("syft", "cargo-auditable", TOOL_NAME):
        if not any(item.get("name") == name and item.get("version") for item in tools):
            errors.append(f"{name} requires an exact version")
    if metadata_property_values(metadata, "psonoci:sbom:dependency-graph") != [
        "cargo-runtime-edges-verified-against-syft"
    ]:
        errors.append("runtime dependency graph verification evidence is required")

    primary = metadata.get("component")
    components = ([primary] if primary else []) + bom.get("components", [])
    refs: set[str] = set()
    executable_count = 0
    for component in components:
        label = f"{component.get('name', '<unnamed>')} {component.get('version', '<unversioned>')}"
        ref = component.get("bom-ref")
        if not ref or ref in refs:
            errors.append(f"{label}: missing or duplicate bom-ref")
        refs.add(ref)
        if not component.get("name") or not component.get("version"):
            errors.append(f"{label}: exact name and version are required")
        external_runtime = property_values(component, "psonoci:runtime:delivery") == ["external"]
        text_runtime_license = property_values(component, "psonoci:runtime:delivery") == ["bundled"] and all(
            item.get('license', {}).get('name', '').startswith('LicenseRef-') and
            item.get('license', {}).get('text', {}).get('contentType') == 'text/plain' and
            item.get('license', {}).get('text', {}).get('content') for item in component.get('licenses', [])
        )
        if not external_runtime and (not component.get("licenses") or not (text_runtime_license or all(item.get("expression") for item in component.get("licenses", [])))):
            errors.append(f"{label}: SPDX license expression is required")
        creator = any(item.get("email") for item in component.get("authors", [])) or any(
            item.get("type") in {"vcs", "website"} and item.get("url")
            for item in component.get("externalReferences", [])
        )
        if not creator:
            errors.append(f"{label}: creator identity is required")
        if external_runtime:
            if not component.get("purl"):
                errors.append(f"{label}: external runtime identity requires a PURL")
            continue
        allowed_properties = {
            "bsi:component:executable": {"executable", "non-executable"},
            "bsi:component:archive": {"archive", "no archive"},
            "bsi:component:structured": {"structured", "unstructured"},
            "bsi:component:effectiveLicence": None,
        }
        for name, allowed in allowed_properties.items():
            values = property_values(component, name)
            if len(values) != 1:
                errors.append(f"{label}: {name} must occur exactly once")
            elif allowed is not None and values[0] not in allowed:
                errors.append(f"{label}: invalid {name} value {values[0]!r}")
        if property_values(component, "bsi:component:executable") == ["executable"]:
            executable_count += 1
            if "SHA-512" not in {item.get("alg") for item in component.get("hashes", [])}:
                errors.append(f"{label}: executable requires SHA-512")
            if not property_values(component, "bsi:component:filename"):
                errors.append(f"{label}: executable requires its filename")
            commits = property_values(component, "psonoci:release:commit")
            if len(commits) != 1 or not COMMIT_RE.fullmatch(commits[0]):
                errors.append(f"{label}: full source commit is required")
            targets = property_values(component, "psonoci:release:target")
            if len(targets) != 1:
                errors.append(f"{label}: exactly one release target is required")
    if executable_count != 1:
        errors.append("exactly one delivered executable is required")
    else:
        executable = next(c for c in components if property_values(c, "bsi:component:executable") == ["executable"])
        evidence_values = metadata_property_values(metadata, "psonoci:sbom:runtime-evidence")
        if len(evidence_values) != 1:
            errors.append("exactly one runtime evidence record is required")
        else:
            try:
                evidence = json.loads(evidence_values[0])
                runtime_info.validate_evidence(evidence, component_sha512(executable, "executable"),
                                          property_values(executable, "psonoci:release:target")[0], evidence["imports"])
                runtime_by_ref = {c["bom-ref"]: c for c in components if property_values(c, "psonoci:runtime:delivery")}
                if set(runtime_by_ref) != {c["purl"] for c in evidence["components"]}:
                    raise runtime_info.EvidenceError("runtime components do not match the evidence inventory")
                graph = {d["ref"]: d.get("dependsOn", []) for d in bom.get("dependencies", [])}
                for item in evidence["components"]:
                    recorded = runtime_by_ref[item["purl"]]
                    if (recorded.get("name"), recorded.get("version"), recorded.get("purl")) != (item["name"], item["version"], item["purl"]):
                        raise runtime_info.EvidenceError("runtime component identity differs from its evidence")
                    if property_values(recorded, "psonoci:runtime:delivery") != [item["delivery"]]:
                        raise runtime_info.EvidenceError("runtime delivery classification differs from its evidence")
                    if not any(ref.get("type") == "website" and ref.get("url") == item["creator"] for ref in recorded.get("externalReferences", [])):
                        raise runtime_info.EvidenceError("runtime creator differs from its evidence")
                    if property_values(recorded, "psonoci:runtime:evidence") != [json.dumps(item["evidence"], sort_keys=True)]:
                        raise runtime_info.EvidenceError("runtime component proof differs from its evidence")
                    if property_values(recorded, "psonoci:runtime:imports") != [json.dumps(item["imports"], sort_keys=True)]:
                        raise runtime_info.EvidenceError("runtime component imports differ from its evidence")
                    if item.get("license") and recorded.get("licenses") != runtime_licenses(item):
                        raise runtime_info.EvidenceError("runtime licensing differs from its evidence")
                    if item["purl"] not in graph.get(executable["bom-ref"], []):
                        raise runtime_info.EvidenceError("runtime component is disconnected from the executable")
            except (runtime_info.EvidenceError, ValueError, KeyError, IndexError, TypeError) as error:
                errors.append(f"runtime evidence validation failed: {error}")
    if not primary or property_values(primary, "bsi:component:archive") != ["archive"]:
        errors.append("the release archive must be the metadata component")
    elif "SHA-512" not in {item.get("alg") for item in primary.get("hashes", [])}:
        errors.append("release archive requires SHA-512")
    elif not property_values(primary, "bsi:component:filename"):
        errors.append("release archive requires its filename")

    graph_ref_list = [item.get("ref") for item in bom.get("dependencies", [])]
    graph_refs = set(graph_ref_list)
    if graph_refs != refs:
        errors.append("dependency graph must contain every component exactly once")
    if len(graph_ref_list) != len(graph_refs):
        errors.append("dependency graph contains duplicate component records")
    for item in bom.get("dependencies", []):
        if set(item.get("dependsOn", [])) - refs:
            errors.append(f"{item.get('ref')}: dependency graph has dangling references")
    if not bom.get("compositions"):
        errors.append("dependency completeness must be declared")
    if errors:
        raise SbomError("SBOM policy validation failed:\n- " + "\n- ".join(errors))


def verify_release(bom: dict[str, Any], artifact: Path) -> None:
    """Re-bind a staged archive to its validated SBOM before publication."""
    validate_document(bom)
    primary = bom["metadata"]["component"]
    archive_names = property_values(primary, "bsi:component:filename")
    if archive_names != [artifact.name]:
        raise SbomError(
            f"SBOM archive filename {archive_names!r} does not match {artifact.name}"
        )
    if sha512(artifact) != component_sha512(primary, "release archive"):
        raise SbomError(f"{artifact} SHA-512 does not match the SBOM")

    executables = [
        component
        for component in bom.get("components", [])
        if property_values(component, "bsi:component:executable") == ["executable"]
    ]
    if len(executables) != 1:
        raise SbomError("SBOM must describe exactly one delivered executable")
    executable = executables[0]
    filenames = property_values(executable, "bsi:component:filename")
    if len(filenames) != 1:
        raise SbomError("executable must have exactly one filename")
    expected_hash = component_sha512(executable, "release executable")
    if archive_member_hashes(artifact, filenames[0]) != [expected_hash]:
        raise SbomError(
            f"{artifact} must contain exactly the SBOM executable {filenames[0]}"
        )
    if artifact.suffix == ".zip":
        with zipfile.ZipFile(artifact) as archive:
            binary = archive.read(next(name for name in archive.namelist() if Path(name).name == filenames[0]))
    else:
        with tarfile.open(artifact, "r:gz") as archive:
            member = next(member for member in archive.getmembers() if member.isfile() and Path(member.name).name == filenames[0])
            binary = archive.extractfile(member).read()
    evidence = json.loads(metadata_property_values(bom["metadata"], "psonoci:sbom:runtime-evidence")[0])
    runtime_info.validate_evidence(evidence, expected_hash, property_values(executable, "psonoci:release:target")[0], runtime_info.imports(binary))


def validate_release_set(
    directory: Path, signature_suffix: str, release_tag: str, targets: list[str]
) -> None:
    """Require all four release files for every target, with no extra entries."""
    if signature_suffix not in {".asc", ".sig"}:
        raise SbomError("signature suffix must be .asc or .sig")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", release_tag):
        raise SbomError("release tag must be a filename-safe identifier")
    if not targets or len(targets) != len(set(targets)):
        raise SbomError("expected release targets must be nonempty and unique")
    expected: set[str] = set()
    for target in targets:
        if not re.fullmatch(r"[a-z0-9_]+(?:-[a-z0-9_]+)+", target):
            raise SbomError(f"invalid release target: {target!r}")
        base = f"psonoci-{release_tag}-{target}"
        archive = base + (".zip" if "windows" in target else ".tar.gz")
        sbom = base + ".cdx.json"
        expected.update((archive, archive + signature_suffix, sbom, sbom + signature_suffix))

    entries = list(directory.iterdir())
    invalid = sorted(item.name for item in entries if item.is_symlink() or not item.is_file())
    actual = {item.name for item in entries}
    errors = []
    if missing := sorted(expected - actual):
        errors.append(f"missing release files: {', '.join(missing)}")
    if unexpected := sorted(actual - expected):
        errors.append(f"unexpected release files: {', '.join(unexpected)}")
    if invalid:
        errors.append(f"release entries must be regular files: {', '.join(invalid)}")
    if errors:
        raise SbomError("release asset set validation failed:\n- " + "\n- ".join(errors))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate_parser = commands.add_parser("generate", help="enrich a Syft scan and apply policy")
    generate_parser.add_argument("--target", required=True)
    for option in ("binary", "artifact", "syft-input", "output"):
        generate_parser.add_argument(f"--{option}", required=True, type=Path)
    generate_parser.add_argument("--artifact-url")
    generate_parser.add_argument("--commit", required=True)
    generate_parser.add_argument("--cargo-auditable-version", required=True)
    generate_parser.add_argument("--runtime-evidence", type=Path, help="hash-bound link/runtime inventory; defaults beside the executable")
    generate_parser.add_argument("--release-version")
    generate_parser.add_argument("--manifest-path", type=Path, default=Path("Cargo.toml"))
    generate_parser.add_argument("--overrides", type=Path, default=Path("sbom/overrides.json"))
    validate_parser = commands.add_parser("validate", help="apply psonoci's CRA/BSI policy")
    validate_parser.add_argument("--input", required=True, type=Path)
    verify_parser = commands.add_parser(
        "verify-release", help="validate policy and bind a staged archive to its SBOM"
    )
    verify_parser.add_argument("--input", required=True, type=Path)
    verify_parser.add_argument("--artifact", required=True, type=Path)
    set_parser = commands.add_parser(
        "validate-release-set", help="require the exact release files for all expected targets"
    )
    set_parser.add_argument("--directory", required=True, type=Path)
    set_parser.add_argument("--signature-suffix", required=True, choices=(".asc", ".sig"))
    set_parser.add_argument("--release-tag", required=True)
    set_parser.add_argument("--targets", required=True, nargs="+")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "generate":
            bom = generate(args)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
            print(f"wrote {args.output}: {len(bom['components'])} components")
        elif args.command == "validate":
            validate_document(json.loads(args.input.read_text(encoding="utf-8")))
            print(f"validated {args.input}: psonoci CRA/BSI policy passed")
        elif args.command == "verify-release":
            verify_release(json.loads(args.input.read_text(encoding="utf-8")), args.artifact)
            print(f"verified {args.artifact}: archive and SBOM evidence match")
        else:
            validate_release_set(
                args.directory, args.signature_suffix, args.release_tag, args.targets
            )
            print(f"validated {args.directory}: complete release files for {len(args.targets)} targets")
    except (
        OSError, OverflowError, ValueError, SbomError, runtime_info.EvidenceError, tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (AttributeError, IndexError, KeyError, StopIteration, TypeError) as error:
        print(f"error: malformed SBOM input: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

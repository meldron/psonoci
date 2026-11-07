#!/usr/bin/env python3
"""Publish verified prerelease files to GitLab, then expose their release links."""

import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from sbom import validate_release_set

TARGETS = [
    "x86_64-unknown-linux-musl", "armv7-unknown-linux-gnueabihf",
    "armv7-unknown-linux-musleabihf",
    "aarch64-unknown-linux-musl", "x86_64-apple-darwin", "aarch64-apple-darwin",
    "x86_64-pc-windows-gnu", "x86_64-pc-windows-msvc",
]
PRERELEASE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.(0|[1-9][0-9]*)")


class GitLab:
    def __init__(self, environment):
        api = environment["CI_API_V4_URL"].rstrip("/")
        if urlparse(api).scheme != "https":
            raise ValueError("GitLab API must use HTTPS")
        self.base = f"{api}/projects/{quote(environment['CI_PROJECT_ID'], safe='')}"
        self.token = environment["CI_JOB_TOKEN"]

    def request(self, method, path, data=None, content_type="application/octet-stream"):
        request = Request(self.base + path, data=data, method=method, headers={
            "JOB-TOKEN": self.token, "Content-Type": content_type,
        })
        try:
            with urlopen(request, timeout=120) as response:
                return response.read()
        except HTTPError as error:
            if method == "GET" and error.code == 404:
                return None
            # Do not include request headers or credentials in failure output.
            raise RuntimeError(f"GitLab {method} {path} failed: HTTP {error.code}") from None


def publish(client, environment, directory, changelog):
    tag = environment["CI_COMMIT_TAG"]
    if not PRERELEASE.fullmatch(tag):
        raise ValueError("Expected vX.Y.Z-alpha.N, vX.Y.Z-beta.N or vX.Y.Z-rc.N")
    if environment.get("CI_COMMIT_REF_PROTECTED") != "true":
        raise ValueError("Prerelease tag must be protected")
    if "GOOGLE_APPLICATION_CREDENTIALS" in environment:
        raise ValueError("Prereleases must not receive production upload credentials")
    commit = environment["CI_COMMIT_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Expected the full source commit SHA")
    validate_release_set(directory, ".sig", tag, TARGETS)
    release_path = f"/releases/{quote(tag, safe='')}"
    if client.request("GET", release_path) is not None:
        raise ValueError("Refusing to replace an already published release")

    package = f"/packages/generic/psonoci/{quote(tag, safe='')}"
    links = []
    for artifact in sorted(directory.iterdir()):
        path = f"{package}/{quote(artifact.name, safe='')}"
        data = artifact.read_bytes()
        existing = client.request("GET", path)
        if existing is None:
            client.request("PUT", path, data)
            existing = client.request("GET", path)
        if existing is None or hashlib.sha512(existing).digest() != hashlib.sha512(data).digest():
            raise ValueError(f"Remote package differs from validated file: {artifact.name}")
        links.append({"name": artifact.name, "url": client.base + path,
                      "direct_asset_path": "/" + artifact.name, "link_type": "package"})

    changes = changelog.read_text().split("\n# ", 1)[0].split("\n", 1)[1].strip()
    project = environment["CI_PROJECT_URL"]
    description = (
        f"**Prerelease for testing; not a stable release.**\n\nSource commit: `{commit}`.\n\n"
        "Downloads are hosted in this GitLab project's Package Registry. "
        "This prerelease does not publish to get.psono.com or update its latest binaries.\n\n"
        "Every archive includes a matching CycloneDX SBOM and detached GPG signatures. "
        f"See [verification instructions]({project}/-/blob/{tag}/SBOM.md).\n\n{changes}\n"
    )
    payload = {"name": f"psonoci {tag} — Prerelease", "tag_name": tag,
               "description": description, "assets": {"links": links}}
    client.request("POST", "/releases", json.dumps(payload).encode(), "application/json")
    print(f"Published prerelease {tag} with {len(links)} verified download links")


if __name__ == "__main__":
    try:
        publish(GitLab(os.environ), os.environ, Path("collected_artifacts"), Path("CHANGELOG.md"))
    except (KeyError, ValueError, RuntimeError, OSError) as error:
        sys.exit(str(error))

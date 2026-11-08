#!/usr/bin/env bash
set -euo pipefail

# One-time deployment of the signed files produced by the original tag pipeline.
[[ "$CI_PROJECT_ID" == 19437616 && "$CI_COMMIT_BRANCH" == master && "$CI_COMMIT_REF_PROTECTED" == true ]]
[[ "$RELEASE_RECOVERY_V070" == true && "$SBOM_SCHEMA_SOURCE_JOB_ID" == 17840092943 ]]
release_tag=v0.7.0
release_commit=e3a1cd19b5a4d1c5cb6ecb10e1b1ffdb39795607

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl git gnupg python3 unzip
git fetch --no-tags origin "refs/tags/$release_tag"
[[ $(git rev-parse 'FETCH_HEAD^{commit}') == "$release_commit" ]]
curl --fail --location --silent --show-error --retry 3 \
    --header "JOB-TOKEN: $CI_JOB_TOKEN" \
    "$CI_API_V4_URL/projects/$CI_PROJECT_ID/jobs/17840092943/artifacts" \
    --output /tmp/v070-validated.zip
unzip -q /tmp/v070-validated.zip 'collected_artifacts/*'
scripts/verify-release-sboms.sh collected_artifacts .sig "$release_tag" \
    x86_64-unknown-linux-musl armv7-unknown-linux-gnueabihf armv7-unknown-linux-musleabihf \
    aarch64-unknown-linux-musl x86_64-apple-darwin aarch64-apple-darwin \
    x86_64-pc-windows-gnu x86_64-pc-windows-msvc

python3 - "$release_commit" <<'PY'
import json
from pathlib import Path
import shutil
import sys
import tarfile
import zipfile

artifacts = Path('collected_artifacts')
for path in artifacts.glob('*.cdx.json'):
    document = json.loads(path.read_text())
    commits = [p['value'] for c in document['components'] for p in c.get('properties', [])
               if p['name'] == 'psonoci:release:commit']
    if commits != [sys.argv[1]]:
        raise SystemExit(f'{path.name} does not identify the tagged commit')

aliases = {
    'x86_64-unknown-linux-musl': 'x86_64-linux',
    'armv7-unknown-linux-gnueabihf': 'armv7-linux',
    'aarch64-unknown-linux-musl': 'aarch64-linux',
    'x86_64-pc-windows-msvc': 'x86_64-windows',
    'x86_64-apple-darwin': 'x86_64-macos',
    'aarch64-apple-darwin': 'aarch64-macos',
}
for target, alias in aliases.items():
    base = artifacts / f'psonoci-v0.7.0-{target}'
    binary = 'psonoci.exe' if 'windows' in target else 'psonoci'
    output = Path('release-aliases') / alias / binary
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('wb') as dst:
        if binary.endswith('.exe'):
            with zipfile.ZipFile(str(base) + '.zip') as archive, archive.open(binary) as src:
                shutil.copyfileobj(src, dst)
        else:
            with tarfile.open(str(base) + '.tar.gz') as archive, archive.extractfile(binary) as src:
                shutil.copyfileobj(src, dst)
PY

# The validated archive set is bound to the protected stable tag above.
CI_COMMIT_TAG="$release_tag" bash var/publish_release_artifacts.sh
for file in release-aliases/*/*; do
    gsutil cp "$file" "gs://get.psono.com/$CI_PROJECT_PATH/\${file#release-aliases/}"
done

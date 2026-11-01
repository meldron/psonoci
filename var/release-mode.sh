#!/usr/bin/env bash
set -euo pipefail

# Derive the mode from the tag, rather than a caller-overridable mode variable.
case "${1:-}" in
  validation)
    case "${CI_COMMIT_TAG:-}" in
      gitlab-release-test-tag|gitlab-release-test-tag2) exit 0 ;;
      *) exit 1 ;;
    esac
    ;;
  production)
    if [[ ! "${CI_COMMIT_TAG:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "Refusing production publication or authentication outside a version release tag" >&2
      exit 1
    fi
    ;;
  *)
    echo "usage: $0 <validation|production>" >&2
    exit 2
    ;;
esac

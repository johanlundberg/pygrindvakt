set shell := ["bash", "-euo", "pipefail", "-c"]

remote := "origin"

# List recipes.
default:
    @just --list

python_dirs := "python tests examples"

# Build the extension into .venv (needed before `test`).
develop:
    .venv/bin/maturin develop

# Run the test suite; extra pytest arguments are passed through.
test *args:
    .venv/bin/python -m pytest tests {{ args }}

# Type-check the shipped stubs with mypy --strict (what CI runs).
typecheck:
    MYPYPATH=python .venv/bin/mypy --strict tests/typecheck_usage.py

# Lint with ruff.
lint:
    ruff check {{ python_dirs }}

# Check formatting with ruff without changing files.
format-check:
    ruff format --check {{ python_dirs }}

# Format with ruff.
format:
    ruff format {{ python_dirs }}

# Everything: ruff lint + format check, mypy, tests.
check: lint format-check typecheck test

# The v<version> tag triggers .github/workflows/release.yml.
# Create and push a signed release tag, e.g. `just release 0.2.0`.
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    version="{{ version }}"
    tag="v${version}"

    if ! [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
        echo "error: '${version}' is not a version like 1.2.3 or 1.2.3-rc.1" >&2
        exit 1
    fi

    if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
        echo "error: working tree has uncommitted changes" >&2
        exit 1
    fi

    # The tag must match the versions that get built and published.
    cargo_version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
    py_version="$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -n1)"
    if [[ "${cargo_version}" != "${version}" || "${py_version}" != "${version}" ]]; then
        echo "error: version mismatch: tag ${version}, Cargo.toml ${cargo_version}, pyproject.toml ${py_version}" >&2
        exit 1
    fi

    if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
        echo "error: tag ${tag} already exists locally" >&2
        exit 1
    fi
    if git ls-remote --exit-code --tags {{ remote }} "refs/tags/${tag}" >/dev/null 2>&1; then
        echo "error: tag ${tag} already exists on {{ remote }}" >&2
        exit 1
    fi

    branch="$(git rev-parse --abbrev-ref HEAD)"
    echo "Tagging ${tag} on ${branch} ($(git rev-parse --short HEAD))"
    git tag --sign --message "Release ${tag}" "${tag}"
    git tag --verify "${tag}"
    git push {{ remote }} "${tag}"
    echo "Pushed ${tag} to {{ remote }}"

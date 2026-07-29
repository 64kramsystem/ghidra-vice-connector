"""Cut a local release; build failures leave version and changelog edits."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Sequence

DEFAULT_BRANCH = "master"
VERSION_FILE = Path("src/main/py/src/vice/contracts.py")
_VERSION = re.compile(
    r'(?m)^(CONNECTOR_VERSION = ")(\d+\.\d+\.\d+)(")$'
)
_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class ReleaseError(RuntimeError):
    pass


def run(root: Path, *command: str) -> str:
    result = subprocess.run(
        command, cwd=root, text=True, capture_output=True
    )
    if result.returncode:
        raise ReleaseError(
            f"{' '.join(command)} failed:\n{result.stdout}{result.stderr}"
        )
    return result.stdout.strip()


def next_version(current: str, bump: str) -> str:
    match = _SEMVER.fullmatch(current)
    if match is None:
        raise ReleaseError(f"invalid current version {current!r}")
    if _SEMVER.fullmatch(bump):
        return bump
    major, minor, patch = map(int, match.groups())
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ReleaseError("bump must be major, minor, patch, or X.Y.Z")


def release(root: Path, bump: str) -> str:
    if run(root, "git", "branch", "--show-current") != DEFAULT_BRANCH:
        raise ReleaseError(f"release from {DEFAULT_BRANCH}")
    if run(root, "git", "status", "--porcelain"):
        raise ReleaseError("working tree is not clean")
    run(root, "git", "fetch", "origin", DEFAULT_BRANCH)
    if run(root, "git", "rev-parse", "HEAD") != run(
        root, "git", "rev-parse", f"origin/{DEFAULT_BRANCH}"
    ):
        raise ReleaseError("local and origin branches differ")
    tags = run(root, "git", "tag", "--points-at", "HEAD", "--list", "v*")
    if any(_SEMVER.fullmatch(tag.removeprefix("v")) for tag in tags.splitlines()):
        raise ReleaseError("HEAD is already released")

    path = root / VERSION_FILE
    text = path.read_text(encoding="utf-8")
    match = _VERSION.search(text)
    if match is None:
        raise ReleaseError("connector version is missing")
    version = next_version(match.group(2), bump)
    changelog = root / "CHANGELOG.md"
    _split_changelog(changelog.read_text(encoding="utf-8"))
    path.write_text(
        _VERSION.sub(rf"\g<1>{version}\g<3>", text, count=1),
        encoding="utf-8",
    )
    _roll_changelog(changelog, version)
    run(root, "./gradlew", "--no-daemon", "clean", "buildExtension")
    run(root, "git", "add", str(VERSION_FILE), "CHANGELOG.md")
    run(root, "git", "commit", "-m", f"Release {version}")
    run(root, "git", "tag", "-a", f"v{version}", "-m", f"Release {version}")
    run(
        root,
        "git",
        "push",
        "--atomic",
        "origin",
        f"HEAD:{DEFAULT_BRANCH}",
        f"v{version}",
    )
    return version


def _roll_changelog(path: Path, version: str) -> None:
    text = path.read_text(encoding="utf-8")
    before, after = _split_changelog(text)
    path.write_text(
        before + "## Unreleased\n\n" + f"## {version}\n" + after.lstrip("\n"),
        encoding="utf-8",
    )


def _split_changelog(text: str) -> tuple[str, str]:
    marker = "## Unreleased"
    if text.count(marker) != 1:
        raise ReleaseError("CHANGELOG.md needs one Unreleased section")
    before, after = text.split(marker)
    following = re.search(r"(?m)^## ", after.lstrip("\n"))
    section = (
        after.lstrip("\n")[:following.start()].strip()
        if following
        else after.strip()
    )
    if not section:
        raise ReleaseError("Unreleased changelog is empty")
    return before, after


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bump")
    args = parser.parse_args(argv)
    try:
        version = release(Path(__file__).resolve().parents[1], args.bump)
    except ReleaseError as error:
        print(f"release refused: {error}", file=sys.stderr)
        return 2
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Scripted releases for ghidra-vice-connector.

One command, with either a relative bump or an exact version:

    tools/release minor        # or major / patch / 1.2.3

A release tags its own commit `v<version>`, so a HEAD already carrying such a tag
has nothing to release: the run says so and exits 0 without touching anything.
Only `v<semver>` counts — the old `v12.1-<timestamp>` tag is not a release of this
version line.

Otherwise it refuses unless the checkout is on the default branch, clean, and
exactly in sync with origin. Then it writes the version, rolls the changelog,
builds and inspects the release candidate artifacts, commits, tags, pushes the
branch and the tag, and publishes the GitHub release.

Everything fallible happens *before* the push, because the push is a one-way
door: after it, the tag is public and no rollback here can retract it. Until then
a failure restores the working tree, the index and the branch ref, so a failed
release is a no-op.

A publish that fails after the push leaves a tagged HEAD, which this command now
reads as released. Finish that one by hand with `gh release create`; re-running
will not redo it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

PRODUCT = "ghidra-vice-connector"
DEFAULT_BRANCH = "master"
# Under dist/: ignored by git, and dist/ is not copied into the extension.
# A root-level manifest was demonstrably packaged into the zip, absolute
# local paths included.
MANIFEST_PATH = Path("dist") / "release-manifest.json"
CHECKSUMS_PATH = Path("dist") / "SHA256SUMS"
NOTES_PATH = Path("dist") / "release-notes.md"

# Releases are this project's only distribution channel: building requires JDK 21,
# Gradle and a full Ghidra install, so the asset is how anyone else installs it.
MARK_LATEST = True

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_CONNECTOR_VERSION_RE = re.compile(r'(?m)^(CONNECTOR_VERSION = ")(\d+\.\d+\.\d+)(")$')
CONTRACTS_PY = Path("src/main/py/src/vice/contracts.py")
CONTRACT_JSON = Path("contracts/c64-vice-api-v1.json")
_UNRELEASED_RE = re.compile(r"(?m)^## Unreleased[ \t]*$")
_LEVEL_TWO_RE = re.compile(r"(?m)^## .+$")

Runner = Callable[[Sequence[str], Path], str]


class ReleaseError(RuntimeError):
    """A release was refused or failed; the repository is unchanged."""


# --------------------------------------------------------------------------- shell


def run(command: Sequence[str], cwd: Path) -> str:
    completed = subprocess.run(
        list(command), cwd=cwd, capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise ReleaseError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout}{completed.stderr}".rstrip()
        )
    return completed.stdout


# ------------------------------------------------------------------------- version


def next_version(current: str, bump: str) -> str:
    """Return the selected semantic version.

    Note `0.99.0` + minor is `0.100.0`, not `1.0.0`: semver places no limit on a
    component's magnitude, and both Maven and PEP 440 compare them numerically.
    """
    match = _SEMVER_RE.fullmatch(current)
    if match is None:
        raise ReleaseError(f"current version is not semantic: {current!r}")
    major, minor, patch = (int(part) for part in match.groups())

    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    if _SEMVER_RE.fullmatch(bump):
        return bump
    raise ReleaseError(f"expected major, minor, patch, or X.Y.Z; got {bump!r}")


def read_version(repo_root: Path) -> str:
    """Read `CONNECTOR_VERSION`, the value this connector already serves.

    Deliberately **not** derived from tags: the old tag line uses a different
    scheme (`v12.1-<timestamp>`), so "highest tag wins" would be meaningless.
    """
    text = (repo_root / CONTRACTS_PY).read_text(encoding="utf-8")
    match = _CONNECTOR_VERSION_RE.search(text)
    if match is None:
        raise ReleaseError(f"{CONTRACTS_PY} has no CONNECTOR_VERSION")
    return match.group(2)


def write_version(repo_root: Path, version: str) -> list[Path]:
    """Write the version, then regenerate the contract JSON built from it.

    Regeneration is part of the write so the published contract cannot retain
    the previous connector version.
    """
    contracts_path = repo_root / CONTRACTS_PY
    text = contracts_path.read_text(encoding="utf-8")
    updated, count = _CONNECTOR_VERSION_RE.subn(rf"\g<1>{version}\g<3>", text, count=1)
    if count != 1:
        raise ReleaseError(f"{CONTRACTS_PY} has no CONNECTOR_VERSION")
    contracts_path.write_text(updated, encoding="utf-8")

    regenerate_contract(repo_root)
    return [contracts_path, repo_root / CONTRACT_JSON]


def regenerate_contract(repo_root: Path) -> None:
    """Rewrite the published contract from the declaration, in a subprocess.

    A subprocess, not an import: this module may already have imported the old
    declaration, and reloading it mid-run is a trap.
    """
    script = (
        "from pathlib import Path\n"
        "from vice.contracts import write_contract\n"
        f"write_contract(Path({str(repo_root / CONTRACT_JSON)!r}))\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repo_root,
        env={**os.environ, "PYTHONPATH": str(repo_root / "src/main/py/src")},
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ReleaseError(f"contract regeneration failed:\n{completed.stderr.rstrip()}")


# ----------------------------------------------------------------------- changelog


def unreleased_section(changelog_path: Path) -> str:
    text = changelog_path.read_text(encoding="utf-8")
    headings = list(_UNRELEASED_RE.finditer(text))
    if len(headings) != 1:
        raise ReleaseError(
            f"CHANGELOG.md must have exactly one ## Unreleased heading; found {len(headings)}"
        )
    heading = headings[0]
    following = _LEVEL_TWO_RE.search(text, heading.end())
    end = following.start() if following else len(text)
    return text[heading.end() : end].strip()


def roll_changelog(changelog_path: Path, version: str) -> None:
    """Retitle `## Unreleased` as the version, with a fresh empty one above it.

    Above, not below: the retired CI job inserted the version heading directly
    beneath `## Unreleased`, and a later merge then filed a new entry underneath
    it — inside a release that did not contain it.
    """
    text = changelog_path.read_text(encoding="utf-8")
    section = unreleased_section(changelog_path)
    if not section:
        raise ReleaseError("## Unreleased is empty; nothing to release")

    heading = _UNRELEASED_RE.search(text)
    assert heading is not None
    updated = (
        text[: heading.start()]
        + "## Unreleased\n\n"
        + f"## {version}\n"
        + text[heading.end() :].lstrip("\n")
    )
    changelog_path.write_text(updated, encoding="utf-8")


# ----------------------------------------------------------------------------- git


def git_status_porcelain(repo_root: Path, runner: Runner = run) -> str:
    return runner(["git", "status", "--porcelain"], repo_root).strip()


def ensure_clean(repo_root: Path, runner: Runner = run) -> None:
    if git_status_porcelain(repo_root, runner):
        raise ReleaseError("working tree is not clean; commit or stash first")


def ensure_default_branch(repo_root: Path, runner: Runner = run) -> None:
    branch = runner(["git", "branch", "--show-current"], repo_root).strip()
    if branch != DEFAULT_BRANCH:
        raise ReleaseError(f"releases run on {DEFAULT_BRANCH}, not {branch!r}")


def head_sha(repo_root: Path, runner: Runner = run) -> str:
    return runner(["git", "rev-parse", "HEAD"], repo_root).strip()


def ensure_in_sync_with_origin(repo_root: Path, runner: Runner = run) -> str:
    """Refuse unless the branch matches origin exactly; return origin's SHA.

    Releasing something the remote does not have, or missing something it does,
    produces a tag whose contents nobody else can reproduce. The returned SHA
    becomes the lease for the push, so movement between here and there is caught
    rather than merely being unlikely.
    """
    runner(["git", "fetch", "--quiet", "origin", DEFAULT_BRANCH], repo_root)
    ahead_behind = runner(
        ["git", "rev-list", "--left-right", "--count",
         f"origin/{DEFAULT_BRANCH}...HEAD"],
        repo_root,
    ).split()
    if len(ahead_behind) != 2:
        raise ReleaseError("cannot compare HEAD with origin")
    behind, ahead = (int(value) for value in ahead_behind)
    if behind or ahead:
        raise ReleaseError(
            f"HEAD is {ahead} ahead and {behind} behind origin/{DEFAULT_BRANCH}; "
            "push or pull first"
        )
    return runner(
        ["git", "rev-parse", f"origin/{DEFAULT_BRANCH}"], repo_root
    ).strip()


def head_release_tag(repo_root: Path, runner: Runner = run) -> str | None:
    """The version already released at HEAD, if any.

    A release tags its own commit, so a tagged HEAD has nothing left to release.
    Only `v<semver>` counts: the old tag line here uses `v12.1-<timestamp>`,
    which is not a release of this version line.
    """
    for tag in runner(
        ["git", "tag", "--points-at", "HEAD", "--list", "v*"], repo_root
    ).split():
        if _SEMVER_RE.fullmatch(tag[1:]):
            return tag[1:]
    return None


def ensure_tag_absent(repo_root: Path, tag: str, runner: Runner = run) -> None:
    local = runner(["git", "tag", "--list", tag], repo_root).strip()
    if local:
        raise ReleaseError(f"tag {tag} already exists locally")
    remote = runner(["git", "ls-remote", "--tags", "origin", tag], repo_root).strip()
    if remote:
        raise ReleaseError(f"tag {tag} already exists on origin")


def origin_repo(repo_root: Path, runner: Runner = run) -> str:
    """Return `owner/repo` for `origin`.

    Every `gh` call is pinned to this. Unpinned, `gh` resolves through whichever
    remote it prefers: in this repository that is `upstream`, i.e. a different
    project entirely, so an unpinned publish would target the wrong repo.
    """
    url = runner(["git", "remote", "get-url", "origin"], repo_root).strip()
    # Backslashes normalised so a Windows path-style remote parses too.
    match = re.search(r"[:/]([^/:\\]+/[^/\\]+?)(?:\.git)?$", url.replace("\\", "/"))
    if match is None:
        raise ReleaseError(f"cannot derive owner/repo from origin url {url!r}")
    return match.group(1)


# ------------------------------------------------------------------------ manifest


@dataclass(frozen=True)
class Artifact:
    path: Path
    sha256: str

    def as_json(self) -> dict[str, str]:
        return {"name": self.path.name, "path": str(self.path), "sha256": self.sha256}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(
    repo_root: Path, version: str, commit: str, artifacts: Iterable[Artifact]
) -> Path:
    path = repo_root / MANIFEST_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "version": version,
                "commit": commit,
                "artifacts": [artifact.as_json() for artifact in artifacts],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def read_manifest(repo_root: Path) -> dict:
    path = repo_root / MANIFEST_PATH
    if not path.is_file():
        raise ReleaseError(f"{MANIFEST_PATH} is missing; run prepare first")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ReleaseError(f"{MANIFEST_PATH} is not valid JSON: {error}") from error
    # Validated here so a malformed file is a refusal rather than a KeyError
    # surfacing from wherever it happens to be indexed.
    missing = {"version", "commit", "artifacts"} - set(manifest)
    if missing:
        raise ReleaseError(f"{MANIFEST_PATH} is missing {sorted(missing)}")
    return manifest


def verify_manifest(
    repo_root: Path, manifest: dict, commit: str, version: str
) -> list[Path]:
    """Confirm the prepared artifacts are still the ones being published.

    Hash-checked, not name-checked: an artifact rebuilt from a different commit
    can carry the same name and the same embedded version.
    """
    if manifest["commit"] != commit:
        raise ReleaseError(
            f"manifest commit {manifest['commit'][:12]} is not the tagged commit {commit[:12]}"
        )
    canonical = expected_artifacts(repo_root, version)
    listed = sorted(Path(entry["path"]).name for entry in manifest["artifacts"])
    if listed != sorted(path.name for path in canonical):
        raise ReleaseError(
            f"manifest lists {listed}, not the expected "
            f"{sorted(path.name for path in canonical)}"
        )
    paths = []
    for entry in manifest["artifacts"]:
        path = Path(entry["path"])
        if not path.is_absolute():
            path = repo_root / path
        if not path.is_file():
            raise ReleaseError(f"prepared artifact is missing: {path}")
        if sha256(path) != entry["sha256"]:
            raise ReleaseError(
                f"prepared artifact changed since prepare: {path.name}"
            )
        paths.append(path)
    return paths


def write_checksums(repo_root: Path, artifacts: Sequence[Path]) -> Path:
    path = repo_root / CHECKSUMS_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = sorted(f"{sha256(item)}  {item.name}" for item in artifacts)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


BUILD: tuple[tuple[str, ...], ...] = (
    ("./gradlew", "--no-daemon", "clean", "buildExtension"),
)


def expected_artifacts(repo_root: Path, version: str) -> list[Path]:
    """The newest extension zip Gradle produced.

    Ghidra's buildExtension.gradle names it `<ghidra_ver>_<date>_<project>.zip`,
    so the name carries the target Ghidra version and a date rather than the
    release version. It is discovered, not predicted -- but its *contents* are
    then checked against the release version, which is the assertion that matters.
    """
    candidates = sorted(
        (repo_root / "dist").glob(f"*_{PRODUCT}.zip"),
        key=lambda path: path.stat().st_mtime,
    )
    if not candidates:
        raise ReleaseError(f"build did not produce dist/*_{PRODUCT}.zip")
    return [candidates[-1]]


def verify_artifact_contents(repo_root: Path, version: str) -> list[Artifact]:
    """Check the artifacts' contents, not just their names."""
    extension = expected_artifacts(repo_root, version)[0]

    with zipfile.ZipFile(extension) as archive:
        names = archive.namelist()
        properties_name = f"{PRODUCT}/extension.properties"
        changelog_name = f"{PRODUCT}/CHANGELOG.md"
        if properties_name not in names:
            raise ReleaseError(f"{extension.name} has no {properties_name}")
        properties = archive.read(properties_name).decode("utf-8")
        if f"connectorVersion={version}" not in properties:
            raise ReleaseError(
                f"{extension.name} does not carry connectorVersion={version}"
            )
        # buildExtension.gradle copies the project root, so the changelog ships.
        # Absence is a failure, not a pass: tolerating it would mean a packaging
        # change that dropped the file silently disabled this check.
        if changelog_name not in names:
            raise ReleaseError(f"{extension.name} has no {changelog_name}")
        packaged = archive.read(changelog_name).decode("utf-8")
        if packaged != (repo_root / "CHANGELOG.md").read_text(encoding="utf-8"):
            raise ReleaseError(f"{extension.name} bundles a stale CHANGELOG.md")
        # The release scratch files must never be packaged.
        for helper in (MANIFEST_PATH.name, CHECKSUMS_PATH.name):
            if any(name.endswith(f"/{helper}") for name in names):
                raise ReleaseError(f"{extension.name} packages {helper}")

    return [Artifact(extension, sha256(extension))]


# ------------------------------------------------------------------------ prepare


@dataclass(frozen=True)
class PublishPlan:
    """Everything publishing needs, computed before anything is pushed."""

    version: str
    tag: str
    repo: str
    notes_path: Path
    assets: tuple[Path, ...]


def build_publish_plan(repo_root: Path, version: str, runner: Runner = run) -> PublishPlan:
    """Do all the local, fallible publication work.

    Deliberately called before the push: reading the manifest, verifying hashes,
    writing checksums and parsing the origin URL can all fail, and after a push
    a failure leaves a public tag that this script cannot retract.
    """
    tag = f"v{version}"
    commit = head_sha(repo_root, runner)
    manifest = read_manifest(repo_root)
    if manifest["version"] != version:
        raise ReleaseError(f"manifest is for {manifest['version']}, not {version}")
    artifacts = verify_manifest(repo_root, manifest, commit, version)
    checksums = write_checksums(repo_root, artifacts)

    # The tag body, captured locally: `gh release create` refuses
    # --notes-from-tag together with --repo, and --repo is not negotiable
    # because gh otherwise resolves through the wrong remote here.
    body = runner(["git", "tag", "-l", "--format=%(contents)", tag], repo_root).strip()
    notes_path = repo_root / NOTES_PATH
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    notes_path.write_text((body or version) + "\n", encoding="utf-8")

    return PublishPlan(
        version=version,
        tag=tag,
        repo=origin_repo(repo_root, runner),
        notes_path=notes_path,
        assets=(*artifacts, checksums),
    )


def release(repo_root: Path, bump: str, runner: Runner = run) -> str:
    """Cut and publish a release in one command."""
    ensure_default_branch(repo_root, runner)
    ensure_clean(repo_root, runner)

    released = head_release_tag(repo_root, runner)
    if released is not None:
        print(f"HEAD is already tagged v{released}; nothing to release")
        return released

    origin_sha = ensure_in_sync_with_origin(repo_root, runner)
    version = prepare(repo_root, bump, runner)
    plan = build_publish_plan(repo_root, version, runner)

    # The one-way door. Everything fallible and local has already run.
    #
    # One atomic push, leased against the SHA the sync check saw: separate pushes
    # can leave origin holding the release commit without its tag, which no later
    # run can resume or redo cleanly. The lease also catches a concurrent rewind,
    # which a plain non-fast-forward check does not.
    print(f"push: origin HEAD and {plan.tag} (atomic)")
    runner(
        [
            "git", "push", "--atomic",
            f"--force-with-lease=refs/heads/{DEFAULT_BRANCH}:{origin_sha}",
            "origin",
            f"HEAD:refs/heads/{DEFAULT_BRANCH}",
            f"refs/tags/{plan.tag}",
        ],
        repo_root,
    )

    return publish(repo_root, plan, runner)


def prepare(repo_root: Path, bump: str, runner: Runner = run) -> str:
    changelog = repo_root / "CHANGELOG.md"
    if not unreleased_section(changelog):
        raise ReleaseError("## Unreleased is empty; nothing to release")

    original_head = head_sha(repo_root, runner)
    current = read_version(repo_root)
    version = next_version(current, bump)
    tag = f"v{version}"
    ensure_tag_absent(repo_root, tag, runner)

    print(f"{current} -> {version}")
    release_commit: str | None = None
    manifest_path = repo_root / MANIFEST_PATH
    try:
        written = [*write_version(repo_root, version), changelog]
        roll_changelog(changelog, version)

        for step in BUILD:
            print(f"build: {' '.join(step)}")
            runner(step, repo_root)

        artifacts = verify_artifact_contents(repo_root, version)

        # Explicit paths, not `add -A`: the latter would stage build output and
        # anything else untracked into the release commit.
        staged = [str(path.relative_to(repo_root)) for path in written]
        runner(["git", "add", *staged], repo_root)
        runner(["git", "commit", "-m", f"Release {version}"], repo_root)
        commit = head_sha(repo_root, runner)
        release_commit = commit

        write_manifest(repo_root, version, commit, artifacts)
        runner(
            ["git", "tag", "-a", tag, "-m", unreleased_or_version(changelog, version)],
            repo_root,
        )
    except BaseException:
        _rollback(repo_root, original_head, release_commit, manifest_path, runner)
        raise

    return version


def unreleased_or_version(changelog: Path, version: str) -> str:
    """Tag message: the released section, falling back to the bare version."""
    text = changelog.read_text(encoding="utf-8")
    match = re.search(rf"(?m)^## {re.escape(version)}[ \t]*$", text)
    if match is None:
        return version
    following = _LEVEL_TWO_RE.search(text, match.end())
    end = following.start() if following else len(text)
    return f"{version}\n\n{text[match.end():end].strip()}"


def _rollback(
    repo_root: Path,
    original_head: str,
    release_commit: str | None,
    manifest_path: Path,
    runner: Runner,
) -> None:
    """Restore worktree, index and refs. A failed release must be a no-op."""
    if manifest_path.exists():
        manifest_path.unlink()
    if release_commit is not None:
        current = head_sha(repo_root, runner)
        if current == release_commit:
            runner(["git", "reset", "--hard", original_head], repo_root)
        else:
            # Something else advanced HEAD; resetting would destroy that work.
            raise ReleaseError(
                f"HEAD moved to {current[:12]} after the release commit "
                f"{release_commit[:12]}; not resetting. Undo manually."
            )
    else:
        # Unstage anything the failed commit left in the index, then restore the
        # tracked files. `reset --hard` is confined to tracked content, so build
        # output stays where it is.
        runner(["git", "reset", "-q", "HEAD"], repo_root)
        runner(["git", "checkout", "--", "."], repo_root)


# ------------------------------------------------------------------------ publish


def publish(repo_root: Path, plan: PublishPlan, runner: Runner = run) -> str:
    """Create the GitHub release and confirm the assets landed."""
    runner(
        [
            "gh", "release", "create", plan.tag,
            "--repo", plan.repo,
            "--verify-tag",
            "--title", f"{PRODUCT} {plan.version}",
            # --notes-file, not --notes-from-tag: gh refuses the latter together
            # with --repo, and --repo must stay because gh otherwise resolves
            # through the wrong remote here.
            "--notes-file", str(plan.notes_path),
            f"--latest={'true' if MARK_LATEST else 'false'}",
            *[str(path) for path in plan.assets],
        ],
        repo_root,
    )

    listed = sorted(
        runner(
            ["gh", "release", "view", plan.tag, "--repo", plan.repo,
             "--json", "assets", "--jq", ".assets[].name"],
            repo_root,
        ).split()
    )
    expected = sorted(path.name for path in plan.assets)
    if listed != expected:
        raise ReleaseError(f"released assets {listed} do not match expected {expected}")

    print(f"published {plan.tag} to {plan.repo}")
    return plan.version


# ---------------------------------------------------------------------------- cli


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=f"Cut and publish a {PRODUCT} release",
        epilog="Builds, commits, tags, pushes, and publishes.",
    )
    parser.add_argument(
        "bump",
        metavar="{major,minor,patch,X.Y.Z}",
        help="component to raise or exact release version",
    )

    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    try:
        release(repo_root, args.bump)
    except ReleaseError as error:
        print(f"release refused: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

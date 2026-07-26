"""Tests for tools/release.

Every refusal test satisfies all *other* preconditions, so no test can pass for
the wrong reason.
"""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools import release  # noqa: E402

CONTRACTS = '''API_MAJOR = 1
CONNECTOR_NAME = "ghidra-vice-connector"
CONNECTOR_VERSION = "{version}"
'''

CHANGELOG = """# Changelog

## Unreleased

- A thing worth releasing.

## 0.98.0

- Older news.
"""


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / release.CONTRACTS_PY.parent).mkdir(parents=True)
    (root / release.CONTRACT_JSON.parent).mkdir(parents=True)
    git(root, "init", "-q", "-b", release.DEFAULT_BRANCH)
    git(root, "config", "user.email", "test@example.com")
    git(root, "config", "user.name", "Test")
    (root / ".gitignore").write_text(
        f"dist/\n{release.MANIFEST_NAME}\n", encoding="utf-8"
    )
    (root / release.CONTRACTS_PY).write_text(
        CONTRACTS.format(version="0.99.0"), encoding="utf-8"
    )
    (root / release.CONTRACT_JSON).write_text(
        json.dumps({"connector": {"name": "ghidra-vice-connector"}}, indent=2) + "\n",
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "initial")
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", str(remote))
    git(root, "remote", "add", "origin", str(remote))
    git(root, "push", "-q", "origin", release.DEFAULT_BRANCH)
    return root


def make_extension(
    repo: Path,
    version: str,
    *,
    connector_version: str | None = None,
    changelog: str | None = None,
) -> Path:
    (repo / "dist").mkdir(exist_ok=True)
    path = repo / "dist" / f"ghidra_12.1.2_PUBLIC_20260726_{release.PRODUCT}.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"{release.PRODUCT}/extension.properties",
            f"version=12.1.2\nconnectorVersion={connector_version or version}\n",
        )
        archive.writestr(
            f"{release.PRODUCT}/CHANGELOG.md",
            changelog if changelog is not None
            else (repo / "CHANGELOG.md").read_text(encoding="utf-8"),
        )
    return path


def recording_runner(repo: Path, *, fail: str | None = None, build: bool = True):
    def runner(command, cwd):
        joined = " ".join(str(part) for part in command)
        if fail and fail in joined:
            raise release.ReleaseError(f"injected failure: {joined}")
        if command[0] == "git":
            return release.run(command, cwd)
        if build and "gradlew" in joined:
            make_extension(repo, release.read_version(repo))
            return ""
        if command[:3] == ["gh", "release", "view"]:
            manifest = release.read_manifest(repo)
            return "\n".join(
                [entry["name"] for entry in manifest["artifacts"]] + ["SHA256SUMS"]
            )
        return ""

    return runner


@pytest.fixture(autouse=True)
def stub_contract_regeneration(monkeypatch: pytest.MonkeyPatch):
    """The fixture repo has no vice package; regeneration is covered separately."""
    monkeypatch.setattr(release, "regenerate_contract", lambda repo_root: None)


# ------------------------------------------------------------------ version


def test_version_comes_from_the_declaration(repo: Path):
    assert release.read_version(repo) == "0.99.0"


def test_write_version_updates_the_declaration(repo: Path):
    release.write_version(repo, "0.100.0")

    assert release.read_version(repo) == "0.100.0"
    assert 'CONNECTOR_VERSION = "0.100.0"' in (
        repo / release.CONTRACTS_PY
    ).read_text(encoding="utf-8")


def test_next_version_from_ninety_nine(repo: Path):
    assert release.next_version("0.99.0", "minor") == "0.100.0"


def test_version_is_not_taken_from_the_old_tag_scheme(repo: Path):
    """The old line is v12.1-<timestamp>; highest-tag-wins would be meaningless."""
    git(repo, "tag", "-a", "v12.1-20260603105209", "-m", "old scheme")

    release.prepare(repo, "minor", recording_runner(repo))

    assert release.read_version(repo) == "0.100.0"
    assert git(repo, "tag", "--list", "v0.100.0").strip() == "v0.100.0"


# ----------------------------------------------------------------- refusals


def test_refuses_a_dirty_tree(repo: Path):
    (repo / "CHANGELOG.md").write_text(CHANGELOG + "\n", encoding="utf-8")

    with pytest.raises(release.ReleaseError, match="not clean"):
        release.prepare(repo, "minor", recording_runner(repo))


def test_refuses_a_non_default_branch(repo: Path):
    git(repo, "checkout", "-qb", "feature")

    with pytest.raises(release.ReleaseError, match="releases run on"):
        release.prepare(repo, "minor", recording_runner(repo))


def test_refuses_an_empty_unreleased_section(repo: Path):
    (repo / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n## 0.98.0\n\n- Older.\n", encoding="utf-8"
    )
    git(repo, "commit", "-aqm", "empty")

    with pytest.raises(release.ReleaseError, match="nothing to release"):
        release.prepare(repo, "minor", recording_runner(repo))


def test_refuses_a_tag_already_on_origin(repo: Path):
    git(repo, "tag", "v0.100.0")
    git(repo, "push", "-q", "origin", "v0.100.0")
    git(repo, "tag", "-d", "v0.100.0")

    with pytest.raises(release.ReleaseError, match="already exists on origin"):
        release.prepare(repo, "minor", recording_runner(repo))


# ------------------------------------------------------------ gate ordering


def test_gates_run_after_the_version_is_written(repo: Path):
    observed: list[str] = []

    def runner(command, cwd):
        if "pytest" in " ".join(str(part) for part in command):
            observed.append(release.read_version(repo))
            return ""
        return recording_runner(repo)(command, cwd)

    release.prepare(repo, "minor", runner)

    assert observed == ["0.100.0"]


def test_a_failing_gate_leaves_the_repository_untouched(repo: Path):
    before_head = release.head_sha(repo)
    before = (repo / release.CONTRACTS_PY).read_text(encoding="utf-8")

    with pytest.raises(release.ReleaseError, match="injected failure"):
        release.prepare(repo, "minor", recording_runner(repo, fail="pytest"))

    assert release.head_sha(repo) == before_head
    assert (repo / release.CONTRACTS_PY).read_text(encoding="utf-8") == before
    assert git(repo, "status", "--porcelain").strip() == ""
    assert git(repo, "tag", "--list").strip() == ""


def test_the_bats_gate_targets_the_test_directory():
    """test/ and tests/ are siblings here; a tests/*.bats glob matches nothing."""
    bats = [gate for gate in release.GATES if gate[0] == "bats"]

    assert bats == [("bats", "test/import-prg.bats")]
    assert (REPO_ROOT / "test" / "import-prg.bats").is_file()


def test_the_live_vice_suite_is_excluded_from_the_gates():
    """It needs a running emulator; CI covers it with REQUIRE_LIVE_VICE=1."""
    pytest_gates = [
        gate for gate in release.GATES if "pytest" in " ".join(str(p) for p in gate)
    ]

    assert pytest_gates
    assert all("--ignore=tests/test_live_vice.py" in gate for gate in pytest_gates)


def test_a_failing_tag_resets_the_branch(repo: Path):
    before_head = release.head_sha(repo)

    with pytest.raises(release.ReleaseError, match="injected failure"):
        release.prepare(repo, "minor", recording_runner(repo, fail="git tag -a"))

    assert release.head_sha(repo) == before_head
    assert git(repo, "status", "--porcelain").strip() == ""
    assert not (repo / release.MANIFEST_NAME).exists()


# --------------------------------------------------------- artifact contents


def test_a_missing_artifact_fails_before_committing(repo: Path):
    before_head = release.head_sha(repo)

    with pytest.raises(release.ReleaseError, match="build did not produce"):
        release.prepare(repo, "minor", recording_runner(repo, build=False))

    assert release.head_sha(repo) == before_head
    assert git(repo, "status", "--porcelain").strip() == ""


def test_a_zip_with_the_wrong_connector_version_fails(repo: Path):
    def runner(command, cwd):
        if "gradlew" in " ".join(str(part) for part in command):
            make_extension(repo, "0.100.0", connector_version="0.99.0")
            return ""
        return recording_runner(repo, build=False)(command, cwd)

    with pytest.raises(release.ReleaseError, match="connectorVersion=0.100.0"):
        release.prepare(repo, "minor", runner)


def test_a_zip_bundling_a_stale_changelog_fails(repo: Path):
    """buildExtension copies the project root, so the changelog must be rolled."""

    def runner(command, cwd):
        if "gradlew" in " ".join(str(part) for part in command):
            make_extension(repo, "0.100.0", changelog=CHANGELOG)
            return ""
        return recording_runner(repo, build=False)(command, cwd)

    with pytest.raises(release.ReleaseError, match="stale CHANGELOG"):
        release.prepare(repo, "minor", runner)


# ------------------------------------------------------------------ publish


def prepared(repo: Path) -> str:
    version = release.prepare(repo, "minor", recording_runner(repo))
    git(repo, "push", "-q", "origin", release.DEFAULT_BRANCH)
    git(repo, "push", "-q", "origin", f"v{version}")
    return version


def test_publish_marks_the_release_latest(repo: Path):
    """Releases are this project's only distribution channel."""
    prepared(repo)
    commands: list[list[str]] = []

    def runner(command, cwd):
        commands.append([str(part) for part in command])
        return recording_runner(repo)(command, cwd)

    release.publish(repo, runner)

    create = next(c for c in commands if c[:3] == ["gh", "release", "create"])
    assert "--latest=true" in create
    assert release.MARK_LATEST is True


def test_publish_pins_gh_to_the_origin_repository(repo: Path):
    git(repo, "remote", "add", "upstream", "https://github.com/someone/else.git")
    prepared(repo)
    commands: list[list[str]] = []

    def runner(command, cwd):
        commands.append([str(part) for part in command])
        return recording_runner(repo)(command, cwd)

    release.publish(repo, runner)

    for call in [c for c in commands if c[0] == "gh"]:
        assert call[call.index("--repo") + 1] == release.origin_repo(repo)


def test_publish_refuses_when_the_tag_is_absent_from_origin(repo: Path):
    version = release.prepare(repo, "minor", recording_runner(repo))
    git(repo, "push", "-q", "origin", release.DEFAULT_BRANCH)

    with pytest.raises(release.ReleaseError, match=f"origin has no v{version}"):
        release.publish(repo, recording_runner(repo))


def test_publish_refuses_an_artifact_rebuilt_after_prepare(repo: Path):
    prepared(repo)
    manifest = release.read_manifest(repo)
    Path(manifest["artifacts"][0]["path"]).write_bytes(b"rebuilt elsewhere")

    with pytest.raises(release.ReleaseError, match="changed since prepare"):
        release.publish(repo, recording_runner(repo))


def test_publish_verifies_the_exact_asset_set(repo: Path):
    prepared(repo)

    def runner(command, cwd):
        if command[:3] == ["gh", "release", "view"]:
            return "SHA256SUMS"
        return recording_runner(repo)(command, cwd)

    with pytest.raises(release.ReleaseError, match="do not match expected"):
        release.publish(repo, runner)


def test_publish_succeeds(repo: Path):
    version = prepared(repo)

    assert release.publish(repo, recording_runner(repo)) == version
    assert (repo / "SHA256SUMS").is_file()


# ---------------------------------------------------- contract regeneration


def test_write_version_regenerates_the_contract(
    repo: Path, monkeypatch: pytest.MonkeyPatch
):
    """A bump without regeneration fails the connector's own parity test."""
    calls: list[Path] = []
    monkeypatch.setattr(release, "regenerate_contract", calls.append)

    release.write_version(repo, "0.100.0")

    assert calls == [repo]

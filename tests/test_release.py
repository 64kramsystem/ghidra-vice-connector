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
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
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
        parts = [str(part) for part in command]
        joined = " ".join(parts)
        if fail and fail in joined:
            raise release.ReleaseError(f"injected failure: {joined}")
        if parts[0] == "git":
            return release.run(command, cwd)
        if build and "gradlew" in joined:
            make_extension(repo, release.read_version(repo))
            return ""
        if parts[:3] == ["gh", "release", "view"]:
            # Derived from the version, not the manifest: the manifest is the
            # thing under test.
            version = release.read_version(repo)
            return "\n".join(
                [path.name for path in release.expected_artifacts(repo, version)]
                + ["SHA256SUMS"]
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
    assert not (repo / release.MANIFEST_PATH).exists()


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
    assert (repo / release.CHECKSUMS_PATH).is_file()


# ---------------------------------------------------- contract regeneration


def test_write_version_regenerates_the_contract(
    repo: Path, monkeypatch: pytest.MonkeyPatch
):
    """A bump without regeneration fails the connector's own parity test."""
    calls: list[Path] = []
    monkeypatch.setattr(release, "regenerate_contract", calls.append)

    release.write_version(repo, "0.100.0")

    assert calls == [repo]


# ------------------------------------------------ blockers found in review


def test_a_concurrent_commit_is_not_destroyed(repo: Path):
    """Rollback must reset only the commit this run created."""

    def runner(command, cwd):
        parts = [str(part) for part in command]
        if parts[:3] == ["git", "tag", "-a"]:
            (repo / "other.txt").write_text("concurrent", encoding="utf-8")
            git(repo, "add", "other.txt")
            git(repo, "commit", "-qm", "concurrent work")
            raise release.ReleaseError("injected failure: git tag -a")
        return recording_runner(repo)(command, cwd)

    with pytest.raises(release.ReleaseError, match="not resetting"):
        release.prepare(repo, "minor", runner)

    assert git(repo, "log", "-1", "--format=%s").strip() == "concurrent work"


def test_an_injected_commit_failure_leaves_no_trace(repo: Path):
    before_head = release.head_sha(repo)

    with pytest.raises(release.ReleaseError, match="injected failure"):
        release.prepare(repo, "minor", recording_runner(repo, fail="git commit"))

    assert release.head_sha(repo) == before_head
    assert git(repo, "status", "--porcelain").strip() == ""
    assert git(repo, "tag", "--list").strip() == ""


def test_an_injected_manifest_write_failure_resets_the_branch(
    repo: Path, monkeypatch: pytest.MonkeyPatch
):
    before_head = release.head_sha(repo)

    def explode(*args, **kwargs):
        raise release.ReleaseError("injected failure: manifest write")

    monkeypatch.setattr(release, "write_manifest", explode)

    with pytest.raises(release.ReleaseError, match="injected failure"):
        release.prepare(repo, "minor", recording_runner(repo))

    assert release.head_sha(repo) == before_head
    assert not (repo / release.MANIFEST_PATH).exists()


def test_publish_rejects_a_manifest_missing_artifacts(repo: Path):
    """The manifest is untrusted input; an empty one must not publish nothing."""
    prepared(repo)
    manifest = json.loads((repo / release.MANIFEST_PATH).read_text(encoding="utf-8"))
    manifest["artifacts"] = []
    (repo / release.MANIFEST_PATH).write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(release.ReleaseError, match="manifest lists"):
        release.publish(repo, recording_runner(repo))


def test_a_zip_without_a_changelog_is_rejected(repo: Path):
    """Absence must fail: tolerating it would silently disable the staleness check."""

    def runner(command, cwd):
        parts = [str(part) for part in command]
        if "gradlew" in " ".join(parts):
            path = repo / "dist" / f"ghidra_12.1.2_PUBLIC_20260726_{release.PRODUCT}.zip"
            path.parent.mkdir(exist_ok=True)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(
                    f"{release.PRODUCT}/extension.properties",
                    "version=12.1.2\nconnectorVersion=0.100.0\n",
                )
            return ""
        return recording_runner(repo, build=False)(command, cwd)

    with pytest.raises(release.ReleaseError, match="has no ghidra-vice-connector/CHANGELOG"):
        release.prepare(repo, "minor", runner)


def test_a_zip_packaging_the_release_scratch_files_is_rejected(repo: Path):
    """buildExtension copies the project root; these must never ship."""

    def runner(command, cwd):
        parts = [str(part) for part in command]
        if "gradlew" in " ".join(parts):
            path = make_extension(repo, "0.100.0")
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr(
                    f"{release.PRODUCT}/{release.MANIFEST_PATH.name}",
                    '{"artifacts": []}',
                )
            return ""
        return recording_runner(repo, build=False)(command, cwd)

    with pytest.raises(release.ReleaseError, match="packages release-manifest"):
        release.prepare(repo, "minor", runner)


def test_publish_takes_notes_from_the_tag(repo: Path):
    prepared(repo)
    commands: list[list[str]] = []

    def runner(command, cwd):
        commands.append([str(part) for part in command])
        return recording_runner(repo)(command, cwd)

    release.publish(repo, runner)

    create = next(c for c in commands if c[:3] == ["gh", "release", "create"])
    assert "--notes-from-tag" in create
    assert "--notes" not in create


def test_release_scratch_files_do_not_dirty_the_repository(repo: Path):
    prepared(repo)
    release.publish(repo, recording_runner(repo))

    assert git(repo, "status", "--porcelain").strip() == ""
    assert str(release.MANIFEST_PATH).startswith("dist/")
    assert str(release.CHECKSUMS_PATH).startswith("dist/")


def test_publish_refuses_a_missing_manifest(repo: Path):
    """Regression: this path once raised NameError instead of refusing."""
    prepared(repo)
    (repo / release.MANIFEST_PATH).unlink()

    with pytest.raises(release.ReleaseError, match="missing"):
        release.publish(repo, recording_runner(repo))


def test_publish_rejects_a_manifest_listing_a_noncanonical_artifact(repo: Path):
    """Nonempty is not enough: the names must be the canonical set."""
    prepared(repo)
    stray = repo / "dist" / "something-else.zip"
    stray.write_bytes(b"stray")
    manifest = json.loads((repo / release.MANIFEST_PATH).read_text(encoding="utf-8"))
    manifest["artifacts"] = [
        {"name": stray.name, "path": str(stray), "sha256": release.sha256(stray)}
    ]
    (repo / release.MANIFEST_PATH).write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(release.ReleaseError, match="manifest lists"):
        release.publish(repo, recording_runner(repo))


def test_publish_refuses_a_remote_tag_on_a_different_commit(repo: Path):
    version = prepared(repo)
    (repo / "extra.txt").write_text("x", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "later work")
    git(repo, "tag", "-d", f"v{version}")
    git(repo, "tag", "-a", f"v{version}", "-m", "moved")

    with pytest.raises(release.ReleaseError, match="origin has no"):
        release.publish(repo, recording_runner(repo))


def test_checksums_match_recomputed_artifact_hashes(repo: Path):
    """Filenames and a line count would pass a file full of zero hashes."""
    prepared(repo)
    release.publish(repo, recording_runner(repo))

    manifest = release.read_manifest(repo)
    expected = {
        Path(entry["path"]).name: release.sha256(Path(entry["path"]))
        for entry in manifest["artifacts"]
    }
    written = {}
    for line in (repo / release.CHECKSUMS_PATH).read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        written[name] = digest

    assert written == expected
    assert all(len(digest) == 64 and set(digest) != {"0"} for digest in written.values())


# --------------------------------------------- guards ported from mcp-next
# These existed in ghidra-mcp-next but not here, which is how five mutations
# survived a round of review: hand-porting fixes across two repos leaves gaps.


@pytest.mark.parametrize(
    ("current", "bump", "expected"),
    [
        ("0.99.0", "patch", "0.99.1"),
        ("0.99.0", "minor", "0.100.0"),
        ("0.99.0", "major", "1.0.0"),
        ("0.100.3", "patch", "0.100.4"),
        ("1.2.3", "major", "2.0.0"),
    ],
)
def test_next_version_arithmetic(current: str, bump: str, expected: str):
    assert release.next_version(current, bump) == expected


def test_next_version_rejects_non_semver():
    with pytest.raises(release.ReleaseError, match="not semantic"):
        release.next_version("v12.1-20260603105209", "minor")


def test_refuses_a_tag_that_exists_locally(repo: Path):
    """The local check is separate from the origin one and must not be dropped."""
    git(repo, "tag", "v0.100.0")

    with pytest.raises(release.ReleaseError, match="already exists locally"):
        release.prepare(repo, "minor", recording_runner(repo))


def test_roll_inserts_the_new_unreleased_above_the_release(repo: Path):
    """Below is what the retired CI job did, and it misfiled a later entry."""
    release.prepare(repo, "minor", recording_runner(repo))
    text = (repo / "CHANGELOG.md").read_text(encoding="utf-8")

    assert text.index("## Unreleased") < text.index("## 0.100.0")
    assert "- A thing worth releasing." in text.split("## 0.100.0", 1)[1]
    assert release.unreleased_section(repo / "CHANGELOG.md") == ""


def test_two_consecutive_releases_do_not_nest_headings(repo: Path):
    release.prepare(repo, "minor", recording_runner(repo))

    # A real new entry, so the empty-Unreleased guard does not reject release two.
    text = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
    text = text.replace("## Unreleased\n", "## Unreleased\n\n- Something new.\n", 1)
    (repo / "CHANGELOG.md").write_text(text, encoding="utf-8")
    git(repo, "commit", "-aqm", "more news")

    release.prepare(repo, "patch", recording_runner(repo))
    final = (repo / "CHANGELOG.md").read_text(encoding="utf-8")

    assert final.count("## Unreleased") == 1
    assert final.index("## Unreleased") < final.index("## 0.100.1")
    assert final.index("## 0.100.1") < final.index("## 0.100.0")


def test_the_full_gate_and_build_sets_are_present():
    """Narrowing pytest, or dropping `clean`, would otherwise pass unnoticed."""
    assert release.GATES == (
        (sys.executable, "-m", "pytest", "tests/", "--ignore=tests/test_live_vice.py"),
        ("bats", "test/import-prg.bats"),
    )
    assert release.BUILD == (
        ("./gradlew", "--no-daemon", "clean", "buildExtension"),
    )

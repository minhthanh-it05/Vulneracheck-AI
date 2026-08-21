"""
Unit tests for vulneracheck.pipeline.get_changed_files() (`--diff` mode) and
PipelineConfig/run_pipeline's mutually-exclusive-2-mode validation.

Uses a TEMPORARY git repo created via subprocess right in the test (no real
repo needed) — fast, no ONNX model needed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vulneracheck.pipeline import PipelineConfig, get_changed_files, run_pipeline


def _run_git(args: list[str], cwd: Path) -> None:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"git {args} failed: {result.stderr}"


def _commit(cwd: Path, message: str) -> None:
    _run_git(
        [
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test",
            "commit",
            "-m",
            message,
        ],
        cwd,
    )


@pytest.fixture
def temp_git_repo(tmp_path: Path) -> Path:
    """Creates a temporary git repo with 2 commits:
        commit1: adds file1.c, file3.c (unchanged in commit2)
        commit2: modifies file1.c, adds file2.c
    Returns the repo path.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(["init", "--quiet"], repo)

    (repo / "file1.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (repo / "file3.c").write_text("int unrelated(void) { return 1; }\n", encoding="utf-8")
    _run_git(["add", "file1.c", "file3.c"], repo)
    _commit(repo, "commit1: add file1.c, file3.c")

    (repo / "file1.c").write_text(
        "int main(void) { char buf[8]; strcpy(buf, \"x\"); return 0; }\n", encoding="utf-8"
    )
    (repo / "file2.c").write_text("void helper(void) {}\n", encoding="utf-8")
    _run_git(["add", "file1.c", "file2.c"], repo)
    _commit(repo, "commit2: modify file1.c, add file2.c")

    return repo


def test_get_changed_files_returns_only_changed_files(temp_git_repo: Path) -> None:
    changed = get_changed_files("HEAD~1..HEAD", temp_git_repo)
    changed_names = {p.name for p in changed}

    assert changed_names == {"file1.c", "file2.c"}
    assert "file3.c" not in changed_names


def test_get_changed_files_paths_are_real_files(temp_git_repo: Path) -> None:
    changed = get_changed_files("HEAD~1..HEAD", temp_git_repo)
    for p in changed:
        assert p.is_file()
        assert p.read_text(encoding="utf-8") != ""


def test_get_changed_files_not_a_git_repo_raises_clear_error(tmp_path: Path) -> None:
    not_a_repo = tmp_path / "plain_dir"
    not_a_repo.mkdir()

    with pytest.raises(RuntimeError, match="git"):
        get_changed_files("HEAD~1..HEAD", not_a_repo)


def test_get_changed_files_nonexistent_ref_raises_clear_error(temp_git_repo: Path) -> None:
    with pytest.raises(RuntimeError, match="that-ref-does-not-exist"):
        get_changed_files("that-ref-does-not-exist..HEAD", temp_git_repo)


def test_get_changed_files_empty_diff_returns_empty_list(temp_git_repo: Path) -> None:
    changed = get_changed_files("HEAD..HEAD", temp_git_repo)
    assert changed == []


def test_pipeline_config_rejects_both_target_path_and_diff_range(tmp_path: Path) -> None:
    config = PipelineConfig(
        target_path=tmp_path, diff_range="HEAD~1..HEAD", output_path=tmp_path / "out.json"
    )
    with pytest.raises(ValueError, match="mutually exclusive"):
        run_pipeline(config)


def test_pipeline_config_rejects_neither_target_path_nor_diff_range(tmp_path: Path) -> None:
    config = PipelineConfig(output_path=tmp_path / "out.json")
    with pytest.raises(ValueError):
        run_pipeline(config)

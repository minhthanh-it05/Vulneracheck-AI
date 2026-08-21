"""
pipeline: Orchestrator driving the 4-step cascade flow of VulneraCheck-AI.

Processing order (per-file, for Layer 1+2; Layer 3 runs once as a batch over
all candidates collected — see run_pipeline):
    1. secrets  (Layer 1) — scan 1 file for hardcoded secrets/API keys.
    2. parsers  (Layer 2) — parse the AST with Tree-sitter, apply .scm rules
       following the high-recall principle: forward EVERY "suspicious" code
       snippet (candidate sink) to the next step, accepting a high false
       positive rate at this step to avoid missing true positives.
    3. verifier (Layer 3) — use the GraphCodeBERT (ONNX) model to binary-classify
       each candidate: safe / vulnerable, filtering out some of Layer 2's false positives.
    4. reporting — merge results from all 3 layers, export a SARIF 2.1.0 report.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from vulneracheck.parsers import CandidateSink, LANGUAGE_RULE_MAP, TreeSitterEngine
from vulneracheck.reporting import (
    Finding,
    LOW_CONFIDENCE_CATEGORY_NOTE,
    LOW_CONFIDENCE_CWE_CATEGORIES,
    ML_NOT_SUPPORTED_NOTE,
    SarifReport,
    redact_secret,
)
from vulneracheck.secrets import SecretFinding, scan_file
from vulneracheck.verifier import ONNXVerifier, VerifierResult

# Sinks that do NOT get the low-confidence mitigation applied even though
# their CWE overlaps with LOW_CONFIDENCE_CWE_CATEGORIES. "delete"/"delete[]"
# (C++) shares CWE-416/CWE-476 codes with the memory-unsafe group
# (free/realloc/...) in the .scm rule, but does NOT have the same systematic
# false positive issue — on the contrary, confidence improved clearly after
# extending the snippet (0.66 -> 0.98). Explicitly excluded to avoid being
# caught just because it shares a CWE code with another group.
_LOW_CONFIDENCE_OVERRIDE_EXCLUDED_SINKS = {"delete"}

# File extension -> language supported by the verifier (Layer 3).
# .h is always treated as "c" (convention used when training the model); .hpp/.hh/.cc/.cxx are "cpp".
_EXTENSION_LANGUAGE_MAP = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".java": "java",
}

# Display name for the language_key (first segment of a LANGUAGE_RULE_MAP
# value) used when building the ml_unsupported summary warning. Different
# from _EXTENSION_LANGUAGE_MAP above: that map only serves Layer 3 (no
# "python" since Layer 3 doesn't support it); this map covers EVERY language
# Layer 2 supports, including languages outside Layer 3's scope.
_DISPLAY_LANGUAGE_NAMES = {
    "python": "Python",
    "java": "Java",
    "c": "C",
    "cpp": "C++",
}

# Directories always skipped when walking the directory tree (exact names, not patterns).
_SKIP_DIR_NAMES = {"node_modules", "__pycache__", "venv", ".venv"}

# Skip files larger than this threshold instead of reading them fully into RAM.
_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB

# Number of bytes read from the start of a file to guess whether it's binary (contains a null byte).
_BINARY_SNIFF_BYTES = 8192

_verifier_singleton: ONNXVerifier | None = None
_parser_engine_singleton: TreeSitterEngine | None = None


def _get_verifier() -> ONNXVerifier:
    """Initialize ONNXVerifier exactly once and reuse the session for every
    run_verifier_layer call within the process."""
    global _verifier_singleton
    if _verifier_singleton is None:
        from vulneracheck.verifier import (
            DEFAULT_MODEL_PATH,
            DEFAULT_THRESHOLD_CONFIG_PATH,
            DEFAULT_TOKENIZER_PATH,
        )

        _verifier_singleton = ONNXVerifier(
            model_path=DEFAULT_MODEL_PATH,
            tokenizer_path=DEFAULT_TOKENIZER_PATH,
            threshold_config_path=DEFAULT_THRESHOLD_CONFIG_PATH,
        )
    return _verifier_singleton


def _get_parser_engine() -> TreeSitterEngine:
    """Initialize TreeSitterEngine exactly once — each language's
    Parser/Query is already cached inside TreeSitterEngine (see parsers/__init__.py)."""
    global _parser_engine_singleton
    if _parser_engine_singleton is None:
        _parser_engine_singleton = TreeSitterEngine()
    return _parser_engine_singleton


@dataclass
class PipelineConfig:
    """Configuration for a single pipeline scan run.

    Exactly 1 of 2 modes, never both and never neither (checked at the
    start of run_pipeline):
        - target_path: scan a whole file or directory (legacy mode).
        - diff_range: only scan files changed between 2 git refs, e.g.
          "origin/main..HEAD" (newer mode, uses repo_root as where git runs).
    """

    target_path: Path | None = None
    diff_range: str | None = None
    repo_root: Path = field(default_factory=Path.cwd)
    output_path: Path = Path("report.sarif.json")


@dataclass
class PipelineResult:
    """Aggregate result after running the full 4-step cascade."""

    secret_findings: list[SecretFinding] = field(default_factory=list)
    candidate_sinks: list[CandidateSink] = field(default_factory=list)
    verified_findings: list[VerifierResult] = field(default_factory=list)
    report: SarifReport | None = None
    ml_unsupported_warning: str | None = None


def run_secrets_layer(file_path: Path) -> list[SecretFinding]:
    """
    Layer 1: Regex/pattern scan on 1 file (calls secrets.scan_file directly).

    Input:
        file_path: path to 1 source file to scan.
    Output:
        List of SecretFinding — every hardcoded secret/API key detected.
        This layer's results go straight into the final report, WITHOUT going through the verifier.
    """
    return scan_file(str(file_path))


def run_parsers_layer(file_path: Path) -> list[CandidateSink]:
    """
    Layer 2: Parse the AST with Tree-sitter and apply the .scm rule matching the file's language.

    Input:
        file_path: path to 1 source file to scan.
    Output:
        List of CandidateSink — high-recall, forwards ALL matches found,
        with no further filtering here (filtering is the job of the .scm rule or Layer 3).
        A file in a language outside the supported scope returns an empty list.
    """
    engine = _get_parser_engine()
    return engine.parse_file(str(file_path))


def run_verifier_layer(candidates: list[CandidateSink]) -> list[VerifierResult]:
    """
    Layer 3: Run GraphCodeBERT (ONNX) inference on each candidate sink.

    The threshold is no longer a single shared parameter — each language
    (c/cpp/java) has its own threshold and uncertain-zone, read from
    weights/threshold_config.json (see vulneracheck.verifier.ONNXVerifier).

    Input:
        candidates: list of CandidateSink from Layer 2 (collected from all
        scanned files). The language is inferred from the file_path
        extension; a candidate in a language outside SUPPORTED_ML_LANGUAGES
        is still returned with status="ML_NOT_SUPPORTED" instead of being silently dropped.
    Output:
        List of VerifierResult in the same order as the input candidates —
        uses predict_batch (1 ONNX session call for the whole batch), not a
        predict() loop per candidate.
    """
    verifier = _get_verifier()
    items = [
        (candidate.snippet, _EXTENSION_LANGUAGE_MAP.get(Path(candidate.file_path).suffix, ""))
        for candidate in candidates
    ]
    return verifier.predict_batch(items)


def _display_language_name(file_path: str) -> str:
    """Display language name for the user, inferred from LANGUAGE_RULE_MAP
    (Layer 2 — broader scope than Layer 3, includes "python" too). An
    extension with no .scm rule (shouldn't happen here since this is only
    called for a candidate that already went through Layer 2) falls back to
    the extension itself."""
    extension = Path(file_path).suffix
    rule_file = LANGUAGE_RULE_MAP.get(extension)
    if rule_file is None:
        return extension.lstrip(".") or "unknown"
    language_key = rule_file.split("/", 1)[0]
    return _DISPLAY_LANGUAGE_NAMES.get(language_key, language_key)


def build_ml_unsupported_warning(
    verified_candidates: list[tuple[CandidateSink, VerifierResult]]
) -> str | None:
    """Build a single SUMMARY warning line (not repeated per finding) when
    there are candidates with ml_verified=False — informs the user that
    those findings are based only on Layer 1+2, not yet filtered for
    precision by Layer 3, so confidence is much lower than C/C++/Java.

    Returns None if every candidate is ml_verified=True (nothing to warn
    about) — the caller (CLI) only prints the warning when the return value is not None.
    """
    unsupported = [
        (candidate, result)
        for candidate, result in verified_candidates
        if not result.ml_verified
    ]
    if not unsupported:
        return None

    languages = sorted({_display_language_name(candidate.file_path) for candidate, _ in unsupported})
    return (
        f"⚠️  {len(unsupported)} candidate(s) from language(s) {', '.join(languages)} not yet "
        "AI-verified (Layer 1+2 only) — confidence is much lower than "
        "C/C++/Java, needs closer manual review."
    )


def run_reporting_layer(
    secret_findings: list[SecretFinding],
    verified_candidates: list[tuple[CandidateSink, VerifierResult]],
    output_path: Path,
) -> SarifReport:
    """
    Merge Layer 1 (secrets) and Layer 3 (verified candidates) results into a
    single SARIF 2.1.0 report, written to output_path.

    Input:
        secret_findings: results from run_secrets_layer (collected from all scanned files).
        verified_candidates: (CandidateSink, VerifierResult) pairs at the
        same position — need both to build the SARIF location (file/line)
        and the model result, since VerifierResult alone doesn't carry file_path/line.
        output_path: path to the output SARIF file.
    Output:
        SarifReport, already written to disk at output_path.

    Finding output rules:
        - Secret: ALWAYS redact the real value via redact_secret() before
          putting it in the message — SecretFinding.matched_text contains
          the raw secret, which must never leak into SARIF/PR comments.
        - Candidate ml_verified=False (language not supported by Layer 3):
          still emits a finding (Layer 2 already matched a dangerous sink),
          severity="warning", with properties noting it hasn't gone through ML so confidence is lower.
        - Candidate status="UNCERTAIN_NEEDS_REVIEW": emits a finding,
          severity="warning" — the model isn't confident enough to conclude on its own.
        - Candidate label=1 and status="OK": emits a finding, severity="error"
          — the model confirms it's vulnerable.
        - Candidate label=0 and status="OK": does NOT emit a finding — the
          model confirms it's safe, which is exactly the false positive that Layer 3 exists to filter out.

    Systematic false positive mitigation (see docs/model_card.md): for every
    finding the verifier DID run (ml_verified=True — both UNCERTAIN and
    label=1/OK), if candidate.cwe is in LOW_CONFIDENCE_CWE_CATEGORIES
    (buffer-copy, memory-unsafe, format-string — the group confirmed to have
    9/9 safe samples flagged incorrectly), severity is forced to "warning"
    regardless of the actual confidence/label, with
    properties.low_confidence_category=true plus an explanatory note. The
    real confidence number is NOT stripped/rounded — it stays as-is in
    properties for transparency. "delete" is explicitly excluded despite
    sharing the CWE code (see _LOW_CONFIDENCE_OVERRIDE_EXCLUDED_SINKS)
    because it does not have the same issue.
    """
    def _apply_low_confidence_override(finding: Finding, candidate: CandidateSink) -> None:
        if candidate.sink_name in _LOW_CONFIDENCE_OVERRIDE_EXCLUDED_SINKS:
            return
        if any(cwe in LOW_CONFIDENCE_CWE_CATEGORIES for cwe in candidate.cwe):
            finding.severity = "warning"
            finding.extra_properties["low_confidence_category"] = True
            finding.extra_properties["note"] = LOW_CONFIDENCE_CATEGORY_NOTE

    report = SarifReport()

    for finding in secret_findings:
        redacted = redact_secret(finding.matched_text)
        report.add(
            Finding(
                rule_id=f"secret/{finding.rule_id}",
                message=f"Hardcoded secret detected (rule: {finding.rule_id}): {redacted}",
                file_path=finding.file_path,
                start_line=finding.line,
                severity="error",
                confidence=1.0,
            )
        )

    for candidate, result in verified_candidates:
        cwe_suffix = f" [{', '.join(candidate.cwe)}]" if candidate.cwe else ""
        base_properties = {"cwe": candidate.cwe} if candidate.cwe else {}

        if not result.ml_verified:
            report.add(
                Finding(
                    rule_id=f"sink/{candidate.sink_name}",
                    message=(
                        f"Candidate sink '{candidate.sink_name}'{cwe_suffix} detected by "
                        "Layer 2, NOT YET verified by Layer 3 (ML) because this language is "
                        "outside the model's supported scope."
                    ),
                    file_path=candidate.file_path,
                    start_line=candidate.line,
                    start_column=candidate.column,
                    severity="warning",
                    confidence=0.0,
                    extra_properties={
                        **base_properties,
                        "ml_verified": False,
                        "note": ML_NOT_SUPPORTED_NOTE,
                    },
                )
            )
            continue

        if result.status == "UNCERTAIN_NEEDS_REVIEW":
            uncertain_finding = Finding(
                rule_id=f"sink/{candidate.sink_name}",
                message=(
                    f"Candidate sink '{candidate.sink_name}'{cwe_suffix} — the model isn't "
                    f"confident enough to conclude (confidence={result.confidence:.3f} falls "
                    "within the uncertain zone), needs manual review."
                ),
                file_path=candidate.file_path,
                start_line=candidate.line,
                start_column=candidate.column,
                severity="warning",
                confidence=result.confidence or 0.0,
                extra_properties={
                    **base_properties,
                    "ml_verified": True,
                    "status": result.status,
                    "label": result.label,
                },
            )
            _apply_low_confidence_override(uncertain_finding, candidate)
            report.add(uncertain_finding)
        elif result.label == 1:
            vulnerable_finding = Finding(
                rule_id=f"sink/{candidate.sink_name}",
                message=(
                    f"Candidate sink '{candidate.sink_name}'{cwe_suffix} — the model confirms "
                    f"it is VULNERABLE (confidence={result.confidence:.3f})."
                ),
                file_path=candidate.file_path,
                start_line=candidate.line,
                start_column=candidate.column,
                severity="error",
                confidence=result.confidence or 0.0,
                extra_properties={
                    **base_properties,
                    "ml_verified": True,
                    "status": result.status,
                    "label": result.label,
                },
            )
            _apply_low_confidence_override(vulnerable_finding, candidate)
            report.add(vulnerable_finding)
        # label == 0 and status == "OK": the model confirms it's safe -> no
        # finding is emitted (this is exactly the false positive that Layer 3 exists to filter out).

    report.write(output_path)
    return report


def _is_probably_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return True
    return b"\x00" in chunk


def _should_scan_file(path: Path) -> bool:
    """Checks size + binary status. Does not check for symlink-escape here —
    that only matters when walking a directory tree (see
    _iter_scannable_files); a file passed directly as the target is an
    explicit user choice, not the result of automatic traversal, so there's
    no "wandering off" risk."""
    try:
        size = path.stat().st_size
    except OSError:
        print(f"[vulneracheck] Skipping {path} (could not read file size).", file=sys.stderr)
        return False
    if size > _MAX_FILE_SIZE_BYTES:
        print(
            f"[vulneracheck] Skipping {path} (size {size} bytes > "
            f"{_MAX_FILE_SIZE_BYTES} bytes, avoiding reading it fully into RAM).",
            file=sys.stderr,
        )
        return False
    if _is_probably_binary(path):
        print(f"[vulneracheck] Skipping {path} (suspected to be a binary file).", file=sys.stderr)
        return False
    return True


def _resolve_safe_path(file_path: Path, root_real: Path) -> Path | None:
    """Returns the resolved real path if file_path is a regular file, inside
    root_real, and not a symlink; returns None (with a stderr warning) if
    excluded. Shared by both directory traversal (_iter_scannable_files) and
    --diff mode (get_changed_files) to apply the exact same set of safety
    conditions, without duplicating the logic in 2 places.
    """
    try:
        if file_path.is_symlink():
            print(
                f"[vulneracheck] Skipping {file_path} (symlink, not followed to avoid "
                "path traversal).",
                file=sys.stderr,
            )
            return None
        real_path = file_path.resolve()
        if not real_path.is_relative_to(root_real):
            print(
                f"[vulneracheck] Skipping {file_path} (resolves outside the root directory "
                f"{root_real}).",
                file=sys.stderr,
            )
            return None
        if not real_path.is_file():
            return None
    except OSError:
        return None
    return real_path


def _iter_scannable_files(root: Path):
    """Safely walks the directory tree:
        - skips .git/, node_modules/, __pycache__/, venv/.venv/, and any
          other hidden directory starting with "." (including .git, since it also starts with ".");
        - does NOT follow symlinks (followlinks=False when walking the
          directory, and skips any file that is a symlink or resolves
          outside root — blocks path traversal via a malicious symlink pointing outside the scanned directory);
        - skips files that are too large or suspected binary (see _should_scan_file).
    """
    root_real = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames if not d.startswith(".") and d not in _SKIP_DIR_NAMES
        ]
        for filename in filenames:
            file_path = Path(dirpath) / filename
            real_path = _resolve_safe_path(file_path, root_real)
            if real_path is not None and _should_scan_file(real_path):
                yield file_path


def get_changed_files(diff_range: str, repo_root: Path) -> list[Path]:
    """Gets the list of changed files between 2 refs via `git diff --name-only
    <diff_range>`, run in repo_root.

    Applies the EXACT SAME safety conditions as regular directory traversal
    (size, binary, symlink, outside root) via
    _resolve_safe_path/_should_scan_file — reused, not rewritten. A file
    deleted in the diff (no longer present at head) is automatically
    excluded since _resolve_safe_path checks is_file().

    diff_range: format "<base_ref>..<head_ref>", e.g. "origin/main..HEAD".

    Raises:
        RuntimeError if the `git` command is not found, repo_root is not a
        git repo, or a ref in diff_range does not exist (with a message
        explaining common causes, e.g. missing a deep enough `git fetch` in CI).
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", diff_range],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "`git` command not found in PATH — Git must be installed to use --diff."
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"`git diff --name-only {diff_range}` failed at {repo_root} "
            f"(exit code {result.returncode}). Common causes: "
            f"{repo_root} is not a git repo, or a ref in '{diff_range}' "
            "does not exist (in CI, needs a deep enough `git fetch`/checkout — see "
            f"fetch-depth). Details from git: {result.stderr.strip()}"
        )

    root_real = repo_root.resolve()
    files: list[Path] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        file_path = repo_root / line
        real_path = _resolve_safe_path(file_path, root_real)
        if real_path is not None and _should_scan_file(real_path):
            files.append(file_path)
    return files


def run_pipeline(config: PipelineConfig) -> PipelineResult:
    """
    Runs the full cascade: secrets -> parsers -> verifier -> reporting.

    Input:
        config: PipelineConfig — exactly 1 of 2 modes:
            - target_path: scan 1 file or 1 directory (whole).
            - diff_range: only scan files changed between 2 git refs (e.g.
              for a PR), obtained via get_changed_files(config.diff_range,
              config.repo_root).
        Setting both or neither raises ValueError — the 2 scan modes are
        independent and mutually exclusive.
    Output:
        PipelineResult containing each layer's intermediate results and the
        final report (already written to config.output_path).

    Execution order: Layer 1 (secrets) and Layer 2 (parsers) run
    sequentially PER FILE. Layer 3 (verifier) runs ONCE as a batch over ALL
    CandidateSink collected from every file (using predict_batch, not
    calling the model separately per file) — much more efficient than many
    small per-file batches, while still satisfying the requirement that
    "Layer 3 only runs on CandidateSink, not on the whole file".
    """
    if config.target_path is not None and config.diff_range is not None:
        raise ValueError(
            "PipelineConfig can only set 1 of the 2: target_path or diff_range, "
            "not both (the 2 scan modes are mutually exclusive)."
        )
    if config.target_path is None and config.diff_range is None:
        raise ValueError("PipelineConfig needs target_path or diff_range to be set.")

    if config.diff_range is not None:
        files = get_changed_files(config.diff_range, config.repo_root)
    else:
        target_path = Path(config.target_path)
        if target_path.is_file():
            files = [target_path] if _should_scan_file(target_path) else []
        else:
            files = list(_iter_scannable_files(target_path))

    result = PipelineResult()
    all_candidates: list[CandidateSink] = []

    for file_path in files:
        result.secret_findings.extend(run_secrets_layer(file_path))
        candidates = run_parsers_layer(file_path)
        result.candidate_sinks.extend(candidates)
        all_candidates.extend(candidates)

    verifier_results = run_verifier_layer(all_candidates)
    result.verified_findings = verifier_results

    verified_candidates = list(zip(all_candidates, verifier_results))
    result.ml_unsupported_warning = build_ml_unsupported_warning(verified_candidates)
    result.report = run_reporting_layer(
        result.secret_findings, verified_candidates, config.output_path
    )

    return result

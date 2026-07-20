#!/usr/bin/env python3
"""
rust_repair_codeql_pipeline_v6.py

Methodology definitions
-----------------------
1. "as_generated_compiles":
   Whether the ORIGINAL raw sample, before any repair, successfully completes
   `cargo build` in its original location and structure.

   - If the original sample already contains a Cargo project root with Cargo.toml,
     the pipeline attempts `cargo build` there and records:
       original_build_attempted = yes
       as_generated_compiles = yes|no

   - If the original sample is not directly build-attemptable as a Cargo project
     (for example, a raw folder of .rs files or a single .rs file without Cargo.toml),
     the pipeline records:
       original_build_attempted = no
       as_generated_compiles = no
       initial_compile_category = missing_project_structure

2. "repaired_compiles":
   Whether the REPAIRED COPY in the parallel repaired tree successfully completes
   `cargo build` after repair operations are applied.

3. Originals are never modified in place.

4. CodeQL eligibility:
   Only repaired samples that pass `cargo build` are eligible for CodeQL.

5. Manual security review stage:
   This stage is HEURISTIC TRIAGE ONLY. It surfaces potentially security-relevant
   patterns for follow-up review. It is not definitive vulnerability confirmation.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, asdict, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

MOD_DECL_RE = re.compile(r"^\s*(pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$", re.MULTILINE)
FN_MAIN_RE = re.compile(r"\bfn\s+main\s*\(")
INNER_ATTR_RE = re.compile(r"^\s*#!\[[^\]]+\]\s*$", re.MULTILINE)

COMPILE_ERROR_PATTERNS = [
    ("missing_dependency", re.compile(r"(?i)(use of undeclared crate or module|can't find crate|failed to resolve)")),
    ("bad_import", re.compile(r"(?i)(unresolved import|could not find .* in .*)")),
    ("wrong_crate_api", re.compile(r"(?i)(no function or associated item|no method named|private associated function|trait bound .* not satisfied)")),
    ("type_mismatch", re.compile(r"(?i)(mismatched types|expected .* found .*|type annotations needed)")),
    ("nonce_length_error", re.compile(r"(?i)(nonce.*(length|size)|expected an array with a size of 12|generic-array|typenum)")),
    ("key_length_error", re.compile(r"(?i)(key.*(length|size)|expected an array with a size of (16|24|32))")),
    ("borrow_checker", re.compile(r"(?i)(cannot borrow .* as mutable|borrow of moved value|does not live long enough|cannot move out of)")),
    ("missing_main", re.compile(r"(?i)(main function not found|`main` function not found)")),
    ("syntax_error", re.compile(r"(?i)(expected one of|mismatched closing delimiter|unexpected closing delimiter|unclosed delimiter|this file contains an unclosed delimiter)")),
]

CRYPTO_CONTEXT_PATTERNS = [
    re.compile(r"(?i)\baes\b"),
    re.compile(r"(?i)\baes_gcm\b"),
    re.compile(r"(?i)\bchacha20poly1305\b"),
    re.compile(r"(?i)\bcipher\b"),
    re.compile(r"(?i)\baead\b"),
    re.compile(r"(?i)\bencrypt\b"),
    re.compile(r"(?i)\bdecrypt\b"),
    re.compile(r"(?i)\bnonce\b"),
    re.compile(r"(?i)\bsecret\b"),
    re.compile(r"(?i)\bkey\b"),
    re.compile(r"(?i)\biv\b"),
    re.compile(r"(?i)\btag\b"),
    re.compile(r"(?i)\bfrom_slice\b"),
    re.compile(r"(?i)\bnew_from_slice\b"),
    re.compile(r"(?i)\bseal\b"),
    re.compile(r"(?i)\bopen\b"),
]

HARDCODED_NONCE_PATTERNS = [
    re.compile(r"(?i)\bnonce\s*[:=][^;\n]*\[[^\]]+\]"),
    re.compile(r"(?i)\blet\s+\w*nonce\w*\s*[:=][^;\n]*\[[^\]]+\]"),
    re.compile(r"(?i)\bconst\s+\w*NONCE\w*\b[^=]*=\s*\[[^\]]+\]"),
    re.compile(r"(?i)\bstatic\s+\w*NONCE\w*\b[^=]*=\s*\[[^\]]+\]"),
    re.compile(r'(?i)\bnonce\s*[:=][^;\n]*b"[^"]+"'),
    re.compile(r'(?i)\bconst\s+\w*NONCE\w*\b[^=]*=\s*b"[^"]+"'),
    re.compile(r'(?i)\bstatic\s+\w*NONCE\w*\b[^=]*=\s*b"[^"]+"'),
    re.compile(r'(?i)\bnonce\s*[:=][^;\n]*vec!\s*\[[^\]]+\]'),
]

HARDCODED_KEY_PATTERNS = [
    re.compile(r"(?i)\bconst\s+\w*KEY\w*\b[^=]*=\s*\[[^\]]+\]"),
    re.compile(r"(?i)\bstatic\s+\w*KEY\w*\b[^=]*=\s*\[[^\]]+\]"),
    re.compile(r'(?i)\b(?:key|secret)\s*[:=][^;\n]*b"[^"]+"'),
    re.compile(r'(?i)\bconst\s+\w*(?:KEY|SECRET)\w*\b[^=]*=\s*b"[^"]+"'),
    re.compile(r'(?i)\bstatic\s+\w*(?:KEY|SECRET)\w*\b[^=]*=\s*b"[^"]+"'),
]

WEAK_RANDOM_PATTERNS = [
    re.compile(r"(?i)\bthread_rng\s*\("),
    re.compile(r"(?i)\brand::random\s*<"),
    re.compile(r"(?i)\bStdRng\b"),
    re.compile(r"(?i)\bseed_from_u64\s*\("),
]

INSECURE_MISC_PATTERNS = [
    ("panic_on_crypto", re.compile(r"(?i)\.(unwrap|expect)\s*\(")),
    ("debug_secret_leak", re.compile(r"(?i)\b(println!|eprintln!|dbg!)\b")),
]

CSV_DIALECT = "excel"


@dataclass
class SampleRecord:
    sample_id: str
    original_path: str
    repaired_path: str
    original_project_root: str
    repaired_project_root: str
    original_build_attempted: str
    as_generated_compiles: str
    repaired_compiles: str
    initial_compile_category: str
    repaired_compile_category: str
    initial_compile_rc: str
    repaired_compile_rc: str
    initial_compile_log_path: str
    repaired_compile_log_path: str
    repair_log_path: str
    repair_actions: str
    codeql_attempted: str
    codeql_succeeded: str
    codeql_db_path: str
    codeql_create_log_path: str
    codeql_analyze_log_path: str
    sarif_path: str
    manual_review_report_path: str
    sample_report_path: str
    codeql_findings_count: int
    manual_findings_count: int
    created_at_utc: str


@dataclass
class CodeQLFinding:
    sample_id: str
    rule_id: str
    rule_name: str
    severity: str
    precision: str
    message: str
    artifact_path: str
    start_line: str
    start_column: str
    end_line: str
    end_column: str
    cwe: str
    tags: str
    help_uri: str
    sarif_path: str


@dataclass
class ManualFinding:
    sample_id: str
    finding_id: str
    category: str
    severity: str
    security_relevant: str
    rationale: str
    note: str
    artifact_path: str
    line_number: str
    code_excerpt: str
    review_type: str
    report_path: str


@dataclass
class ValidationResult:
    name: str
    ok: str
    detail: str


@dataclass
class RepairOutcome:
    actions: List[str]
    log_path: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def dataclass_fieldnames(cls) -> List[str]:
    return [f.name for f in fields(cls)]


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    ensure_parent(path)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, obj) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path: Path, rows: List[dict], fieldnames: List[str]) -> None:
    ensure_parent(path)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, dialect=CSV_DIALECT, extrasaction="raise")
        writer.writeheader()
        for row in rows:
            row_keys = set(row.keys())
            field_keys = set(fieldnames)
            if row_keys != field_keys:
                missing = sorted(field_keys - row_keys)
                extra = sorted(row_keys - field_keys)
                raise ValueError(f"CSV schema mismatch for {path}: missing={missing}, extra={extra}")
            writer.writerow(row)


def run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        timeout=timeout,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def resolve_codeql(codeql_bin: str) -> Tuple[bool, str]:
    raw = (codeql_bin or "").strip()
    if not raw:
        return False, "empty CodeQL path/command"

    candidate = Path(raw).expanduser()

    if candidate.is_absolute() or "/" in raw:
        try:
            candidate = candidate.resolve(strict=False)
        except Exception:
            pass

        try:
            rc, out, err = run_cmd([str(candidate), "--version"], timeout=30)
            if rc == 0:
                return True, str(candidate)
            detail = (out or err).strip()
            return False, f"explicit CodeQL path failed version check: {candidate} :: {detail}"
        except FileNotFoundError:
            return False, f"explicit CodeQL path does not exist: {candidate}"
        except Exception as e:
            return False, f"explicit CodeQL path could not be executed: {candidate} :: {e}"

    resolved = which(raw)
    if not resolved:
        return False, f"CodeQL command not found in PATH: {raw}"

    try:
        rc, out, err = run_cmd([resolved, "--version"], timeout=30)
        if rc == 0:
            return True, resolved
        detail = (out or err).strip()
        return False, f"CodeQL command found but failed version check: {resolved} :: {detail}"
    except Exception as e:
        return False, f"CodeQL command found but could not be executed: {resolved} :: {e}"


def list_rust_sources(root: Path) -> List[Path]:
    return sorted(p for p in root.rglob("*.rs") if p.is_file())


def is_probable_binary_source(text: str) -> bool:
    return bool(FN_MAIN_RE.search(text))


def sanitize_package_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", name.strip())
    cleaned = cleaned.strip("_").lower() or "repaired_sample"
    if cleaned[0].isdigit():
        cleaned = f"sample_{cleaned}"
    return cleaned


def find_project_root_for_build(start_path: Path) -> Optional[Path]:
    cur = start_path.parent if start_path.is_file() else start_path
    cur = cur.resolve()
    while True:
        cargo_toml = cur / "Cargo.toml"
        if cargo_toml.exists():
            return cur
        if cur.parent == cur:
            return None
        cur = cur.parent


def gather_sample_inputs(input_root: Path) -> List[Path]:
    if input_root.is_file():
        return [input_root]
    return sorted(list(input_root.iterdir()))


def copy_sample_to_repaired_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    if src.is_dir():
        shutil.copytree(src, dst)
    else:
        dst.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst / src.name)


def infer_main_rs_target(sample_root: Path) -> Optional[Path]:
    rs_files = list_rust_sources(sample_root)
    if not rs_files:
        return None
    binaries = []
    for p in rs_files:
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if is_probable_binary_source(txt):
            binaries.append(p)
    if binaries:
        return binaries[0]
    return rs_files[0]


def guess_needed_dependencies(sample_root: Path) -> List[str]:
    deps: List[str] = []
    combined = []
    for rs in list_rust_sources(sample_root):
        try:
            combined.append(rs.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            pass
    blob = "\n".join(combined).lower()

    if "aes_gcm" in blob or "aes-gcm" in blob or "aes256gcm" in blob or "aes128gcm" in blob:
        deps.append("aes-gcm")
    if "chacha20poly1305" in blob:
        deps.append("chacha20poly1305")
    if "rand_core::" in blob and "rand::" not in blob:
        deps.append("rand_core")
    elif "osrng" in blob or "rand::" in blob:
        deps.append("rand")

    out = []
    seen = set()
    for d in deps:
        if d not in seen:
            out.append(d)
            seen.add(d)
    return out


def create_minimal_cargo_project(sample_root: Path, repair_actions: List[str]) -> Optional[Path]:
    existing = find_project_root_for_build(sample_root)
    if existing:
        repair_actions.append(f"existing_cargo_project:{existing}")
        return existing

    main_rs = infer_main_rs_target(sample_root)
    if main_rs is None:
        repair_actions.append("no_rust_source_found")
        return None

    cargo_root = sample_root
    src_dir = cargo_root / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    dep_lines = []
    for dep in guess_needed_dependencies(sample_root):
        if dep == "aes-gcm":
            dep_lines.append('aes-gcm = "0.10"')
        elif dep == "chacha20poly1305":
            dep_lines.append('chacha20poly1305 = "0.10"')
        elif dep == "rand":
            dep_lines.append('rand = "0.8"')
        elif dep == "rand_core":
            dep_lines.append('rand_core = "0.6"')

    cargo_toml = textwrap.dedent(
        f"""\
        [package]
        name = "{sanitize_package_name(cargo_root.name or 'repaired_sample')}"
        version = "0.1.0"
        edition = "2021"

        [dependencies]
        """
    )
    if dep_lines:
        cargo_toml += "\n".join(dep_lines) + "\n"

    write_text(cargo_root / "Cargo.toml", cargo_toml)
    repair_actions.append(f"created_cargo_toml:{cargo_root / 'Cargo.toml'}")

    target_main = src_dir / "main.rs"
    if main_rs.resolve() != target_main.resolve():
        shutil.copy2(main_rs, target_main)
        repair_actions.append(f"copied_main_rs:{main_rs}=>{target_main}")

    return cargo_root


def repair_duplicate_inner_attributes(text: str, actions: List[str], path: Path) -> str:
    lines = text.splitlines()
    seen_inner = set()
    changed = False
    new_lines = []
    for line in lines:
        if INNER_ATTR_RE.match(line):
            if line.strip() in seen_inner:
                new_lines.append(f"// repaired_duplicate_inner_attr: {line}")
                changed = True
            else:
                seen_inner.add(line.strip())
                new_lines.append(line)
        else:
            new_lines.append(line)
    if changed:
        actions.append(f"commented_duplicate_inner_attrs:{path}")
    return "\n".join(new_lines) + ("\n" if text.endswith("\n") else "")


def comment_out_missing_mod_decls(project_root: Path, text: str, actions: List[str], path: Path) -> str:
    changed = False
    lines = text.splitlines()
    new_lines = []
    for line in lines:
        m = re.match(r"^\s*(pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$", line)
        if not m:
            new_lines.append(line)
            continue
        mod_name = m.group(2)
        mod_rs = project_root / "src" / f"{mod_name}.rs"
        mod_dir_rs = project_root / "src" / mod_name / "mod.rs"
        if not mod_rs.exists() and not mod_dir_rs.exists():
            new_lines.append(f"// repaired_missing_mod_decl: {line}")
            changed = True
        else:
            new_lines.append(line)
    if changed:
        actions.append(f"commented_missing_mod_decls:{path}")
    return "\n".join(new_lines) + ("\n" if text.endswith("\n") else "")


def repair_rust_sources(project_root: Path, repair_log_path: Path, repair_actions: List[str]) -> RepairOutcome:
    for rs in list_rust_sources(project_root):
        original = rs.read_text(encoding="utf-8", errors="ignore")
        updated = original
        if rs.name == "main.rs":
            updated = repair_duplicate_inner_attributes(updated, repair_actions, rs)
            updated = comment_out_missing_mod_decls(project_root, updated, repair_actions, rs)
        if updated != original:
            rs.write_text(updated, encoding="utf-8")
    write_text(repair_log_path, "\n".join(repair_actions) + ("\n" if repair_actions else "no_repairs_applied\n"))
    return RepairOutcome(actions=list(repair_actions), log_path=str(repair_log_path))


def detect_compile_category(build_output: str) -> str:
    for category, pattern in COMPILE_ERROR_PATTERNS:
        if pattern.search(build_output or ""):
            return category
    return "unknown_compile_failure"


def build_rust_project(project_root: Path, log_path: Path) -> Tuple[bool, int, str]:
    rc, out, err = run_cmd(["cargo", "build"], cwd=project_root, timeout=900)
    merged = f"$ cargo build\n[rc={rc}]\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}\n"
    write_text(log_path, merged)
    return rc == 0, rc, ("ok" if rc == 0 else detect_compile_category(merged))


def create_codeql_database(project_root: Path, db_path: Path, log_path: Path, codeql_bin: str) -> Tuple[bool, str]:
    cmd = [
        codeql_bin, "database", "create", str(db_path),
        "--language=rust",
        "--source-root", str(project_root),
        "--command", "cargo build",
        "--overwrite",
    ]
    rc, out, err = run_cmd(cmd, cwd=project_root, timeout=3600)
    merged = f"$ {' '.join(cmd)}\n[rc={rc}]\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}\n"
    write_text(log_path, merged)
    return rc == 0, str(log_path)


def run_codeql_analyze(db_path: Path, sarif_path: Path, log_path: Path, codeql_bin: str) -> Tuple[bool, str]:
    cmd = [
        codeql_bin, "database", "analyze", str(db_path),
        "--format=sarifv2.1.0",
        "--output", str(sarif_path),
        "codeql/rust-queries:codeql-suites/rust-security-and-quality.qls",
    ]
    rc, out, err = run_cmd(cmd, timeout=3600)
    merged = f"$ {' '.join(cmd)}\n[rc={rc}]\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}\n"
    write_text(log_path, merged)
    return rc == 0, str(log_path)


def parse_sarif_findings(sample_id: str, sarif_path: Path) -> List[CodeQLFinding]:
    if not sarif_path.exists():
        return []
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    findings: List[CodeQLFinding] = []

    for run in data.get("runs", []):
        rules_by_id = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            rules_by_id[rule.get("id", "")] = rule

        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId", "")
            rule = rules_by_id.get(rule_id, {})
            props = rule.get("properties", {}) or {}
            tags = props.get("tags", []) or []
            cwes = [t for t in tags if str(t).startswith("external/cwe/cwe-")]
            loc = (result.get("locations") or [{}])[0]
            ploc = loc.get("physicalLocation", {}) or {}
            region = ploc.get("region", {}) or {}

            findings.append(
                CodeQLFinding(
                    sample_id=sample_id,
                    rule_id=rule_id,
                    rule_name=str(rule.get("name", "")),
                    severity=str(result.get("level", "")),
                    precision=str(props.get("precision", "")),
                    message=str(result.get("message", {}).get("text", "")),
                    artifact_path=str(ploc.get("artifactLocation", {}).get("uri", "")),
                    start_line=str(region.get("startLine", "")),
                    start_column=str(region.get("startColumn", "")),
                    end_line=str(region.get("endLine", "")),
                    end_column=str(region.get("endColumn", "")),
                    cwe=",".join(cwes),
                    tags="|".join(map(str, tags)),
                    help_uri=str(rule.get("helpUri", "")),
                    sarif_path=str(sarif_path),
                )
            )
    return findings


def has_crypto_context_near(lines: List[str], idx: int, window: int = 5) -> bool:
    start = max(0, idx - window)
    end = min(len(lines), idx + window + 1)
    context = "\n".join(lines[start:end])
    return any(p.search(context) for p in CRYPTO_CONTEXT_PATTERNS)


def build_manual_review_report(sample_id: str, findings: List[ManualFinding]) -> str:
    lines = [
        "Manual Security Review Report (Heuristic Triage Only)",
        f"Sample ID: {sample_id}",
        "",
        "Important note:",
        "- This stage is heuristic triage only.",
        "- Findings are candidate signals for analyst follow-up, not definitive vulnerability confirmation.",
        "- Treat security_relevant=no findings as contextual weak signals unless corroborated by deeper review.",
        "",
    ]
    if not findings:
        lines.append("No heuristic manual findings detected.")
        return "\n".join(lines) + "\n"

    for f in findings:
        lines.append(f"[{f.finding_id}] {f.category} severity={f.severity} security_relevant={f.security_relevant}")
        lines.append(f"file: {f.artifact_path}:{f.line_number}")
        lines.append(f"code: {f.code_excerpt}")
        lines.append(f"rationale: {f.rationale}")
        lines.append(f"note: {f.note}")
        lines.append("")
    return "\n".join(lines) + "\n"


def manual_security_triage(sample_id: str, scan_root: Path, report_path: Path) -> List[ManualFinding]:
    findings: List[ManualFinding] = []
    counter = 1

    for rs in list_rust_sources(scan_root):
        lines = rs.read_text(encoding="utf-8", errors="ignore").splitlines()
        for i, line in enumerate(lines):
            code_excerpt = line.strip()
            nearby_crypto = has_crypto_context_near(lines, i, window=5)

            for patt in HARDCODED_NONCE_PATTERNS:
                if patt.search(line):
                    findings.append(
                        ManualFinding(
                            sample_id=sample_id,
                            finding_id=f"MF-{counter:04d}",
                            category="hardcoded_nonce",
                            severity="medium",
                            security_relevant="yes" if nearby_crypto else "no",
                            rationale="Literal or constant nonce material detected; fixed nonces can break AEAD security when reused.",
                            note="Heuristic triage only; confirm actual runtime reuse and cipher context before treating as a vulnerability.",
                            artifact_path=str(rs),
                            line_number=str(i + 1),
                            code_excerpt=code_excerpt,
                            review_type="heuristic_triage",
                            report_path=str(report_path),
                        )
                    )
                    counter += 1

            for patt in HARDCODED_KEY_PATTERNS:
                if patt.search(line):
                    findings.append(
                        ManualFinding(
                            sample_id=sample_id,
                            finding_id=f"MF-{counter:04d}",
                            category="hardcoded_key_or_secret",
                            severity="high",
                            security_relevant="yes" if nearby_crypto else "no",
                            rationale="Literal or static key/secret material detected in source.",
                            note="Heuristic triage only; validate whether this is test data, dead code, or real secret exposure.",
                            artifact_path=str(rs),
                            line_number=str(i + 1),
                            code_excerpt=code_excerpt,
                            review_type="heuristic_triage",
                            report_path=str(report_path),
                        )
                    )
                    counter += 1

            for patt in WEAK_RANDOM_PATTERNS:
                if patt.search(line) and nearby_crypto:
                    findings.append(
                        ManualFinding(
                            sample_id=sample_id,
                            finding_id=f"MF-{counter:04d}",
                            category="weak_or_non_csprng_randomness",
                            severity="medium",
                            security_relevant="yes",
                            rationale="Potentially unsuitable randomness source used near cryptographic context.",
                            note="Heuristic triage only; some uses may be benign unless the randomness feeds keys, nonces, IVs, or salts.",
                            artifact_path=str(rs),
                            line_number=str(i + 1),
                            code_excerpt=code_excerpt,
                            review_type="heuristic_triage",
                            report_path=str(report_path),
                        )
                    )
                    counter += 1

            for category, patt in INSECURE_MISC_PATTERNS:
                if patt.search(line) and nearby_crypto:
                    findings.append(
                        ManualFinding(
                            sample_id=sample_id,
                            finding_id=f"MF-{counter:04d}",
                            category=category,
                            severity="low" if category == "panic_on_crypto" else "medium",
                            security_relevant="yes",
                            rationale="Potentially risky pattern found in cryptographic or secret-handling context.",
                            note="Heuristic triage only; validate whether it creates a real security issue in reachable production code.",
                            artifact_path=str(rs),
                            line_number=str(i + 1),
                            code_excerpt=code_excerpt,
                            review_type="heuristic_triage",
                            report_path=str(report_path),
                        )
                    )
                    counter += 1

    write_text(report_path, build_manual_review_report(sample_id, findings))
    return findings


def make_sample_report(sample: SampleRecord, codeql_findings: List[CodeQLFinding], manual_findings: List[ManualFinding]) -> str:
    lines = [
        f"Sample report for {sample.sample_id}",
        "=" * 80,
        "",
        "Methodology notes",
        "- as_generated_compiles refers to the original sample before any repair.",
        "- repaired_compiles refers to the repaired copy after pipeline repair steps.",
        "- Manual findings below are heuristic triage only, not definitive vulnerability confirmation.",
        "",
        "Build and repair summary",
        f"- original_path: {sample.original_path}",
        f"- repaired_path: {sample.repaired_path}",
        f"- original_build_attempted: {sample.original_build_attempted}",
        f"- as_generated_compiles: {sample.as_generated_compiles}",
        f"- repaired_compiles: {sample.repaired_compiles}",
        f"- initial_compile_category: {sample.initial_compile_category}",
        f"- repaired_compile_category: {sample.repaired_compile_category}",
        f"- repair_actions: {sample.repair_actions}",
        f"- initial_compile_log_path: {sample.initial_compile_log_path}",
        f"- repaired_compile_log_path: {sample.repaired_compile_log_path}",
        f"- repair_log_path: {sample.repair_log_path}",
        "",
        "CodeQL",
        f"- attempted: {sample.codeql_attempted}",
        f"- succeeded: {sample.codeql_succeeded}",
        f"- codeql_db_path: {sample.codeql_db_path}",
        f"- codeql_create_log_path: {sample.codeql_create_log_path}",
        f"- codeql_analyze_log_path: {sample.codeql_analyze_log_path}",
        f"- sarif_path: {sample.sarif_path}",
        f"- codeql_findings_count: {len(codeql_findings)}",
        "",
    ]

    if codeql_findings:
        lines.append("CodeQL findings")
        for f in codeql_findings:
            lines.append(f"- [{f.rule_id}] {f.rule_name} severity={f.severity} path={f.artifact_path}:{f.start_line} message={f.message}")
        lines.append("")

    lines.append("Manual review findings (heuristic triage only)")
    lines.append(f"- manual_findings_count: {len(manual_findings)}")
    for f in manual_findings:
        lines.append(
            f"- [{f.finding_id}] {f.category} severity={f.severity} security_relevant={f.security_relevant} "
            f"path={f.artifact_path}:{f.line_number} note={f.note}"
        )

    return "\n".join(lines) + "\n"


def validate_environment(codeql_bin: str, require_codeql: bool = False) -> List[ValidationResult]:
    results: List[ValidationResult] = []
    results.append(ValidationResult(name="python", ok="yes", detail=sys.version.replace("\n", " ")))

    if which("cargo"):
        rc, out, err = run_cmd(["cargo", "--version"], timeout=30)
        results.append(ValidationResult("cargo", "yes" if rc == 0 else "no", (out or err).strip()))
    else:
        results.append(ValidationResult("cargo", "no", "cargo not found in PATH"))

    if which("rustc"):
        rc, out, err = run_cmd(["rustc", "--version"], timeout=30)
        results.append(ValidationResult("rustc", "yes" if rc == 0 else "no", (out or err).strip()))
    else:
        results.append(ValidationResult("rustc", "no", "rustc not found in PATH"))

    codeql_ok, codeql_detail = resolve_codeql(codeql_bin)
    if codeql_ok:
        rc, out, err = run_cmd([codeql_detail, "--version"], timeout=30)
        results.append(ValidationResult("codeql", "yes" if rc == 0 else "no", (out or err).strip()))
    else:
        results.append(ValidationResult("codeql", "no" if require_codeql else "optional-missing", codeql_detail))

    return results


def write_validation_report(path: Path, results: List[ValidationResult]) -> None:
    lines = ["Validation report", "=" * 80, ""]
    for r in results:
        lines.append(f"- {r.name}: ok={r.ok} detail={r.detail}")
    write_text(path, "\n".join(lines) + "\n")


def process_sample(
    sample_input: Path,
    repaired_root: Path,
    reports_root: Path,
    codeql_root: Path,
    enable_codeql: bool,
    codeql_bin: str,
) -> Tuple[SampleRecord, List[CodeQLFinding], List[ManualFinding]]:
    sample_id = sample_input.stem if sample_input.is_file() else sample_input.name
    repaired_path = repaired_root / sample_id
    sample_dir = reports_root / sample_id

    sample_report_path = sample_dir / "sample_report.txt"
    manual_review_report_path = sample_dir / "manual_review.txt"
    initial_compile_log_path = sample_dir / "initial_build.log"
    repaired_compile_log_path = sample_dir / "repaired_build.log"
    repair_log_path = sample_dir / "repair.log"
    codeql_create_log_path = sample_dir / "codeql_create.log"
    codeql_analyze_log_path = sample_dir / "codeql_analyze.log"
    codeql_db_path = codeql_root / sample_id / "db"
    sarif_path = codeql_root / sample_id / "results.sarif"

    copy_sample_to_repaired_tree(sample_input, repaired_path)

    original_project_root = find_project_root_for_build(sample_input)
    original_build_attempted = "yes" if original_project_root else "no"

    if original_project_root:
        as_generated_compiles_bool, initial_rc, initial_category = build_rust_project(original_project_root, initial_compile_log_path)
    else:
        as_generated_compiles_bool = False
        initial_rc = -1
        initial_category = "missing_project_structure"
        write_text(initial_compile_log_path, "Original sample is not directly build-attemptable as a Cargo project.\n")

    repair_actions: List[str] = []
    repaired_project_root = create_minimal_cargo_project(repaired_path, repair_actions)

    if repaired_project_root is None:
        repaired_compiles_bool = False
        repaired_rc = -1
        repaired_category = "missing_project_structure"
        repair_outcome = RepairOutcome(actions=repair_actions, log_path=str(repair_log_path))
        write_text(repair_log_path, "\n".join(repair_actions) + ("\n" if repair_actions else "no_repairs_applied\n"))
        write_text(repaired_compile_log_path, "Repaired sample could not be converted into a build-attemptable Cargo project.\n")
    else:
        repair_outcome = repair_rust_sources(repaired_project_root, repair_log_path, repair_actions)
        repaired_compiles_bool, repaired_rc, repaired_category = build_rust_project(repaired_project_root, repaired_compile_log_path)

    codeql_attempted = "no"
    codeql_succeeded = "no"
    codeql_findings: List[CodeQLFinding] = []

    if enable_codeql and repaired_compiles_bool:
        codeql_attempted = "yes"
        created, _ = create_codeql_database(repaired_project_root, codeql_db_path, codeql_create_log_path, codeql_bin)
        if created:
            analyzed, _ = run_codeql_analyze(codeql_db_path, sarif_path, codeql_analyze_log_path, codeql_bin)
            codeql_succeeded = "yes" if analyzed else "no"
            if analyzed:
                codeql_findings = parse_sarif_findings(sample_id, sarif_path)

    scan_root = repaired_project_root if repaired_project_root else repaired_path
    manual_findings = manual_security_triage(sample_id, scan_root, manual_review_report_path)

    record = SampleRecord(
        sample_id=sample_id,
        original_path=str(sample_input),
        repaired_path=str(repaired_path),
        original_project_root=str(original_project_root) if original_project_root else "",
        repaired_project_root=str(repaired_project_root) if repaired_project_root else "",
        original_build_attempted=original_build_attempted,
        as_generated_compiles="yes" if as_generated_compiles_bool else "no",
        repaired_compiles="yes" if repaired_compiles_bool else "no",
        initial_compile_category=initial_category,
        repaired_compile_category=repaired_category,
        initial_compile_rc=str(initial_rc),
        repaired_compile_rc=str(repaired_rc),
        initial_compile_log_path=str(initial_compile_log_path),
        repaired_compile_log_path=str(repaired_compile_log_path),
        repair_log_path=str(repair_outcome.log_path),
        repair_actions="|".join(repair_outcome.actions),
        codeql_attempted=codeql_attempted,
        codeql_succeeded=codeql_succeeded,
        codeql_db_path=str(codeql_db_path) if codeql_db_path.exists() else "",
        codeql_create_log_path=str(codeql_create_log_path) if codeql_create_log_path.exists() else "",
        codeql_analyze_log_path=str(codeql_analyze_log_path) if codeql_analyze_log_path.exists() else "",
        sarif_path=str(sarif_path) if sarif_path.exists() else "",
        manual_review_report_path=str(manual_review_report_path),
        sample_report_path=str(sample_report_path),
        codeql_findings_count=len(codeql_findings),
        manual_findings_count=len(manual_findings),
        created_at_utc=utc_now_iso(),
    )

    write_text(sample_report_path, make_sample_report(record, codeql_findings, manual_findings))
    return record, codeql_findings, manual_findings


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Rust repair + build + CodeQL + heuristic triage pipeline")
    p.add_argument("--input-root", default="generated_code", help="Input file or directory")
    p.add_argument("--output-root", default="pipeline_output", help="Output root directory")
    p.add_argument("--enable-codeql", action="store_true", help="Enable CodeQL for repaired compilable samples")
    p.add_argument("--codeql-bin", default="codeql", help="Path to CodeQL executable or command name in PATH")
    p.add_argument("--validate-only", action="store_true", help="Validate environment and exit without processing samples")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    codeql_ok, codeql_detail = resolve_codeql(args.codeql_bin)
    if args.enable_codeql and not codeql_ok:
        print(f"ERROR: --enable-codeql was requested, but CodeQL is unavailable: {codeql_detail}", file=sys.stderr)
        return 4

    output_root = Path(args.output_root)
    repaired_root = output_root / "projects_repaired"
    reports_root = output_root / "reports"
    codeql_root = output_root / "codeql"
    summary_root = output_root / "summary"

    if args.validate_only:
        results = validate_environment(args.codeql_bin, require_codeql=args.enable_codeql)
        write_validation_report(summary_root / "validation_report.txt", results)
        write_csv(summary_root / "validation_report.csv", [asdict(r) for r in results], dataclass_fieldnames(ValidationResult))
        print(f"Validation complete. Report: {summary_root / 'validation_report.txt'}")
        return 0

    input_root = Path(args.input_root)
    if not input_root.exists():
        print(f"Input root does not exist: {input_root}", file=sys.stderr)
        return 2

    samples = gather_sample_inputs(input_root)
    if not samples:
        print(f"No samples found under {input_root}", file=sys.stderr)
        return 3

    sample_records: List[SampleRecord] = []
    codeql_findings_all: List[CodeQLFinding] = []
    manual_findings_all: List[ManualFinding] = []

    for sample in samples:
        try:
            rec, cqf, mf = process_sample(
                sample_input=sample,
                repaired_root=repaired_root,
                reports_root=reports_root,
                codeql_root=codeql_root,
                enable_codeql=args.enable_codeql,
                codeql_bin=codeql_detail if codeql_ok else args.codeql_bin,
            )
            sample_records.append(rec)
            codeql_findings_all.extend(cqf)
            manual_findings_all.extend(mf)
        except Exception as e:
            sample_id = sample.stem if sample.is_file() else sample.name
            err_report = reports_root / sample_id / "fatal_error.txt"
            write_text(err_report, f"Fatal processing error for {sample_id}: {e}\n")
            sample_records.append(
                SampleRecord(
                    sample_id=sample_id,
                    original_path=str(sample),
                    repaired_path=str(repaired_root / sample_id),
                    original_project_root="",
                    repaired_project_root="",
                    original_build_attempted="no",
                    as_generated_compiles="no",
                    repaired_compiles="no",
                    initial_compile_category="pipeline_exception",
                    repaired_compile_category="pipeline_exception",
                    initial_compile_rc="",
                    repaired_compile_rc="",
                    initial_compile_log_path="",
                    repaired_compile_log_path="",
                    repair_log_path="",
                    repair_actions="",
                    codeql_attempted="no",
                    codeql_succeeded="no",
                    codeql_db_path="",
                    codeql_create_log_path="",
                    codeql_analyze_log_path="",
                    sarif_path="",
                    manual_review_report_path="",
                    sample_report_path=str(err_report),
                    codeql_findings_count=0,
                    manual_findings_count=0,
                    created_at_utc=utc_now_iso(),
                )
            )

    summary_root.mkdir(parents=True, exist_ok=True)
    write_csv(summary_root / "samples.csv", [asdict(r) for r in sample_records], dataclass_fieldnames(SampleRecord))
    write_csv(summary_root / "codeql_findings.csv", [asdict(r) for r in codeql_findings_all], dataclass_fieldnames(CodeQLFinding))
    write_csv(summary_root / "manual_findings.csv", [asdict(r) for r in manual_findings_all], dataclass_fieldnames(ManualFinding))
    write_json(summary_root / "samples.json", [asdict(r) for r in sample_records])

    print(f"Done. Outputs written under: {output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
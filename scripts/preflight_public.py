#!/usr/bin/env python3
"""Pre-publication safety and completeness check for the GHOST showcase repo."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_RUST_ROOT = ROOT / "examples" / "rust-showcase"

REQUIRED_ASSETS = [
    ROOT / "assets/ghost-showcase.png",
    ROOT / "assets/validation-summary.png",
    ROOT / "assets/prelaunch-flow.png",
    ROOT / "evidence/test-results/public-validation-summary.txt",
    ROOT / "evidence/test-results/three-node-e2e-pass.txt",
    ROOT / ".github/ISSUE_TEMPLATE/evaluation-interest.yml",
    ROOT / ".github/DISCUSSION_TEMPLATE/evaluation-interest.yml",
    ROOT / "INTEREST-GROUP.md",
    ROOT / ".gitattributes",
    ROOT / "examples/rust-showcase/Cargo.toml",
    ROOT / "examples/rust-showcase/src/main.rs",
]

FORBIDDEN_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".env", ".sqlite", ".db"}

SECRET_PATTERNS = [
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("generic-secret-assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]

OBSOLETE_TERMS = [
    "WAITLIST_FORM_URL_GOES_HERE",
    "CONTACT_EMAIL_GOES_HERE",
    "SECURITY_CONTACT_GOES_HERE",
    "ghost-demo.mp4",
]


def iter_files():
    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT)
        if ".git" in rel.parts or "__pycache__" in rel.parts or "target" in rel.parts:
            continue
        yield p


def read_text(path: Path):
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def local_md_links(text: str):
    return re.findall(r"\[[^\]]+\]\((?!https?://|mailto:|#)([^)]+)\)", text)


def main() -> int:
    blockers = []
    warnings = []
    files = list(iter_files())

    for path in files:
        rel = path.relative_to(ROOT)

        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            blockers.append(f"Forbidden/sensitive file type present: {rel}")

        if path.suffix.lower() == ".rs":
            try:
                path.resolve().relative_to(PUBLIC_RUST_ROOT.resolve())
            except ValueError:
                blockers.append(f"Rust source exists outside the approved public showcase example: {rel}")

        text = read_text(path)
        if text is None:
            continue

        for obsolete in OBSOLETE_TERMS:
            if obsolete in text and rel != Path("scripts/preflight_public.py"):
                blockers.append(f"Obsolete placeholder/asset reference remains in {rel}: {obsolete}")

        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                blockers.append(f"Possible {label} detected in {rel}")

        if path.suffix.lower() == ".md":
            for target in local_md_links(text):
                target = target.split("#", 1)[0]
                if not target:
                    continue
                candidate = (path.parent / target).resolve()
                try:
                    candidate.relative_to(ROOT.resolve())
                except ValueError:
                    blockers.append(f"Link escapes repository in {rel}: {target}")
                    continue
                if not candidate.exists():
                    blockers.append(f"Broken local link in {rel}: {target}")

    for asset in REQUIRED_ASSETS:
        if not asset.exists():
            blockers.append(f"Required showcase asset missing: {asset.relative_to(ROOT)}")

    if not (ROOT / "README.md").read_text(encoding="utf-8").startswith("# GHOST Secure Text Mesh"):
        blockers.append("README title is missing or unexpected")

    print("GHOST PUBLIC SHOWCASE PREFLIGHT")
    print("=" * 31)
    print(f"BLOCKERS: {len(set(blockers))}")
    for item in sorted(set(blockers)):
        print(f"  - {item}")

    print(f"WARNINGS: {len(warnings)}")
    for item in warnings:
        print(f"  - {item}")

    if blockers:
        print("\nRESULT: BLOCKED — fix blockers before publishing.")
        return 1

    print("\nRESULT: PASS — automated showcase checks passed. Complete a final manual IP/security review before publishing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

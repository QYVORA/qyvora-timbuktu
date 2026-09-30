# TIMBUKTU — Documentation Index

**Status:** `CURRENT` (this index) · **Last reviewed:** 2026-09-30

TIMBUKTU is incident response & digital forensics over offline case files.

## Pipeline and rules

```
SOURCE → INTEGRITY → ARTIFACTS → FILESYSTEM → MEMORY → LOGS → TIMELINE → INDICATORS → RISK
```

Rules: DFI-001…DFI-013.

## Safety boundary

`forensics.live` is disabled by default and the corresponding safety
operation is refused — `timbuktu.live.acquisition` is refused. Secrets are redacted in output.

## What is actually written

**Authoritative for this tool, and currently non-empty:**

- `../README.md` — purpose, install, quick start, CLI, capabilities, safety

Cross-project contracts (authoritative, non-empty):

- [QYVORA-ECOSYSTEM.md](../../../../knowledge/qyvora-docs/09-technical/cross-project/QYVORA-ECOSYSTEM.md)
- [QYVORA-TOOL-OUTPUT-SPEC.md](../../../../knowledge/qyvora-docs/09-technical/cross-project/QYVORA-TOOL-OUTPUT-SPEC.md)
- [07-products overview](../../../../knowledge/qyvora-docs/07-products/timbuktu/)

## Known gap — placeholder files (`UNVERIFIED`)

**27 Markdown files in this repository are zero-byte placeholders.**
They are tracked in git but contain no content, so they must not be
cited as documentation. This file is the honest index; the placeholders
are left in place rather than filled with placeholder prose, and are
tracked for completion.

Repository root:

- `CHANGELOG.md`
- `CODE_OF_CONDUCT.md`
- `CONTRIBUTING.md`
- `GOVERNANCE.md`
- `SECURITY.md`
- `SUPPORT.md`

`docs/` (21 placeholders):

- `docs/Architecture.md`
- `docs/Artifact-Analysis.md`
- `docs/CLI.md`
- `docs/Configuration.md`
- `docs/Console.md`
- `docs/Development.md`
- `docs/Evidence-Acquisition.md`
- `docs/Evidence.md`
- `docs/File-System-Analysis.md`
- `docs/Getting-Started.md`
- `docs/Indicators.md`
- `docs/Installation.md`
- `docs/Investigation.md`
- `docs/Log-Analysis.md`
- `docs/Memory-Analysis.md`
- `docs/Reporting.md`
- `docs/Roadmap.md`
- `docs/Security-Model.md`
- `docs/Targets.md`
- `docs/Timeline-Analysis.md`
- `docs/Validation.md`

Related root files that are **also** zero-byte: `LICENSE`, `NOTICE`.
Until they are populated, this tool's license is `UNVERIFIED` even
though its README shows a license badge. See
[`00-audit/LEGAL_REVIEW_REGISTER.md`](../../../../knowledge/qyvora-docs/00-audit/LEGAL_REVIEW_REGISTER.md).

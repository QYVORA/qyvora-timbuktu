# QYVORA Timbuktu — Security Capability Audit

| Field | Value |
|-------|-------|
| Repository | `frameworks/qyvora-timbuktu` |
| Branch / commit | `main` @ `1bb7621` (working tree clean at audit start and after every probe) |
| Binary under test | `bin/timbuktu` — 9,277,703 bytes, untracked build artefact |
| Reported version | `v0.1.0`, commit `1bb7621`, built 2026-10-21T01:20:57Z with go1.27.1 linux/amd64 |
| Audit date | 2026-10-21 |
| Audit type | Static source review + local, offline binary probes + test/vet execution |
| Feature code changed | **None** (this file is the only artefact created) |

**Status vocabulary (used throughout):** `IMPLEMENTED` · `PARTIALLY IMPLEMENTED` · `STUBBED` · `PLANNED` · `MISSING` · `UNVERIFIED`.
**Priority vocabulary:** `P0` critical · `P1` high · `P2` medium · `P3` low.

Evidence is marked **verified** (observed from the built binary or an executed test) or **inferred** (read from source, not executed).

---

## 1. Framework identity and intended domain

Timbuktu is a **defensive, offline DFIR triage framework**. It is not a network offensive tool and ships no scanner, exploit or packet code. Its domain, per the repo README and the ecosystem definition, is:

- ingest a *forensic case* (a normalised JSON document describing evidence, files, processes, logs, registry artifacts, network artifacts and a timeline),
- run a deterministic analysis pipeline over that case,
- emit findings, evidence, indicators, a timeline, a risk score and reports.

The CLI adopts the shared QYVORA tier grammar (`timbuktu <tier> <module> [action] [target]`, `docs/CLI.md:5`), but all tier commands with real behaviour are hidden legacy verbs (`assess`, `case`, `findings`, `evidence`, `sources`, `target`) rather than tier modules. Live acquisition is deliberately refused (`internal/capabilities/capabilities.go:79-80`, `:90-91`).

Intended consumers: a human analyst at a terminal and, prospectively, the QYVORA AI orchestrator consuming `capabilities -o json`, `version -o json`, JSON results and the JSONL event stream.

## 2. Audit scope and evidence sources

| Evidence | Detail | Result |
|----------|--------|--------|
| Git state | `git status --porcelain`, `git log -1` | Clean tree, `main` @ `1bb7621` |
| Help capture | `docs/audit/help/timbuktu.txt` (243 lines, 2026-10-19) | Top-level commands: `capabilities, completion, exploit, help, recon, report, script, updates, version` |
| Binary probes | `version -o json`; `capabilities -o json|yaml|markdown|html`; `sources -o json`; `rules -o json`; `assess --sim -o json`; `assess --case <missing|malformed>`; `--events stdout`; `exploit`; `console`; `tui`; unknown command/flag; bare invocation | All recorded below |
| Source review | `internal/` (23 packages, 53 `.go` files, 6,609 non-test LOC), `cmd/timbuktu`, `pkg/models`, `pkg/events`, `pkg/transport`, `pkg/utilities` | Reviewed |
| Tests | `GOPROXY=off go test ./... -count=1 -timeout 180s` | **PASS**, exit 0 |
| Static analysis | `GOPROXY=off go vet ./...` | **PASS**, exit 0 |
| Cross-project contract | `shared/qyvora-common/contract/contract.go`, `conformance/runner.go`, `docs/QYVORA-TOOL-OUTPUT-SPEC.md`, ecosystem doc | Reviewed |
| Docs | `README.md`, `docs/README.md`, `docs/CLI.md`, `docs/audit/help/timbuktu.txt` | Reviewed |

Probe isolation: all runtime probes ran from `/tmp/opencode/tb`; the repository tree was not written to. `git status` was re-verified clean after the probe and test runs.

## 3. Existing capability inventory

### 3.1 Machine-declared capabilities (`internal/capabilities/capabilities.go:81-92`)

| ID | Manifest name | `implemented` | `live` |
|----|---------------|---------------|--------|
| `forensics.acquisition` | evidence acquisition | true | false |
| `forensics.integrity` | evidence integrity verification | true | false |
| `forensics.artifacts` | artifact identification | true | false |
| `forensics.filesystem` | filesystem analysis | true | false |
| `forensics.memory` | memory-image analysis | true | false |
| `forensics.timeline` | timeline reconstruction | true | false |
| `forensics.logs` | log analysis | true | false |
| `forensics.indicators` | indicator extraction | true | false |
| `forensics.live` | live host acquisition | **false** | true |

### 3.2 Analysis pipeline (`internal/analysis/analyst.go:93-260`)

Nine ordered stages: **acquisition → integrity → artifacts → filesystem → memory → logs → timeline → analysis (rules) → risk**. Each stage is a `pipeline.Stage` with a stable ID and emits `stage.started` / `stage.completed` events. Observed on `assess --sim`: 76 JSONL events, 28 findings, 28 evidence items, 7 assets, score 100/`critical`.

### 3.3 Rule set (`internal/rules/builtin/builtin.go`, 487 lines; verified via `rules -o json`)

| Rule | Default severity | Name |
|------|------------------|------|
| DFI-001 | critical | Evidence integrity failure |
| DFI-002 | high | Autorun persistence |
| DFI-003 | high | Suspicious scheduled task |
| DFI-004 | high | Service with temp image path |
| DFI-005 | critical | Web shell deployed |
| DFI-006 | high | Suspicious files in unusual locations |
| DFI-007 | critical | Suspicious process activity |
| DFI-013 | high | Masquerading system binary |
| DFI-008 | high | Credential material on disk |
| DFI-009 | medium | Logon anomalies detected |
| DFI-010 | medium | Network indicators present |
| DFI-011 | medium | HOSTS file modification |
| DFI-012 | low | Timeline coverage gap |

(DFI-013 is registered between DFI-007 and DFI-008; cosmetic only.)

### 3.4 Other implemented surfaces

- **Case ingestion** — `forensics.Load`/`LoadFile` (`internal/forensics/forensics.go:204,225`), normalisation and validation (`:242,301`), deterministic marshal (`:319`).
- **Simulation** — `forensics.Simulate` (`internal/forensics/simulate.go:15`, 347 lines) produces a fixed synthetic case.
- **Evidence store** — `internal/evidence/evidence.go`, per-item SHA-256 (`pkg/models/evidence.go:22-33`), persisted owner-only 0600 in a 0700 directory (`evidence.go:58-73`).
- **Risk engine** — per-finding `ScoreFor` = `severity_weight × confidence × (exposure/5) × 40`, capped at 100 (`internal/risk/risk.go:77-103`); worst-case-aware, monotonic aggregation (`:115-147`).
- **Reporting** — `internal/reporting/reporting.go:22` writes reports; output printer supports terminal/json/yaml/markdown/html (`internal/output/output.go`), all five verified exit 0 on `capabilities -o <fmt>`.
- **Event stream** — 15 verbs (`internal/capabilities/capabilities.go:64-72`), JSONL with `schema_version: "1.0"`, `execution_id`, `framework`, `level`, `event`, `data`; default destination stderr, `--events stdout` supported (verified).
- **Script engine** — shared `qyvora-script v0.1.0`; `script build examples/assess.qs` prints a dry-run plan (verified exit 0).
- **Target manager** — persisted under `~/.config/qyvora/timbuktu/targets.json` (`internal/config/config.go:63,113`; `internal/cli/cli.go:565-592`).
- **Self-update** — `internal/selfupdate` with sha256 verification and archive extraction (`archive.go`, `selfupdate.go`); network egress only on explicit `updates`.

## 4. Capability status matrix

Manifest claim vs verified behaviour. "Claim" = `capabilities -o json`; "Verified" = what the code and binary actually do.

| Capability | Claim | Verified status | Evidence | Notes |
|------------|-------|-----------------|----------|-------|
| `forensics.acquisition` | implemented | **PARTIALLY IMPLEMENTED** | `forensics.LoadFile` reads a supplied JSON case | "Acquisition" is *case ingestion*, not evidence acquisition; no device/collection code |
| `forensics.integrity` | implemented | **IMPLEMENTED** (bounded) | `VerifyIntegrity` recomputes SHA-256 over `Evidence[].Content` (`internal/forensics/detect.go:21-40`) | Verifies only in-payload strings; items without `Content` are skipped, not failed; no append-only hash chain |
| `forensics.artifacts` | implemented | **PARTIALLY IMPLEMENTED** | `SuspiciousArtifacts` (`detect.go:252`), kinds are pre-labelled in the case JSON (`pkg/models`, `simulate.go:140`) | Classification is heuristic over supplied `kind` strings; no binary artifact parsing |
| `forensics.filesystem` | implemented | **PARTIALLY IMPLEMENTED** | `SuspiciousFiles`, `MasqueradeSuspicion`, `TrustedSystemDir` (`detect.go:68-217`) | Path/name heuristics on a supplied file list; no filesystem image reader |
| `forensics.memory` | implemented | **PARTIALLY IMPLEMENTED** | `SuspiciousProcesses` (`detect.go:218-251`) | Heuristics over a supplied process list; no memory image parser |
| `forensics.timeline` | implemented | **IMPLEMENTED** | `BuildTimeline`, `sortTimeline`, `TimelineGap` (`detect.go:363-443`); DFI-012 | Operates on supplied timestamps |
| `forensics.logs` | implemented | **PARTIALLY IMPLEMENTED** | `LogAnomalies` over structured `Case.Logs` (`detect.go:281-326`) | No EVTX/syslog parser; entries must already be decoded into JSON |
| `forensics.indicators` | implemented | **IMPLEMENTED** | `ExtractIndicators` (`detect.go:347-362`) | Types: sha256/ip/domain/filename/registry_key/mutex/command |
| `forensics.live` | **not implemented** | **MISSING** (honest) | Manifest `:90-91`; `refuseLive` (`internal/cli/cli.go:594`) | Correctly refused; contract-aligned honesty |

### 4.1 Declared evidence sources (`sources -o json`, `internal/capabilities/capabilities.go:129-137`)

| Source | Claim (`implemented`, note) | Actual | Verdict |
|--------|-----------------------------|--------|---------|
| disk | true — "image file analysis" | No E01/raw/VHD reader exists (grep for `E01`, `ewf`, image parsing returns nothing) | **Overstated → PARTIAL (metadata only)** |
| memory | true — "memory image analysis" | No Volatility-style parser; only a process list in the case JSON | **Overstated → PARTIAL** |
| logs | true — "evtx/auth/syslog parsing" | No EVTX/syslog decoder; `evtx` appears only as a string kind/placeholder (`simulate.go:19,64,261`) | **Overstated → PARTIAL** |
| registry | true — "hive export analysis" | No hive parser; artifact kinds are pre-labelled (`simulate.go:21,80`) | **Overstated → PARTIAL** |
| browser | true — "browser profile analysis" | No SQLite/Chrome/Firefox reader found; browser data must arrive pre-normalised | **Overstated → PARTIAL** |
| prefetch | true — "prefetch analysis" | No PF parser; `.pf` appears only as a simulated path (`simulate.go:212-215`) | **Overstated → PARTIAL** |
| live | false — "not implemented" | Refused | Accurate |

**Assessment:** the forensic *reasoning* layer (rules, risk, timeline, indicators, evidence integrity) is genuinely implemented and tested; the *acquisition/parsing* layer it advertises is not. The documentation in `sources` implies raw-artifact support that does not exist.

## 5. Reconnaissance and discovery findings

Timbuktu has no network reconnaissance domain and correctly should not have one. What the `recon` tier actually exposes is **local case discovery**:

| Command | Behaviour | Verified |
|---------|-----------|----------|
| `case` | generate a deterministic sample forensic case | manifest `:95`, simulation source |
| `sources` | list supported evidence sources and status | verified exit 0 (but see §4.1) |
| `rules` | list 13 registered rules with severities/confidences | verified exit 0 |
| `target` | manage assessment targets (`add/list/use`) | source `cli.go:565-592`; persisted state observed |
| `assess` | run the pipeline (`--sim`, `--case`, `--profile`) | verified |

Observations:

- The tier name `recon` is semantically misleading: these commands are *case selection* and *introspection*, not reconnaissance. The manifest does not list the tier commands at all (see §12).
- `timbuktu assess <path>` **silently ignores the positional argument** (verified: `assess /nonexistent/case.json` fell back to the persisted target and reported `snapshot file not found: /tmp/opencode/trep/case.json`). Only `--case <path>` is honoured (`cli.go:419-427`). Cobra accepts arbitrary args on this command, so a scripted operator/orchestrator that passes a path positionally will analyse the *wrong* target without an error. This is an orchestration hazard (P2, safety-adjacent).
- Bare `timbuktu` prints help and exits 0 (verified); there is no interactive console despite `README.md:62,86`.

## 6. Analysis and assessment findings

- The pipeline is deterministic for identical inputs: `sim` runs emit the same 28 findings, 7 assets and score 100 (`critical`). `simulate.go` is a fixture generator, not a random generator.
- Result document (verified top-level keys): `id, framework, target, profile, sim, started_at, completed_at, assets, findings, evidence, events, score, level`. This is a **flat, tool-specific shape**, *not* `contract.Result` (`identity`, `context`, `findings`, `evidence`, `risk`, `events` — `shared/qyvora-common/contract/contract.go:100-108`). There is **no `schema_version` on the result document** (only on the event stream).
- Risk: per-finding formula matches the output spec (`severity × confidence × exposure/5 × 40`, cap 100 — `risk.go:77-103`); aggregation is worst-case-aware and monotonic (`risk.go:115-147`). Good: the score cannot be diluted by many low findings.
- Evidence linkage: each finding carries evidence IDs, and evidence items carry a content hash (`pkg/models/evidence.go:22-33`). Findings→evidence→source is traceable **within a run**, but there is no cross-item hash chain, no signature and no custodian record, so this is *integrity verification*, not full chain-of-custody.
- Integrity stage semantics: `VerifyIntegrity` skips evidence without `Content`/`SHA256` rather than marking it unverifiable (`detect.go:26-29`). A case with hashes but no payloads therefore "passes" integrity silently. DFI-001 only fires on mismatches.
- Severity vocabulary is contract-correct: `critical/high/medium/low/informational` (`capabilities.go:73-75`), confidence `confirmed/observed/probable/possible/unknown/not_observed` (`:76-78`), matching `QYVORA-TOOL-OUTPUT-SPEC.md:206,229`.
- Determinism risk: findings/evidence order depends on case input order and stage iteration; no explicit stable sort of findings was observed in the result writer (UNVERIFIED whether ordering is guaranteed across runs on identical input; `sim` is stable because the fixture is fixed).

## 7. Exploitation-related capability findings

- The framework has **no exploitation capability and no offensive code**. `exploit` is a bare tier whose `RunE` returns `exit 2` with the honest message `exploit has no modules in this framework (assessment is offline and read-only)` (`internal/cli/cli.go:224-229`; verified exit 2).
- This refusal is honest but **exit-code-nonconformant**: the output spec defines `3` (`ExitUnsupported`) for "unsupported / refused" (`QYVORA-TOOL-OUTPUT-SPEC.md:27,30-32`; `contract.ExitUnsupported = 3`), and `internal/exitcode/exitcode.go:10-15` defines only `0/1/2/130`. An orchestrator cannot distinguish "domain unsupported" from "operator typed the command wrong".
- The `exploit` tier is nonetheless advertised in `--help` and in the embedded CLI grammar, which invites the mistake.
- No mitigation/bypass/payload logic exists anywhere in the tree (verified by package inventory and grep for raw-socket, packet, exploit packages: none).

## 8. High-level implementation candidates

These are *candidates for a later, separately authorised phase*. None was implemented.

| Candidate | Why it matters | Prerequisite | Suggested priority |
|-----------|----------------|--------------|--------------------|
| Real artifact parsers behind `sources` (EVTX, syslog/auth, registry hives, prefetch, browser SQLite) | Makes the `sources` contract truthful and lets analysts point Timbuktu at real exports | Go libraries (e.g. EVTX parser, go-sqlite), format fixtures, golden-file tests | **P1** |
| Disk-image reader (E01/raw) with filesystem walk (NTFS/ext) | Current "disk" support is metadata only; an analyst must pre-extract | Read-only image library; write-blocker policy; hash-on-open | **P1** |
| Optional memory-image adapter (Volatility export ingestion, then native) | Current memory stage is a process-list heuristic | Define normalised memory-export schema; document provenance | P2 |
| Append-only evidence ledger (hash chain + custodian + timestamp) | Upgrades integrity checks into defensible chain-of-custody | New `pkg/models` structure; no external deps needed | **P1** |
| Contract `Result` envelope + `schema_version` on result JSON | Required for orchestrator-safe parsing and cross-tool aggregation | Map existing fields to `identity/context/risk`; keep back-compat | **P1** |
| Exit `3` for domain-unsupported/refused paths | Orchestrator disambiguation; contract conformance | Add `exitcode.Unsupported`; map refusals | P2 |
| Signed report manifest (SHA-256 of report + case + evidence) | Report integrity for handover | Selfupdate already uses sha256; signing key policy | P2 |
| STIX 2.1 / MISP indicator export | Consumes `ExtractIndicators` output; high analyst value, low risk | Indicator-type mapping table | P2 |
| Cross-case correlation (same IOC/asset across cases) | Defensive value; currently single-case only | Case index store, deterministic merge rules | P3 |
| YARA scanning of supplied artifacts | Natural extension of artifact analysis | YARA binding decision (cgo vs pure-Go) | P3 |

## 9. Low-level deferred technique inventory

These are **specialist or hardware-dependent** and are correctly *not* implemented. They are recorded so they are not mistaken for oversights. All are `DEFERRED`; none is required to make the current domain coherent.

| Technique | Status | Why deferred | Evidence |
|-----------|--------|--------------|----------|
| Live disk acquisition (write blocker, USB/NVMe imaging) | **DEFERRED / MISSING** | Requires hardware integration, device enumeration and privileged raw I/O; explicitly refused today | `capabilities.go:90-91`, `cli.go:594` |
| Live memory acquisition (winpmem/AVML/LiME) | **DEFERRED** | Kernel driver/privileged agent; unsafe to improvise | same refusal path |
| Network/remote acquisition (SMB/WMI/SSH pull) | **DEFERRED** | Credentials, lateral movement optics, chain-of-custody | out of domain |
| Raw filesystem parsing / deleted-file recovery / carving | **DEFERRED** | Needs low-level FS parsers; large effort | not present |
| Full-disk encryption detection / key recovery | **DEFERRED** | Cryptographic + legal constraints | not present |
| Hardware write-blocker attestation | **DEFERRED** | Physical device integration | not present |
| Firmware/UEFI artifact analysis | **DEFERRED** | Specialist tooling and fixtures | not present |
| Kernel-level memory forensics (rootkit detection in memory) | **DEFERRED** | Requires memory image parsing first | not present |
| Malware emulation/sandbox detonation | **DEFERRED / OUT OF DOMAIN** | Execution safety, isolation infrastructure | not present |
| Damage/impact scoring beyond finding severity | **DEFERRED** | Needs business-context inputs not in the case model | `risk.go` scores findings only |

No deferred item above should be reclassified as irrelevant: each is a legitimate DFIR technique; they are simply outside the current offline-JSON boundary.

## 10. Common-layer conformance

| Contract area | Status | Evidence |
|---------------|--------|----------|
| Exit codes `0/1/2/130` | **CONFORMANT** | `internal/exitcode/exitcode.go`; verified: unknown cmd/flag → 2, invalid `-o` → 2, missing `--case` file → 2, malformed case JSON → 1, success → 0 |
| Exit code `3` (`Unsupported`) | **MISSING** | No constant; `exploit` refusal returns 2 (`cli.go:224-229`) |
| Version JSON | **CONFORMANT (superset)** | Emits `framework, version, commit, date, build_user, go_version, arch, os, website, support, built_in`; contract requires `framework, version` + optional `commit/date/os/arch` (`contract.go:77-84`) |
| Capability manifest | **NON-CONFORMANT SHAPE** | Emits a local schema (`framework, version, exit_codes, output_formats, event_verbs, severity_levels, confidence_levels, authorization_model, capabilities, commands`), not `contract.CapabilityManifest` (`framework, version, commands` with per-command `inputs/outputs/dangerous/authorization/emits/deterministic` — `contract.go:59-75`) |
| Result envelope | **NON-CONFORMANT** | Flat result; no `identity`/`context`/`risk`; no `schema_version` (see §6) |
| Event envelope | **CONFORMANT** | JSONL `schema_version: "1.0"`, `framework`, `timestamp`, `level`, `event`, `data`; verified default stderr and `--events stdout` |
| Event verbs | **PARTIAL** | 15 namespaced verbs; spec's generic set includes `run.started` style verbs — Timbuktu uses `scan.started`/`stage.*` (acceptable domain variance, but not identical across tools) |
| Capability/prerequisite declarations | **MISSING** | No `requires`/`capability IDs` on commands; no prerequisite model such as toha3ee's |
| TUI linkage (`qyvora-tui v0.11.0`) | **LINKED BUT DISABLED** | `go.mod` requires it; `internal/cli/tui.go` is `//go:build ignore`; `tui` command does not exist (verified exit 2) |
| Shared error types | **PARTIAL** | `internal/errors` + `pexit.NewExitError`; local, not `qyvora-common` |
| Conformance runner treatment | **WEAK** | `shared/qyvora-common/conformance/runner.go:159` groups timbuktu with tools that get `CapJSON`; version probe only; `README.md:118` claims 14/14 conformant |

The conformance engine currently validates *version JSON + exit codes + (for some tools) capabilities JSON presence/format*, not the `Result` envelope, not `schema_version`, and not `authorization`/`dangerous` metadata. Timbuktu passes despite the shape gaps above.

## 11. AI orchestration readiness

| Requirement | Status | Notes |
|-------------|--------|-------|
| Discover tool identity/version | **READY** | `version -o json` verified, semver `v0.1.0`, commit present |
| Discover capabilities | **READY (with caveat)** | `capabilities -o json` verified; caveat: claims exceed behaviour (§4) |
| Enumerate commands + args | **PARTIAL** | Manifest lists 8 commands ONLY; actual CLI has 9 top-level + 6 hidden verbs; no arg schemas, no `dangerous`, no `authorization` per command |
| Invoke deterministically | **READY** | `assess --sim`/`--case`; `-o json`; `--report-dir`; `--no-report` |
| Monitor execution | **READY** | JSONL events with `execution_id`, stage boundaries; `--events stdout|stderr|file` |
| Interpret results | **PARTIAL** | Rich flat JSON but no canonical envelope and no `schema_version`; risk block is `score`+`level` at top level, not `risk` object |
| Fetch evidence/provenance | **READY** | `evidence`/`findings` commands and result arrays; per-item SHA-256 |
| Distinguish outcome classes | **PARTIAL** | 0/1/2/130 only; no `3` for unsupported/refused |
| Cancel safely | **UNVERIFIED at runtime; code-verified** | `cli.go` maps `os.Interrupt` to `CodeInterrupt` (130); an attempted SIGINT probe was inconclusive because `assess --sim` completes in ~3 ms. Recommended: run `assess` on a large case under `--report-dir` and send SIGINT |
| Offline/air-gapped operation | **READY** | No network calls on assess path; only `updates` egresses |
| Safety/authorization metadata | **READY (honest)** | Declares offline-only, live refused |

**Verdict:** Timbuktu is *invocable and monitorable* by an orchestrator today, and its JSON is rich enough to interpret with a tool-specific adapter. It is **not yet contract-safe**: the result lacks the canonical envelope/`schema_version`, the command manifest is incomplete, and there is no `3` class. Those are P1 blockers for a generic orchestrator that does not special-case Timbuktu.

## 12. CLI, repository-layout, and documentation findings

### 12.1 CLI drift (verified)

| Finding | Evidence | Priority |
|---------|----------|----------|
| Positional target silently ignored on `assess` (falls back to persisted target) | probe; `cli.go:419-436` sets only `--case` | P2 |
| `timbuktu console` documented but absent (exit 2) | `README.md:62,86`; probe exit 2 | P2 |
| `timbuktu tui` documented (`docs/CLI.md:33`) but absent; `internal/cli/tui.go` is `//go:build ignore` | probe exit 2 | P2 |
| `docs/CLI.md` says "No recon-tier modules", "No report-tier modules" although `assess`, `case`, `sources`, `rules`, `target`, `report`, `findings`, `evidence` exist as hidden verbs | `docs/CLI.md:13-29` | P2 |
| `docs/CLI.md:39` documents `docs script <file>` (literal `docs` prefix) — typo for `timbuktu script` | `docs/CLI.md:39` | P3 |
| Capabilities manifest omits `version`, `rules`, `script`, `updates`, `completion`, `tiers`; includes only 8 of the actual surfaces | `capabilities.go:93-102` vs `docs/audit/help/timbuktu.txt` | **P1** (orchestration) |
| `sources` claims unimplemented parsers (§4.1) | `capabilities.go:129-137` | **P1** |

### 12.2 Repository layout

- Clean, conventional Go layout: `cmd/timbuktu`, `internal/*`, `pkg/{models,events,transport,utilities}`.
- **34 tracked zero-byte files** (verified `git ls-files` + size), including all four `scripts/*.sh`, `configs/config.example.yaml`, `examples/basic.{json,yaml}`, and 25 Markdown files.
- `docs/README.md:34` claims "27 Markdown files … are zero-byte placeholders" and lists `docs/CLI.md`, `SECURITY.md`, `LICENSE`, `NOTICE` as empty. Actual state: **25** zero-byte Markdown files; `docs/CLI.md` (1,074 B), `SECURITY.md` (1,241 B), `LICENSE` (1,070 B), `NOTICE` (1,060 B) are **populated**. The index is stale in both directions.
- `tests/` is an empty directory (no test files); all tests live beside code (19 `_test.go`, 1,768 lines).
- `reports/.gitkeep` zero-byte; generated reports are untracked/gitignored.
- `bin/timbuktu` (9.3 MB) is untracked; `bin/.gitkeep` tracked.
- `pkg/transport` and `pkg/utilities` exist but are not used by the forensic path (UNVERIFIED sibling-tool scaffolding; no imports from `internal`).
- Cosmetic dead code: `var _ = models.StateObserved // keep models import meaningful` (`capabilities.go:172`).

### 12.3 Documentation accuracy

| Document | Claim | Reality |
|----------|-------|---------|
| `README.md:62,86` | interactive console/REPL | absent; `tui.go` build-ignored; bare invocation prints help |
| `docs/CLI.md:13-29` | no recon/report modules | false for the legacy hidden verbs |
| `docs/README.md:34-70` | 27 zero-byte MD, lists CLI/SECURITY/LICENSE/NOTICE as empty | 25; those four populated |
| `docs/audit/help/timbuktu.txt` | 2026-10-19 capture | still matches current binary for top-level help (spot-checked; unknown-flag/cmd → 2) |

## 13. Testing and verification findings

| Check | Command | Result |
|-------|---------|--------|
| Unit/integration tests | `GOPROXY=off go test ./... -count=1 -timeout 180s` | **PASS** (exit 0) |
| Static analysis | `GOPROXY=off go vet ./...` | **PASS** (exit 0) |
| Deterministic assessment | `assess --sim -o json` | exit 0; 28 findings / 28 evidence / 7 assets / score 100 `critical` |
| Events routing | `assess --sim --events stdout` | JSONL on stdout (76 events); default stderr |
| Output modes | `capabilities -o {terminal,json,yaml,markdown,html}` | all exit 0; YAML is genuine YAML (yaml.v3) |
| Invalid output format | `capabilities -o bogus` | exit 2, message lists valid formats |
| Unknown command | `timbuktu bogus` | exit 2 |
| Unknown flag | `timbuktu --bogus` | exit 2 |
| Refused tier | `timbuktu exploit` | exit 2, honest message |
| Missing case file | `assess --case /nonexistent/case.json` | exit 2 (`snapshot file not found`) |
| Malformed case | `assess --case bad.json` | exit 1 (`loading case: parsing case: invalid character 'o' …`) |
| Script dry-run | `script build examples/assess.qs` | exit 0 |
| SIGINT → 130 | attempted | **UNVERIFIED** (command too short; code path exists) |

Test coverage is real (19 test files, including `forensics`, `risk`, `rules`, `pipeline`, `events`, `output`, `cli` event-destination tests). Gaps: no end-to-end CLI golden tests for the `assess` result shape; no tests for integrity-skip semantics; no contract-envelope tests (because the envelope is not used).

**Exit-code inconsistency observed:** "missing input file" is classified as *usage* (2) by Timbuktu, while toha3ee classifies the analogous missing-file case as *runtime* (1). Both are defensible individually; they are inconsistent cross-tool (P3 for this repo, relevant to the common-layer review).

## 14. Prioritized gaps and recommendations

**No P0 defects were identified.** The framework is honest about live acquisition and contains no offensive code.

### P1 — high

1. **`sources` overstates raw-artifact support** (`capabilities.go:129-137`). *Why:* an operator/orchestrator will route real EVTX/hive/E01/prefetch exports to a tool that cannot parse them, producing silent false negatives. *Evidence:* no parser code, placeholder kinds in `simulate.go`. *Recommendation (later phase):* either implement parsers or change notes to "normalised JSON only" and add a `format` field. *Prerequisite:* format fixtures + golden tests.
2. **Command manifest incomplete / result not contract-shaped.** *Why:* generic orchestration cannot discover `version/rules/script/updates/completion/tiers`, nor parse results without a bespoke adapter. *Evidence:* §11, §10. *Recommendation:* extend manifest with all commands + arg schemas; add `identity/context/risk` envelope and `schema_version`, or document a versioned Timbuktu schema.
3. **No `3` / Unsupported exit class.** *Why:* refused domains (`exploit`, live acquisition) are indistinguishable from invocation errors. *Evidence:* `exitcode.go:10-15`, `cli.go:224-229`. *Recommendation:* add `exitcode.Unsupported=3` and map refusals.

### P2 — medium

4. **Stale/incorrect documentation and placeholder inventory** (§12.2, §12.3): fix `docs/README.md` counts, `docs/CLI.md` tiers and `docs script` typo, remove/replace `console`/`tui` claims or implement the console in a later phase.
5. **Positional target silently ignored** on `assess` (orchestration safety): add `Args: cobra.NoArgs` or accept a positional path.
6. **Empty `configs/config.example.yaml`**: configuration is undocumented despite a config system (viper, 20+ keys); add a commented example.
7. **Empty `scripts/*.sh`** (build/install/release/test): either populate or delete; currently they look like broken entry points.
8. **Integrity stage skips unverifiable evidence silently** (`detect.go:26-29`): mark "unverified" explicitly and add a rule/field so analysts can see coverage.

### P3 — low

9. DFI rule registration order (DFI-013 between 007/008).
10. Zero timestamps persisted in target state (`~/.config/qyvora/timbuktu/targets.json`: `created_at`/`granted_at` `0001-01-01T00:00:00Z`) — data-quality bug in target creation.
11. Dead-code import keeper (`capabilities.go:172`).
12. `pkg/transport`/`pkg/utilities` unused by the forensic path — document or remove from the module surface.
13. Empty `tests/` directory alongside in-package tests is confusing.
14. `docs/audit/help` capture dated 2026-10-19 — refresh after CLI changes.

## 15. Dependencies, prerequisites, and unresolved questions

**Runtime/build dependencies (verified in `go.mod`):** Go directive `go 1.26.5` (binary built with go1.27.1); `qyvora-script v0.1.0`; `qyvora-tui v0.11.0` (linked, disabled); `cobra`, `viper`, `fatih/color`, `termenv`, `go.yaml.in/yaml/v3`. No cgo requirement observed for the assessed path.

**Operational prerequisites:** none for offline analysis; no root, no network. `updates` requires network and verifies sha256 of downloaded artifacts (`internal/selfupdate`).

**Unresolved questions:**

1. Is a 130-on-SIGINT runtime claim required? *Missing evidence:* a long-running case large enough to interrupt. *Procedure:* craft a large JSON case, run `assess --case big.json --report-dir /tmp/x`, send SIGINT, assert 130 and no partial report.
2. Does the orchestrator accept a tool-specific flat result, or must every tool emit `contract.Result`? *Missing:* a written orchestrator IPC decision.
3. Are the populated `LICENSE`/`NOTICE` the intended final texts (they changed 2026-10-07)? *Missing:* legal sign-off; see the central legal register.
4. Is `forensics.acquisition` intended to mean "case ingestion" in the ecosystem vocabulary? If so, rename for clarity.
5. `pkg/transport`/`pkg/utilities` provenance: shared-layer copy or abandoned scaffolding? Not resolved by import analysis.

## 16. Statement of no implementation

No feature was implemented, no code was refactored, no dependency was added or changed, and no existing user work was discarded during this audit. The only file created is this `AUDIT.md`. All runtime probes were offline and read-only; test/vet runs wrote only to Go's build cache and temporary directories outside the repository. The repository's `git status` was clean before and after the audit (the untracked `bin/timbuktu` build artefact predates it). Every recommendation in §8 and §14 is a *proposal for a later, separately authorised phase*, not an implemented change.

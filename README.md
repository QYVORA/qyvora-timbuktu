# Timbuktu

> **Incident response & digital forensics framework.**
> A terminal-first console and CLI for offline forensic case analysis:
> evidence integrity, artifacts, filesystem and memory surfaces, logs,
> timelines and indicators of compromise.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

Timbuktu is QYVORA's incident response & digital forensics framework for
**offline forensic case files** and deterministic simulations. It runs as
a shared terminal-first console **and** a one-shot CLI with identical
commands, and produces evidence-backed findings with transparent risk
scoring. **Live host acquisition is not implemented and is refused
honestly**; Timbuktu analyzes only the case files you explicitly provide.

- **One workflow, two surfaces** — the console commands equal the CLI
  commands.
- **Deterministic `--sim`** — fixed dataset exercises every rule, no
  acquired host required, CI-ready.
- **Offline only** — analyzes only the case files you explicitly provide.
- **Chain of custody** — every evidence item is content-hashed and
  integrity-verified; the tool never modifies evidence.
- **Status** — shipped at v0.1.0 (Go 1.26+, MIT).

## Installation

```sh
git clone https://github.com/QYVORA/qyvora-timbuktu.git
cd qyvora-timbuktu
make build
sudo make install          # /usr/local layout (root)
make install-user          # ~/.local layout (no root)
```

Or build the single static binary directly with the Go toolchain:

```sh
go build ./cmd/timbuktu
```

No release assets are published yet; `timbuktu updates` installs release
builds once the first verifiable release exists.

## Quickstart

Full assessment, no input required, deterministic:

```sh
timbuktu assess --sim       # risk 62/100 (high)
```

Generate a sample forensic case and assess it:

```sh
timbuktu case --sim
timbuktu assess case.sim.json
```

Interactive console (REPL on a real terminal; stdin piping uses a plain line reader):

```sh
timbuktu
assess --sim
findings
evidence
exit
```

Machine-readable output:

```sh
timbuktu capabilities -o json
timbuktu assess -o json
timbuktu report -o json
```

## Commands

```
assess        run the analysis pipeline against a case or simulation
capabilities  print the machine-readable capability contract
case          generate a deterministic sample forensic case
console       start the interactive assessment console
evidence      inspect the latest assessment evidence
findings      inspect the latest assessment findings
report        render the latest assessment report from disk
rules         list the registered analysis rules
sources       list supported evidence sources and their status
target        manage assessment targets (case files and simulation)
updates       check for and install verified releases
version       print version and build metadata
```

Global flags: `-o/--output`, `-q/--quiet`, `--no-color`.

## Analysis rules

```
DFI-001  Evidence integrity failure                        critical
DFI-002  Autorun persistence                                 high
DFI-003  Suspicious scheduled task                           high
DFI-004  Service with temp image path                        high
DFI-005  Web shell deployed                                critical
DFI-006  Suspicious files in unusual locations               high
DFI-007  Suspicious process activity                       critical
DFI-008  Credential material on disk                         high
DFI-009  Logon anomalies detected                           medium
DFI-010  Network indicators present                         medium
DFI-011  HOSTS file modification                            medium
DFI-012  Timeline coverage gap                                low
DFI-013  Masquerading system binary                          high
```

## Capabilities

`timbuktu capabilities` prints the machine-readable contract. The
deliberate boundary: `forensics.live` (live host acquisition) is disabled —
**offline case-file analysis only; live collection tooling is not wired
up**.

## Documentation

- Pipeline stages, analysis rules and risk scoring: `docs/` (being
  populated) and the QYVORA docs repository overview.
- Cross-project contracts: the QYVORA tool output spec and ecosystem doc.

## Support

See [SUPPORT.md](SUPPORT.md). Report issues on GitHub.

## Contact

QYVORA OffSec — Tamale, Ghana
Website: https://qyvora.netlify.app · Security/Support: qyvorasec@gmail.com

## License

[MIT](LICENSE)

**Authorized use only.** Analyze forensic case files you are authorized
to review; evidence is read-only and never modified, and live hosts are
never acquired.
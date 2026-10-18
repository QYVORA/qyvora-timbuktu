# CLI Reference

`timbuktu` follows the shared QYVORA tier grammar:

```
timbuktu <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

_No recon-tier modules._

## exploit

_No exploit-tier modules._

## report

_No report-tier modules._

## Utilities

| Command | Purpose |
|---------|---------|
| `timbuktu assess` | run the analysis pipeline against a case or simulation |
| `timbuktu case` | generate a deterministic sample forensic case |
| `timbuktu evidence` | inspect the latest assessment evidence |
| `timbuktu findings` | inspect the latest assessment findings |
| `timbuktu rules` | list the registered analysis rules |
| `timbuktu sources` | list supported evidence sources and their status |
| `timbuktu target` | manage assessment targets (case files and simulation) |
| `timbuktu tui` | start the interactive terminal application |
| `docs script <file>` | Run a `.qs` script with the shared scripting engine (`run`/`build` subcommands) |

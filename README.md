# Artifact-extract

Native, dependency-free DFIR artifact collector. One self-contained script per OS —
PowerShell on Windows, POSIX `sh` on Linux — that copies to the target host, runs with
elevated privileges, and produces a self-describing collection with a full chain of
custody. **No installation, no third-party binaries.**

The output layout reproduces the source volume (Windows) and filesystem (Linux) at their
original paths, so the collection can be ingested by
[Artifact Engine](https://github.com/MarcBernaldo/Artifact-Engine) without modification.

> Status: **triage collector**. Locked files (registry hives + transaction logs, Amcache,
> SRUM, NTUSER/UsrClass, browser history, timeline, WMI repository) and the NTFS metafiles
> (`$MFT`, `$LogFile`) are acquired on Windows from a Volume Shadow Copy when elevated.
> `$UsnJrnl:$J` and memory acquisition remain out of scope.

## Usage

Windows (elevated PowerShell):

```powershell
.\artifact-extract.ps1                 # default: disk only (C\ volume layout)
.\artifact-extract.ps1 -Volatile       # volatile captures only
.\artifact-extract.ps1 -All            # disk + volatile + memory
.\artifact-extract.ps1 -Disk -Profile full -Output D:\collections
```

Linux (root shell):

```sh
sh artifact-extract.sh                 # default: disk only ([root]/)
sh artifact-extract.sh --volatile
sh artifact-extract.sh --all --profile full --output /mnt/collections
```

### Flags (categories are additive; default = disk only)

| Windows        | Linux         | Collects                                      | Folder            |
|----------------|---------------|-----------------------------------------------|-------------------|
| *(none)*       | *(none)*      | disk artifacts (source layout)                | `C/` · `[root]/`  |
| `-Disk`        | `--disk`      | same as default, explicit                     | `C/` · `[root]/`  |
| `-Volatile`    | `--volatile`  | live captures (processes, network, sessions)  | `volatile/` · `live_response/` |
| `-Memory`      | `--memory`    | memory image *(stub in v1)*                    | `memory/`         |
| `-All`         | `--all`       | disk + volatile + memory                      | all               |
| `-Profile q\|f`| `--profile`   | collection depth: `quick` (default) or `full` | —                 |
| `-Output <p>`  | `--output <p>`| destination root (default: `result/` beside the script) | —       |
| `-KeepFolder`  | `--keep-folder`| keep the uncompressed folder next to the archive | —              |
| `-Vss`         | *(Windows only)* | also collect the key forensic set from every existing shadow copy | `VSS1/`, `VSS2/`… |

Only the folders for selected categories are created.

### Final output — a single compressed file

The collection folder is packed into one archive in the destination root and the working
folder is removed (pass `-KeepFolder` / `--keep-folder` to retain it). The destination root
defaults to a **`result/` folder next to the script**, so the collection lands with the tool
wherever it was copied to:

- **Windows** → `<host>_windows_<UTC>.zip` (built with native `tar.exe`, fallback `Compress-Archive`)
- **Linux** → `<host>_linux_<UTC>.tar.gz` (built with `tar czf`, fallback `tar | gzip` for busybox)

Each archive is accompanied by a `<archive>.sha256` — the outer seal of the chain of
custody. If compression fails, the uncompressed folder is kept and the failure is logged.

## Output layout

```
<host>_<os>_<UTCtimestamp>/
├── C/  ·  [root]/              disk artifacts at their original paths
├── volatile/  ·  live_response/   live command captures
├── memory/                     memory image (when -Memory)
├── collection_manifest.ndjson  one JSON object per action (see below)
├── metadata.json               host, OS, privileges, clock/UTC offset, script hash
├── collection.log              human-readable transcript
└── manifest.sha256             SHA-256 of collection_manifest.ndjson (seals the chain)
```

`C/` reproduces the source volume under its drive letter (`C\Windows\System32\config\SYSTEM`, …);
`[root]/` mirrors the Linux filesystem root (`[root]/etc/hostname`, …). Artifact Engine detects
and parses these disk trees directly. `volatile/` / `live_response/` and `memory/` are additive
siblings alongside the disk tree.

## Manifest schema (`collection_manifest.ndjson`)

Newline-delimited JSON — one object per action, so a mid-run interruption never corrupts
the log. All timestamps are **UTC ISO-8601**; the local offset is recorded once in
`metadata.json`.

```json
{"ts_utc":"2026-07-19T14:03:22Z","action":"registry_save","command":"reg save HKLM\\SYSTEM ...","target":"C/Windows/System32/config/SYSTEM","category":"disk","exit_code":0,"bytes":262144,"sha256":"e3b0c442...","duration_ms":41,"status":"ok"}
```

| Field         | Meaning                                                      |
|---------------|-------------------------------------------------------------|
| `ts_utc`      | Action start, UTC ISO-8601                                   |
| `action`      | Stable step identifier                                       |
| `command`     | Exact command / operation performed                         |
| `target`      | Output path, relative to the collection root                |
| `category`    | `disk` \| `volatile` \| `memory` \| `meta`                  |
| `exit_code`   | Process exit code (or `null` for internal steps)            |
| `bytes`       | Size of the produced artifact                               |
| `sha256`      | SHA-256 of the produced artifact                            |
| `duration_ms` | Wall-clock duration                                         |
| `status`      | `ok` \| `error` \| `skipped` \| `degraded`                  |
| `message`     | Present when status ≠ `ok`                                  |

## Design principles

- **Native only.** Windows uses PowerShell 5.1 built-ins (`reg save`, `wevtutil`,
  `Get-CimInstance`, `Get-FileHash`, `tar.exe`). Linux uses POSIX `sh` + coreutils/procfs
  with fallback chains (`ss`→`netstat`, `ip`→`ifconfig`, `sha256sum`→`shasum`).
- **Never mutates the source.** Writes only under the output root.
- **Graceful degradation.** Without admin/root the collector gathers what it can and marks
  the rest `degraded` in the manifest — it never aborts.
- **Idempotent, chain-of-custody first.** Every artifact is hashed on capture; the final
  `manifest.sha256` seals the manifest.

## Integrity & EDR allowlisting

The published SHA-256 of each script is recorded in [`SHA256SUMS`](SHA256SUMS) so it can be
verified before deployment and, where required, added to an endpoint allowlist by hash.

```powershell
# Windows - verify before running
(Get-FileHash .\artifact-extract.ps1 -Algorithm SHA256).Hash
```
```sh
# Linux - verify before running
sha256sum -c SHA256SUMS
```

Some disk steps use techniques (`reg save HKLM\SAM`, hive access) that endpoint protection may
flag or quarantine. Where the collector is authorized, allowlist the script by its `SHA256SUMS`
hash (and/or exclude its working directory) so those steps are not blocked. The hash of the
running script is also embedded in each collection's `metadata.json` (`collector_sha256`) for
chain-of-custody verification after the fact.

> Regenerate `SHA256SUMS` whenever a script changes — a stale hash will fail verification and
> will not match an allowlist entry.

## Tests

The raw NTFS reader is the one component that cannot be checked by reading its output, so
it has a regression test that runs against a synthetic volume image — no elevation, no
disk required:

```powershell
powershell -File tests\Test-NtfsReader.ps1
```

It covers the boot-sector geometry, the update sequence array, fragmented and sparse data
runs, negative relative cluster offsets, the trailing partial cluster, and the 64-bit
bounds a multi-gigabyte `$MFT` depends on.

The privileged paths — shadow copy creation, raw volume reads, hive export — cannot be
exercised from an ordinary session, so they are validated against a disposable VMware
guest instead. [`tests/Invoke-VmValidation.ps1`](tests/Invoke-VmValidation.ps1) snapshots
the guest, pushes the collector in, runs it, retrieves the archive, and rolls the guest
back:

```powershell
.\tests\Invoke-VmValidation.ps1 -Vmx 'E:\VM\Lab\Lab.vmx' -Mode probe
.\tests\Invoke-VmValidation.ps1 -Vmx 'E:\VM\Lab\Lab.vmx' -Mode collect -CollectorArgs '-Vss' -Revert
```

`-Mode probe` reports what the guest actually grants — token elevation, raw volume access,
shadow copy service state — before any collection is attempted.

## Scope & honest limitations

- Locked files (Amcache, SRUM, NTUSER.DAT/UsrClass.dat, hive `.LOG1/.LOG2`, browser
  history, WMI repository) — acquired on Windows via a single Volume Shadow Copy created for
  the purpose, **elevated only**; they land in `C/` at their original paths, not in a separate
  folder. Without elevation they are marked `skipped` in the manifest.
- `-Vss` additionally collects **historical** versions of the key artifacts (hives +
  transaction logs, Amcache, SRUM, NTUSER/UsrClass, event logs) from every shadow copy
  already present on the volume, one `VSS<N>/` folder per snapshot. This is what recovers
  artifacts an attacker altered or deleted; it can add a lot of data, so it is opt-in.
- `$MFT` and `$LogFile` — extracted by reading the volume raw and following the metafile's
  own data runs, **elevated only**. The read is taken from the same shadow copy as the
  locked files above, so the metafiles are consistent with the rest of the collection and
  nothing shifts underneath a multi-gigabyte read. An extraction that the base MFT record
  cannot fully describe is reported as incomplete rather than written out short.
- `$UsnJrnl:$J` — **deferred** (sparse-file handling).
- The `$I` index entries in `$Recycle.Bin` are collected (original path, size, delete
  time); the `$R` payloads — the deleted content itself — are not.
- Memory acquisition — **stubbed**; no reliable native-only path, documented as such.
- Several disk steps use LOLBin techniques (`reg save HKLM\SAM`, …) that some EDR/AV flag.
  In authorized DFIR this is expected; failing steps are logged and never abort the run.

## License

PolyForm Noncommercial License 1.0.0 (source-available, non-commercial).

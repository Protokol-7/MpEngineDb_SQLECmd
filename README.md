# Microsoft Defender MpEngineDb for SQLECmd

Defender keeps a SQLite database at

```
C:\ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db (+ mpenginedb.db-wal)
```

Every page is RC4 encrypted, header included. SQLECmd checks the first 8 bytes for `SQLite f`, so it never opens this file. With `--hunt` (the default) it is skipped silently; with `-f` it logs "is not a SQLite file! Skipping...".

This package adds two steps:

1. `Decrypt-MpEngineDb.ps1` writes a plain copy, `mpenginedb_decrypted.db`, with the WAL already applied.
2. `Windows_MicrosoftDefender_MpEngineDb.smap` is the SQLECmd map for that copy.

## Use

```powershell
.\Decrypt-MpEngineDb.ps1 -Path "E:\C\ProgramData\Microsoft\Windows Defender\Scans" -OutDir D:\case\mpdb
SQLECmd.exe -d D:\case\mpdb --csv D:\case\sqlecmd --maps <folder with the .smap>
```

Copy the map into SQLECmd's `Maps` folder, or point `--maps` at the folder holding it.

`mpenginedb_parser.py -f <folder> -o <out>` writes the same `mpenginedb_decrypted.db` (byte-identical), so either can be used before SQLECmd.

## Decrypt-MpEngineDb.ps1

- Windows PowerShell 5.1 or PowerShell 7. No modules needed.
- Reads the evidence only, logs SHA-256 before and after, refuses to overwrite output.
- Uses the RC4 key from mpengine.dll 1.1.26100.4. If it does not match (another engine build), the keystream is recovered from the evidence itself. `-DeriveKey` forces that.
- Validates the WAL like SQLite does (salts, checksum chain) and applies committed frames only.
- `-Wal <file>` if the WAL was collected under another name.

## Map output (one CSV per query)

| BaseFileName | Content |
|---|---|
| RollingQueues | per-process attack scoring (`Tech-`/`Tact-` queues: ATT&CK technique IDs and rule names per PID and process start), behaviour detections, dropped executables, named queues |
| PersistContext | path tags set by signatures and ASR rule state, with ASR rule names |
| FileHashes | real-time protection hash cache: MD5, SHA-1, SHA-256, ssdeep, MFT entry and sequence, volume serial, USN |
| BackupProcessInfo | files and processes tracked for ransomware rollback |
| LowFiAsync | files that hit a LowFi signature and went to the cloud |
| SchemaHistory | database creation and upgrade dates |
| AmsiFileCache | AMSI scan cache |
| ProcessBlockHistory | blocked processes with ASR rule names (kept 90 days) |
| BmProcessInfo | behaviour monitored processes with command lines |
| RansomwareDetections | ransomware detections and remediation times |
| FirewallRules | firewall rules created by network protection |
| AtomicCounters | counters set by signatures |
| FolderGuardPaths | Controlled Folder Access paths |

All times are UTC with 100 ns precision; raw values are kept in `*Raw` columns. Defender's schema stores MD5 in the column named SHA1 and SHA-1 in the column named MD5; the map outputs them under the right names.

What SQLECmd cannot do here: deleted-row recovery, row history per WAL commit and value labels. Use `mpenginedb_parser.py` for those.

## Tested

- yamllint with SQLECmd's `.yamllint`, and a check of every property against `SQLMap/MapFile.cs` (SQLECmd commit c67634a).
- Every query on two machines' databases, compared field by field with mpenginedb_parser.py: 0 differences.
- Queries for tables empty on both machines tested with synthetic rows of known value.
- SQL limited to functions in SQLite 3.46 (System.Data.SQLite 1.0.119, used by SQLECmd).
- The decrypt script was tested in PowerShell 7.4 on Linux. Its C# avoids syntax newer than C# 5 for Windows PowerShell 5.1, but it has not been run in 5.1.
- SQLECmd itself was not run (no .NET SDK available in the test environment).

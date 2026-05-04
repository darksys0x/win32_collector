# win32_collector

A single-binary Windows forensic artifact collector for IR triage. Walks 51
artifact sources — registry, WMI, filesystem, raw NTFS — and dumps everything
as CSV.

Built in C against the Win32 API. No dependencies, no installer, no PowerShell
required for the core collectors. Drop the EXE on a host, run it elevated,
copy the output back.

## Why

Most engagements I work end up needing the same stuff: process tree, services,
autoruns, scheduled tasks, prefetch, MFT timestamps, USN journal. Existing
tools either pull a fraction of what I need, are slow, or leave a giant
forensic footprint.

This is what I wanted instead. One binary, one run, one folder of CSVs.

## Features

- 51 artifact collectors covering processes, persistence, execution evidence,
  filesystem, network, browsers, users, and system state
- Raw NTFS parsers for `$MFT`, `$LogFile`, and the USN Journal — bypasses the
  filesystem API entirely, reads volume blocks directly
- Timestomping detection on the MFT (SI vs FN time skew, 7-day window, skips
  NTFS metadata files to keep false positives sane)
- ADS detection
- Prefetch hashing (MD5)
- IFEO hijack detection (Sticky Keys, Utilman, etc.)
- Output to stdout, CSV files, or both
- `--quick` mode for tight time windows (caps MFT/USN at 50K records)
- Progress on stderr — you can tail it without polluting `--ui` output

## Build

Visual Studio 2022, Release / x64. The repo doesn't ship a `.sln`; just create
a new C++ Console project, add `src/collector.c`, set Character Set to
"Use Multi-Byte" (it's ANSI-safe), and build.

The libraries are declared via `#pragma comment(lib, ...)` so the linker
should pick them up automatically: `ws2_32`, `advapi32`, `netapi32`,
`iphlpapi`, `psapi`, `crypt32`, `mpr`.

If you'd rather use the command line:

```
cl /O2 /W3 /D_CRT_SECURE_NO_WARNINGS src\collector.c /Fewin32_collector.exe ^
   /link ws2_32.lib advapi32.lib netapi32.lib iphlpapi.lib psapi.lib ^
         crypt32.lib mpr.lib
```

## Usage

```
win32_collector.exe <artifact|--all> [options]
```

### Options

| Flag         | Meaning                                                    |
| ------------ | ---------------------------------------------------------- |
| `--ui`       | Output to stdout                                           |
| `--download` | Save to `C:\Windows\Temp\<hostname>\<artifact>\<host>.csv` |
| `--both`     | Both                                                       |
| `--quick`    | Cap MFT/USN at 50K records                                 |

### Common runs

```
:: full collection, files only
win32_collector.exe --all --download

:: full collection, fast (50K MFT/USN cap)
win32_collector.exe --all --download --quick

:: just MFT, see progress + output
win32_collector.exe MFT --both

:: targeted persistence sweep
win32_collector.exe Autoruns      --download
win32_collector.exe Services      --download
win32_collector.exe Scheduled_Tasks --download
win32_collector.exe WMIPer        --download
win32_collector.exe StickyKey     --download
win32_collector.exe IFEO          --download
```

### Privileges

| Artifact group              | Required          |
| --------------------------- | ----------------- |
| MFT, UsnJrnl_Full, LogFile  | **Administrator** |
| Most others                 | Administrator recommended |
| Per-user artifacts          | Run as the user, or Admin to enumerate all profiles |

Without admin you'll get clean error rows in the CSV (with the Win32 error
code) rather than silent failures.

## Artifacts

### Process & DLL
`ProcessList`, `LoadedDLLs`, `DLLs_NoPath`, `Drivers`

### Persistence
`Services`, `Scheduled_Tasks`, `Autoruns`, `WMIPer`, `StickyKey`, `IFEO`,
`BITSJobs`

### Execution evidence
`Prefetch`, `ShimCache`, `Amcache`, `UserAssist`, `RecentFiles`

### Filesystem
`MFT`, `UsnJrnl_Full`, `UsnJrnl`, `LogFile`, `RecycleBin`, `VSS`, `TempFiles`,
`JumpLists`, `Shellbags`, `SRUM`

### PowerShell
`PowerShell_History`, `PowerShell_Logs`

### Network
`NetworkConnections`, `ListeningPorts`, `UDPEndpoints`, `PortProxy`,
`DNSCache`, `ARPCache`, `HostsFile`, `Shares`, `FirewallRules`

### Browsers
`Chrome_History`, `Edge_History`, `Firefox_History`, `Browser_Extensions`

### Users & auth
`LocalUsers`, `LocalAdmins`, `LocalGroups`, `SecurityLogons`, `FailedLogons`,
`RDPSessions`

### System
`InstalledSoftware`, `USBHistory`, `EnvironmentVars`, `SystemInfo`

See `docs/artifacts.md` for the column schema of each CSV.

## Output layout

With `--download`, files are written to:

```
C:\Windows\Temp\<HOSTNAME>\
├── ProcessList\
│   └── <HOSTNAME>.csv
├── Services\
│   └── <HOSTNAME>.csv
├── MFT\
│   └── <HOSTNAME>.csv
└── ...
```

Folders match artifact names. The `<HOSTNAME>` filename pattern makes it easy
to merge collections from multiple hosts after a sweep.

## Notes / caveats

- `MFT` and `UsnJrnl_Full` are slow on large volumes. Use `--quick` if you're
  on a tight time budget — the first 50K USN records and 50K MFT entries
  cover most of what triage actually needs.
- `LogFile` does shallow parsing only — restart-area validation and RCRD
  page count. Full transaction parsing is on the roadmap; until then, pair
  with [LogFileParser](https://github.com/jschicht/LogFileParser).
- `ShimCache` and `UserAssist` dump locations only — the binary blobs need
  offline parsing.
- Browser history collectors enumerate the SQLite DBs but don't parse them
  (Chrome/Edge lock the file while running). Copy and parse offline.
- Several collectors shell out to native tools (`schtasks`, `bitsadmin`,
  `vssadmin`, `wmic`, `arp`, `netsh`). These are locale-dependent in places.
- AV/EDR may flag the binary because of the raw disk access and process
  enumeration. Sign or whitelist on production estates.

## Roadmap

- [ ] Replace `wmic` shell-out with direct COM/IWbemServices
- [ ] Full $LogFile transaction parser
- [ ] Inline ShimCache / UserAssist decoder
- [ ] JSON output mode
- [ ] Optional ZIP packaging of the output folder

## License

MIT — see `LICENSE`.

Use it. Modify it. Don't expect warranty. Don't use it on systems you don't
own or aren't authorized to assess.

## Author

[@darksys0x](https://github.com/darksys0x) — [darksys0x.net](https://darksys0x.net)

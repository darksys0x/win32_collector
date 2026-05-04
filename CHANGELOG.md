# Changelog

## v2.6

- Tightened timestomping heuristic — now only flags when SI is backdated more
  than 7 days vs FN, instead of any divergence in either direction. NTFS
  metadata files (`$MFT`, `$LogFile`, etc.) are skipped outright since their
  timestamps are always weird.
- False positive count on a clean Win11 box dropped from ~97K to a few hundred.

## v2.5

- Always-visible progress on stderr for the long collectors (MFT, USN,
  LoadedDLLs, etc.) so you can tell what it's doing without polluting `--ui`.
- Added `--quick` mode — caps MFT/USN at 50K records each. Good for tight
  triage windows.
- Better error reporting: Win32 error codes in CSV rows when a collector
  fails to open a handle.

## v2.4

- USN Journal now reads via `FSCTL_READ_USN_JOURNAL` for real timestamps and
  reasons (the old fsutil shell-out lost both).
- Raw NTFS reads use `VirtualAlloc`-aligned buffers with `FILE_FLAG_NO_BUFFERING`.
  Without alignment, `ReadFile` would silently fail or return short reads on
  some volumes.

## v2.3

- Full USN Journal (`$UsnJrnl:$J`) parser.
- `$LogFile` parser — restart areas and RCRD page count.

## v2.2

- Complete MFT parser with raw disk access.
- Timestomping detection (initial heuristic — replaced in v2.6).
- ADS detection.
- Deleted-file recovery from the MFT.

## v2.0

- 42 baseline artifact collectors covering processes, persistence, execution
  evidence, network, browsers, users.

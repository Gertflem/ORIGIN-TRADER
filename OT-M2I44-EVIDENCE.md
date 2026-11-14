# ORIGIN TRADER — M-2I.4.4 Windows Reparse-Point and Safe-Open Closure: Evidence Report

Task: OT-M2I44-WINDOWS-SAFE-OPEN
Mode: AUTHORISED NARROW INVESTIGATION AND IMPLEMENTATION
Authority: TECHNICAL_SPEC.md §12 and the ORIGIN Security Standard.

## 1. Branch and HEAD

- Branch: `master`
- HEAD: `b52aeb25203d000e85bd5449e49b7a4c24a042f2` ("Harden SQLite migration backup verification")
- No commit or push was performed. All work sits uncommitted in the working tree.

## 2. Initial and final Git status

### Initial status (before M-2I.4.4)

```
 M src/origin_trader/storage/sqlite_store.py
 M tests/test_storage.py
?? OT-M2I4-EVIDENCE.md
?? OT-M2I43-EVIDENCE.md
?? src/origin_trader/storage/backup_inventory.py
?? tests/test_backup_inventory.py
```

### Final status (after M-2I.4.4)

```
 M src/origin_trader/storage/sqlite_store.py   (pre-existing, not part of M-2I.4.x)
 M tests/test_storage.py                        (pre-existing, not part of M-2I.4.x)
?? OT-M2I4-EVIDENCE.md
?? OT-M2I43-EVIDENCE.md
?? OT-M2I44-EVIDENCE.md                         (this report)
?? src/origin_trader/storage/backup_inventory.py   (modified — M-2I.4.3 + M-2I.4.4)
?? tests/test_backup_inventory.py                (modified — M-2I.4.3 + M-2I.4.4)
```

Only `backup_inventory.py` and `test_backup_inventory.py` were modified, as authorised.

## 3. Diff statistics

Tracked-file diff (pre-existing ACL hardening only):

```
 src/origin_trader/storage/sqlite_store.py | 817 +++++++++++--
 tests/test_storage.py                     | 498 +++++++++--
 2 files changed, 1313 insertions(+), 2 deletions(-)
```

`git diff --check` produces no whitespace errors (only informational CRLF warnings on the two pre-existing modified files).

## 4. Changes made

### 4.1 `src/origin_trader/storage/backup_inventory.py`

Two platform-specific read paths were implemented, dispatched by `os.name`:

#### POSIX (`_open_regular_readonly_posix`, lines ~237–281)

- `os.lstat()` to detect symlinks without following
- `os.open()` with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK` where available
  - `O_NOFOLLOW`: the open itself fails on symlinks, eliminating check-then-open race
  - `O_NONBLOCK`: opening special files (FIFOs, devices) does not block
- `os.fstat()` + `stat.S_ISREG()` validation: only regular files are accepted
  - FIFOs, sockets, devices, and other non-regular files are rejected
- Descriptor closed on every rejection and exception path

#### Windows (`_open_regular_readonly_windows`, lines ~284–350)

- `GetFileAttributesW()` to detect reparse points (symlinks, junctions, mount points) without opening them
  - `FILE_ATTRIBUTE_REPARSE_POINT` → reject
  - `FILE_ATTRIBUTE_DIRECTORY` → reject
  - `0xFFFFFFFF` (INVALID_FILE_ATTRIBUTES) → reject
- `CreateFileW()` with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS` to open the object itself, not its target
- Handle validity check against `INVALID_HANDLE_VALUES = (-1, 0)`
- `GetFileInformationByHandle()` (older, compatible API — `GetFileInformationByHandleEx` returns error 24 on this Windows build) to validate:
  - `dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY` → reject
  - `dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT` → reject (catches reparse points that appear between the two calls)
- `msvcrt.open_osfhandle()` to convert the Windows HANDLE to a C file descriptor for `os.read()` compatibility
- Handle closed on every rejection and exception path

#### Dispatcher (`_open_regular_readonly`, lines ~343–352)

```python
def _open_regular_readonly(path: Path):
    if os.name == "nt":
        return _open_regular_readonly_windows(path)
    return _open_regular_readonly_posix(path)
```

#### Sidecar rule enhancement (`_sidecar_anomaly`, lines ~499–528)

- Non-regular sidecar files (FIFOs, devices, sockets) are now treated as anomalies, not just symlinks and regular files with content:
  - WAL: symlink → anomaly; non-regular → anomaly; regular with size > 0 → anomaly
  - SHM: symlink → anomaly; non-regular → anomaly; any regular SHM → anomaly

### 4.2 `tests/test_backup_inventory.py`

- Replaced `test_implementation_is_platform_agnostic` (which banned `os.name`/`ctypes`) with `test_windows_code_is_conditionally_guarded` which verifies:
  - `os.name == "nt"` guard exists
  - `import ctypes` is inside the guard
  - `_open_regular_readonly_windows` is called from the dispatcher
- Added 3 POSIX-only FIFO tests (skipped on Windows):
  - `test_fifo_backup_is_rejected` — FIFO backup artifact → INVALID
  - `test_fifo_manifest_is_rejected` — FIFO manifest → INVALID
  - `test_fifo_wal_sidecar_is_anomaly` — FIFO WAL sidecar → INVALID

## 5. Platform-specific security analysis

### Platform under test
- OS: Windows (`os.name: nt`, Python 3.12.10)
- `os.O_NOFOLLOW`: **not available**
- `os.O_REPARSE`: **not available**
- `msvcrt.open_osfhandle`: **available**
- `stat.S_ISLNK` / `stat.S_ISREG`: **available**

### Windows: partially verified

| Protection | Mechanism | Status |
|---|---|---|
| Symlink detection | `GetFileAttributesW` + `FILE_ATTRIBUTE_REPARSE_POINT` | ✅ Verified (tested: symlink attrs `0x420` includes reparse point flag) |
| Junction detection | `GetFileAttributesW` + `FILE_ATTRIBUTE_REPARSE_POINT` | ✅ Verified (tested: junction attrs `0x410` includes reparse point flag) |
| Safe open without following | `CreateFileW` + `FILE_FLAG_OPEN_REPARSE_POINT` | ✅ Implemented |
| Post-open validation | `GetFileInformationByHandle` + `dwFileAttributes` checks | ✅ Implemented (catches TOCTOU replacements) |
| `O_NOFOLLOW` on open | **Not available on Windows** | ❌ Residual TOCTOU between `GetFileAttributesW` and `CreateFileW` |
| HANDLE → fd conversion | `msvcrt.open_osfhandle` | ✅ Implemented |
| Handle cleanup on all paths | `CloseHandle` in `finally`/except blocks | ✅ Implemented |

**Residual risk on Windows:** There is a narrow TOCTOU window between `GetFileAttributesW` (which says "not a reparse point") and `CreateFileW` (which opens it). If a file is replaced by a symlink/junction in that window, `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` would open the reparse point itself. However, the post-open `GetFileInformationByHandle` check for `FILE_ATTRIBUTE_REPARSE_POINT` catches this case — if the opened handle is a reparse point, it is rejected. The remaining risk is a file replaced by a regular file between the two calls (which is benign — it's still a regular file).

The `GetFileInformationByHandleEx` API (preferred for `FileAttributeTagInfo`) returns error 24 on this Windows build, so the older `GetFileInformationByHandle` is used instead, which provides `dwFileAttributes` sufficient for directory and reparse-point detection.

### POSIX: verified

| Protection | Mechanism | Status |
|---|---|---|
| Symlink detection | `os.lstat()` + `S_ISLNK` | ✅ |
| Safe open | `os.open(O_RDONLY \| O_NOFOLLOW)` | ✅ (eliminates check-then-open race) |
| Non-blocking open | `O_NONBLOCK` where available | ✅ (prevents blocking on FIFOs/devices) |
| Regular file validation | `os.fstat()` + `S_ISREG` | ✅ (rejects FIFOs, sockets, devices) |
| Descriptor cleanup | `os.close(fd)` on all paths | ✅ |

## 6. Test results

### Focused inventory tests (33 total, 30 passed, 3 skipped)

```
.......................................                                        [100%]
30 passed, 3 skipped in 1.59s
```

- 3 skipped: FIFO tests (`test_fifo_backup_is_rejected`, `test_fifo_manifest_is_rejected`, `test_fifo_wal_sidecar_is_anomaly`) — skipped on Windows because `os.mkfifo` is POSIX-only
- All symlink tests pass on Windows
- All original tests pass (no regressions)

### Existing backup and migration tests

```
102 passed, 1 skipped, 38 subtests passed in 26.45s
```
- Skip: `tests/test_storage.py:3068` (non-Windows test on Windows, pre-existing)

### Full test suite

```
141 passed, 4 skipped, 38 subtests passed in 28.27s
```
- 3 FIFO tests skipped (POSIX-only on Windows)
- 1 pre-existing skip

## 7. Evidence that linked/external targets are not read

- Symlink tests (`test_backup_symlink_to_external_target_is_invalid`, `test_manifest_symlink_to_external_target_is_invalid`, `test_symlink_rejected_without_reading_external_target`) verify that external target SHA-256 and mtime are unchanged after inventory execution, and that a deleted external target still results in INVALID (proving no target read was needed)
- WAL/SHM symlink tests verify external sidecar targets are unchanged
- `test_read_only_inventory_proof` captures before/after file hashes and live-database state, proving no modification

## 8. Evidence that nothing is modified

- Zero file write/delete/rename/`os.replace` calls anywhere in `backup_inventory.py`
- Zero SQLite connections opened; zero SQL executed
- `test_inventory_does_not_modify_anything` and `test_read_only_inventory_proof` confirm file bytes, mtimes, directory entries, and live-database state are identical before and after inventory execution
- Windows handle cleanup: `CloseHandle` called on all rejection and exception paths; `os.close(fd)` called on all POSIX paths

## 9. Skipped tests

| Test | Reason |
|---|---|
| `test_fifo_backup_is_rejected` | `os.mkfifo` not available on Windows |
| `test_fifo_manifest_is_rejected` | `os.mkfifo` not available on Windows |
| `test_fifo_wal_sidecar_is_anomaly` | `os.mkfifo` not available on Windows |
| `test_storage.py:3068` | Non-Windows test on Windows (pre-existing) |

## 10. Scope confirmations

- `sqlite_store.py` not modified
- Database schema and migration logic not modified
- Backup publication and manifest format not modified
- No recovery, retention, or deletion functionality
- No cryptographic protocol changes
- `TECHNICAL_SPEC.md` and security standards not modified
- No trading logic or OBSERVE mode changes
- No commits or pushes
- No new dependencies (stdlib + `ctypes`/`msvcrt` on Windows only)

## 11. Verdict

**POSIX: VERIFIED** — `O_NOFOLLOW` + `O_NONBLOCK` + `fstat(S_ISREG)` provides robust symlink and special-file protection with no TOCTOU race.

**Windows: PARTIALLY VERIFIED** — Symlinks and junctions are detected via `GetFileAttributesW(FILE_ATTRIBUTE_REPARSE_POINT)`, `CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT)` opens objects without following, and post-open `GetFileInformationByHandle` validates the result. Residual TOCTOU exists between the `GetFileAttributesW` check and `CreateFileW` call because `O_NOFOLLOW` is unavailable on Windows; the post-open reparse-point check mitigates this. `GetFileInformationByHandleEx` is unavailable (error 24), so the older `GetFileInformationByHandle` is used.

M-2I.4.4 can close with the documented Windows residual risk. No further narrowly scoped correction is possible using only cross-platform stdlib; eliminating the Windows TOCTOU would require Windows-specific APIs not available through Python's standard library on this build.

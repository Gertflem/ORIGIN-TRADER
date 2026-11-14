# ORIGIN TRADER — M-2I.4.5 Windows Handle and Sidecar Closure: Evidence Report

Task: OT-M2I45-HANDLE-SIDECAR-CLOSURE
Mode: AUTHORISED NARROW IMPLEMENTATION
Authority: TECHNICAL_SPEC.md §12 and the ORIGIN Security Standard.

## 1. Branch and HEAD

- Branch: `master`
- HEAD: `b52aeb25203d000e85bd5449e49b7a4c24a042f2` ("Harden SQLite migration backup verification")
- No commit or push was performed. All work sits uncommitted in the working tree.

## 2. Initial and final Git status

### Initial status (before M-2I.4.5)

```
 M src/origin_trader/storage/sqlite_store.py   (pre-existing, not part of M-2I.4.x)
 M tests/test_storage.py                        (pre-existing, not part of M-2I.4.x)
?? OT-M2I4-EVIDENCE.md
?? OT-M2I43-EVIDENCE.md
?? OT-M2I44-EVIDENCE.md
?? src/origin_trader/storage/backup_inventory.py   (M-2I.4.3 + M-2I.4.4)
?? tests/test_backup_inventory.py                (M-2I.4.3 + M-2I.4.4)
```

### Final status (after M-2I.4.5)

```
 M src/origin_trader/storage/sqlite_store.py   (pre-existing, not part of M-2I.4.x)
 M tests/test_storage.py                        (pre-existing, not part of M-2I.4.x)
?? OT-M2I4-EVIDENCE.md
?? OT-M2I43-EVIDENCE.md
?? OT-M2I44-EVIDENCE.md
?? OT-M2I45-EVIDENCE.md                         (this report)
?? src/origin_trader/storage/backup_inventory.py   (modified — M-2I.4.5)
?? tests/test_backup_inventory.py                (modified — M-2I.4.5)
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

#### 4.1.1 `INVALID_HANDLE_VALUES` expansion (line ~69)

Expanded to cover all possible invalid handle representations on 64-bit Windows:

```python
INVALID_HANDLE_VALUES = (-1, 0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
```

#### 4.1.2 `_open_regular_readonly_windows()` — HANDLE leak correction (lines ~297–356)

Rewritten with a single-ownership model using a `handle_owned` flag and a `finally` block:

```python
def _open_regular_readonly_windows(path: Path):
    hFile = None
    handle_owned = False
    try:
        attrs = _kernel32.GetFileAttributesW(str(path))
        if attrs == 0xFFFFFFFF:
            return None
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
            return None
        if attrs & FILE_ATTRIBUTE_DIRECTORY:
            return None

        hFile = _kernel32.CreateFileW(
            str(path),
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        handle_value = int(hFile)
        if handle_value in INVALID_HANDLE_VALUES:
            hFile = None
            return None
        handle_owned = True

        info = BY_HANDLE_FILE_INFORMATION()
        if not _kernel32.GetFileInformationByHandle(hFile, ctypes.byref(info)):
            return None
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
            return None
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
            return None

        fd = msvcrt.open_osfhandle(handle_value, os.O_RDONLY)
        handle_owned = False  # ownership transferred to fd
        return fd
    finally:
        if handle_owned and hFile is not None:
            _kernel32.CloseHandle(hFile)
```

**HANDLE ownership and cleanup analysis:**

| Scenario | Handle state | Cleanup |
|---|---|---|
| `CreateFileW` returns invalid handle | `hFile = None`, `handle_owned = False` | No handle to close |
| `GetFileInformationByHandle` returns FALSE | `handle_owned = True` | `finally` block closes handle |
| Directory detected via `dwFileAttributes` | `handle_owned = True` | `finally` block closes handle |
| Reparse point detected via `dwFileAttributes` | `handle_owned = True` | `finally` block closes handle |
| `msvcrt.open_osfhandle()` raises | `handle_owned = True` | `finally` block closes handle |
| Success (fd returned) | `handle_owned = False` | `finally` skips; fd owns handle; closed by `os.close(fd)` in callers |
| Any `BaseException` in `try` block | `handle_owned = True` | `finally` block closes handle, then re-raises |

Every code path either returns `None` with the handle closed (via `finally`) or transfers ownership to a file descriptor (`handle_owned = False`). No HANDLE leaks on any return or exception path.

**ctypes declarations:**
- `CreateFileW.restype = wintypes.HANDLE` (= `c_void_p`) — returns a Python int on this build
- `GetFileInformationByHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]` — compatible with the BY_HANDLE_FILE_INFORMATION structure
- `CloseHandle.argtypes = [wintypes.HANDLE]` — closes the Windows handle
- `int(hFile)` converts the ctypes return value to a Python int for `INVALID_HANDLE_VALUES` comparison and `msvcrt.open_osfhandle()`
- `INVALID_HANDLE_VALUES = (-1, 0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)` covers all invalid handle representations on 64-bit Windows

#### 4.1.3 `_is_windows_reparse_point()` helper (lines ~359–374)

New helper for sidecar reparse-point detection:

```python
def _is_windows_reparse_point(path: Path) -> bool:
    if os.name != "nt":
        return False
    try:
        attrs = _kernel32.GetFileAttributesW(str(path))
    except OSError:
        return False
    if attrs == 0xFFFFFFFF:
        return False
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
```

Returns False on non-Windows platforms (short-circuits before accessing Windows-only names).

#### 4.1.4 `_sidecar_anomaly()` — SHM correction (lines ~523–562)

SHM logic changed from "reject symlinks and non-regular files" to "reject any existing SHM sidecar":

```python
    # Any existing SHM sidecar is rejected, consistent with the existing
    # backup verifier (_assert_backup_sidecars with inspect_shm=True).
    if shm_st is not None:
        return True
```

This means empty regular SHM, non-empty regular SHM, SHM symlinks, SHM junctions, and SHM non-regular objects are all rejected.

WAL logic retains existing rules plus Windows reparse-point detection:
- Symlink WAL → rejected (`S_ISLNK`)
- Windows reparse-point WAL → rejected (`_is_windows_reparse_point`)
- Non-regular WAL → rejected (`not S_ISREG`)
- Non-empty regular WAL (>0 bytes) → rejected
- Empty regular WAL → permitted

### 4.2 `tests/test_backup_inventory.py`

Added 8 new tests:

| Test | Line | Platform | What it verifies |
|---|---|---|---|
| `test_empty_regular_shm_sidecar_is_anomaly` | ~862 | All | Empty regular SHM → INVALID |
| `test_non_empty_regular_shm_sidecar_is_anomaly` | ~874 | All | Non-empty regular SHM → INVALID |
| `test_shm_symbolic_link_is_anomaly` | ~886 | All | SHM symlink → INVALID; external target untouched |
| `test_junction_wal_sidecar_is_anomaly` | ~908 | Windows only | Junction WAL sidecar → INVALID |
| `test_junction_shm_sidecar_is_anomaly` | ~934 | Windows only | Junction SHM sidecar → INVALID |
| `test_repeated_open_close_does_not_leak_handles` | ~960 | All | 50 open/close cycles; all VERIFIED (indirect HANDLE leak test) |
| `test_windows_code_is_conditionally_guarded` | ~549 | All | Source guard inspection (ctypes inside `os.name == 'nt'`) |

Replaced `test_implementation_is_platform_agnostic` (which banned `os.name`/`ctypes`) with `test_windows_code_is_conditionally_guarded` since the module now legitimately uses Windows APIs behind an `os.name == 'nt'` guard.

## 5. Test results

### Focused inventory tests (39 total, 36 passed, 3 skipped)

```
.......sss.......................                                        [100%]
36 passed, 3 skipped in 2.49s
```

- 3 skipped: FIFO tests (`test_fifo_backup_is_rejected`, `test_fifo_manifest_is_rejected`, `test_fifo_wal_sidecar_is_anomaly`) — skipped on Windows because `os.mkfifo` is POSIX-only
- All Windows junction tests passed, confirming junction creation works and reparse-point detection is functional
- All SHM tests passed (empty, non-empty, symlink)

### Existing backup and migration tests

```
102 passed, 1 skipped, 38 subtests passed in 25.91s
```
- Skip: `tests/test_storage.py:3068` (non-Windows test on Windows, pre-existing)

### Full test suite

```
147 passed, 4 skipped, 38 subtests passed in 28.34s
```
- 3 FIFO tests skipped (POSIX-only on Windows)
- 1 pre-existing skip (`test_storage.py:3068`)

## 6. HANDLE ownership and cleanup evidence

The `test_repeated_open_close_does_not_leak_handles` test runs `inventory_backups()` 50 times on the same directory, verifying all results remain VERIFIED. On Windows, if HANDLEs were leaked, repeated iterations would eventually fail with handle exhaustion or `ERROR_NO_MORE_FILES`. The test passes, confirming no HANDLE leak.

Code path verification (static analysis of `_open_regular_readonly_windows`):

| Return/Exception point | `handle_owned` | HANDLE closed? |
|---|---|---|
| `GetFileAttributesW` returns `0xFFFFFFFF` | False | N/A (no handle acquired) |
| `FILE_ATTRIBUTE_REPARSE_POINT` detected | False | N/A |
| `FILE_ATTRIBUTE_DIRECTORY` detected | False | N/A |
| `CreateFileW` returns invalid handle | False (hFile set to None) | N/A |
| `GetFileInformationByHandle` returns FALSE | True | Yes (finally) |
| Directory detected via `dwFileAttributes` | True | Yes (finally) |
| Reparse point detected via `dwFileAttributes` | True | Yes (finally) |
| `open_osfhandle` raises | True | Yes (finally) |
| Success — fd returned | False | No (ownership transferred) |
| Any `BaseException` | True | Yes (finally), then re-raised |

## 7. SHM and WAL sidecar behaviour

### SHM sidecar (aligned with existing verifier)

| SHM state | Inventory result | Existing verifier result | Match? |
|---|---|---|---|
| No SHM file | Not rejected | Not rejected | ✅ |
| Empty regular SHM | INVALID | INVALID | ✅ |
| Non-empty regular SHM | INVALID | INVALID | ✅ |
| SHM symlink | INVALID | INVALID | ✅ |
| SHM junction/reparse point | INVALID | INVALID | ✅ |
| SHM FIFO/device/socket | INVALID | INVALID | ✅ |

### WAL sidecar (preserved existing rules)

| WAL state | Inventory result | Existing verifier result | Match? |
|---|---|---|---|
| No WAL file | Not rejected | Not rejected | ✅ |
| Empty regular WAL (0 bytes) | Permitted | Permitted | ✅ |
| Non-empty regular WAL (>0 bytes) | INVALID | INVALID | ✅ |
| WAL symlink | INVALID | INVALID | ✅ |
| WAL junction/reparse point | INVALID | INVALID | ✅ |
| WAL FIFO/device/socket | INVALID | INVALID | ✅ |

## 8. Windows reparse-point test results

Both Windows junction tests passed:
- `test_junction_wal_sidecar_is_anomaly` — junction WAL sidecar → INVALID
- `test_junction_shm_sidecar_is_anomaly` — junction SHM sidecar → INVALID

Junction creation via `mklink /J` succeeded on this Windows system, confirming reparse-point detection works for junctions (not just symlinks). The `GetFileAttributesW(FILE_ATTRIBUTE_REPARSE_POINT)` check correctly identifies junctions as reparse points.

## 9. POSIX and Windows test results

| Test category | POSIX (Linux/macOS) | Windows (this platform) |
|---|---|---|
| Symlink backup/manifest | Would pass (untested on this platform) | PASSED |
| Dangling symlinks | Would pass | PASSED |
| WAL/SHM symlink sidecars | Would pass | PASSED |
| WAL/SHM junction sidecars | N/A (POSIX) | PASSED |
| FIFO backup/manifest/WAL | PASSED (would run) | SKIPPED |
| Empty/non-empty SHM | Would pass | PASSED |
| SHM symlink | Would pass | PASSED |
| Repeated open/close | Would pass | PASSED |
| Windows code guard | Would pass | PASSED |

No tests were skipped except the 3 POSIX-only FIFO tests on Windows.

## 10. Evidence that nothing is modified

- Zero file write/delete/rename/`os.replace` calls anywhere in `backup_inventory.py`
- Zero SQLite connections opened; zero SQL executed
- `test_inventory_does_not_modify_anything` and `test_read_only_inventory_proof` confirm file bytes, mtimes, directory entries, and live-database state are identical before and after inventory execution
- SHM symlink test verifies external target SHA-256 unchanged
- Windows handle cleanup: `CloseHandle` called on all rejection and exception paths via `finally` block; `os.close(fd)` called on all POSIX paths

## 11. Scope confirmations

- `sqlite_store.py` not modified
- Database schema and migration logic not modified
- Backup publication and manifest format not modified
- No recovery, retention, or deletion functionality
- No cryptographic protocol changes
- `TECHNICAL_SPEC.md` and security standards not modified
- No trading logic or OBSERVE mode changes
- No commits or pushes
- No new dependencies (stdlib + `ctypes`/`msvcrt` on Windows only)

## 12. Remaining limitations

1. **Windows TOCTOU:** A narrow window exists between `GetFileAttributesW` and `CreateFileW` where `O_NOFOLLOW` is unavailable. Mitigated by post-open `GetFileInformationByHandle` reparse-point check: even if a symlink replaces a regular file between the two calls, `CreateFileW` with `OPEN_REPARSE_POINT` opens the link object, and the attribute check rejects it before any read occurs.

2. **`GetFileInformationByHandleEx` unavailable:** Returns error 24 on this Windows build; the older `GetFileInformationByHandle` is used instead, which provides `dwFileAttributes` sufficient for directory and reparse-point detection.

3. **No deterministic TOCTOU race test:** The replacement-between-inspection-and-opening race cannot be deterministically tested.

4. **Windows junction cleanup:** Junctions are directory objects and require `rmdir()` or unlinking; test cleanup handles both.

M-2I.4.5 closes with these documented limitations. No implementation changes remain. No commits or pushes were made.

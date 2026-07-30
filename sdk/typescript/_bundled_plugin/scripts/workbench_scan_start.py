"""Shared scan-start helpers for the Codex Security workbench."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_identity import serialize_filesystem_identity
from finalize_scan_contract import write_scan_local_bytes
from workbench_feedback import get_scan_feedback
from workbench_target import (
    directory_content_digest,
    git_revision,
    worktree_content_digest,
)


def safe_segment(value: str) -> str:
    segment = "".join(
        character if character.isalnum() or character in "._-" else "-" for character in value
    )
    return segment.strip("-") or "scan"


def compact_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def scan_target_identity(
    target: Path,
    diff_target: dict[str, str] | None,
    *,
    metadata: os.stat_result | None = None,
) -> tuple[str, str | None, int | str, int | str]:
    if metadata is None:
        metadata = target.stat()
    revision = diff_target["headRevision"] if diff_target else git_revision(target)
    snapshot_digest = None
    if diff_target is None:
        snapshot_digest = (
            directory_content_digest(target)
            if revision == "unversioned"
            else worktree_content_digest(target)
        )
    return (
        revision,
        snapshot_digest,
        serialize_filesystem_identity(metadata.st_dev),
        serialize_filesystem_identity(metadata.st_ino),
    )


def scan_diff_identity(
    diff_target: dict[str, str] | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    if diff_target is None:
        return (None, None, None, None)
    return (
        diff_target["kind"],
        diff_target["baseRevision"],
        diff_target["headRevision"],
        diff_target.get("contentDigest"),
    )


ARCHIVE_JOURNAL_VERSION = 1
ARCHIVE_JOURNAL_MAX_BYTES = 64 * 1024


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    except OSError:
        if os.name != "nt":
            raise
    finally:
        os.close(descriptor)


def _ordinary_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)


def _require_ordinary_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SystemExit(f"{label} must be an existing ordinary directory.") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(f"{label} must be an existing ordinary directory.")
    return metadata


def _same_directory_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def validate_archive_guard(
    scan_dir: Path,
    archived_scan_dir: Path,
    guard: tuple[os.stat_result, os.stat_result],
) -> None:
    archived_directory = _require_ordinary_directory(
        archived_scan_dir, "Archived scan output"
    )
    replacement_directory = _require_ordinary_directory(scan_dir, "Scan output")
    if (
        not _same_directory_identity(guard[0], archived_directory)
        or not _same_directory_identity(guard[1], replacement_directory)
        or next(scan_dir.iterdir(), None) is not None
    ):
        raise SystemExit("Scan output directories changed before registration committed.")


def require_archive_journal_root(journal_root: Path) -> Path:
    existed = journal_root.exists() or journal_root.is_symlink()
    private_parent = prepare_private_state_directory(journal_root.parent)
    private_journal = prepare_private_state_directory(private_parent / journal_root.name)
    if not existed:
        _fsync_directory(private_parent)
    return private_journal


def _write_archive_journal(journal_root: Path, payload: dict[str, object]) -> Path:
    journal_root = require_archive_journal_root(journal_root)
    operation_id = payload["operationId"]
    journal_path = journal_root / f"{operation_id}.json"
    temporary_path = journal_root / f".{operation_id}.tmp"
    encoded = (json.dumps(payload, allow_nan=False, sort_keys=True) + "\n").encode()
    if len(encoded) > ARCHIVE_JOURNAL_MAX_BYTES:
        raise SystemExit("The scan archive journal entry is too large.")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary_path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as journal:
            journal.write(encoded)
            journal.flush()
            os.fsync(journal.fileno())
        os.close(descriptor)
        descriptor = None
        os.replace(temporary_path, journal_path)
        _fsync_directory(journal_root)
        return journal_path
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary_metadata = temporary_path.lstat()
            if stat.S_ISREG(temporary_metadata.st_mode) and not stat.S_ISLNK(
                temporary_metadata.st_mode
            ):
                temporary_path.unlink()
                _fsync_directory(journal_root)
        except FileNotFoundError:
            pass
        raise


def _remove_incomplete_archive_journals(journal_root: Path) -> None:
    removed = False
    for entry in journal_root.iterdir():
        if not entry.name.startswith(".") or not entry.name.endswith(".tmp"):
            continue
        operation_id = entry.name[1:-4]
        try:
            if str(uuid.UUID(operation_id)) != operation_id:
                continue
        except (AttributeError, TypeError, ValueError):
            continue
        metadata = entry.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise SystemExit("The scan archive journal contains an unsafe entry.")
        if os.name != "nt" and (
            metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
        ):
            raise SystemExit("The scan archive journal contains an unsafe entry.")
        entry.unlink()
        removed = True
    if removed:
        _fsync_directory(journal_root)


def _remove_archive_journal(journal_path: Path) -> None:
    try:
        metadata = journal_path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SystemExit("The scan archive journal contains an unsafe entry.")
    journal_path.unlink()
    _fsync_directory(journal_path.parent)


def _validated_archive_journal(journal_path: Path) -> dict[str, object]:
    try:
        metadata = journal_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise SystemExit("The scan archive journal contains an unsafe entry.")
        if metadata.st_size > ARCHIVE_JOURNAL_MAX_BYTES:
            raise SystemExit("The scan archive journal entry is too large.")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(journal_path, flags)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as journal:
                raw = journal.read(ARCHIVE_JOURNAL_MAX_BYTES + 1)
        finally:
            os.close(descriptor)
        payload = json.loads(raw)
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit("The scan archive journal entry is invalid.") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "archiveDir",
        "operationId",
        "previousScanIds",
        "scanDir",
        "version",
    }:
        raise SystemExit("The scan archive journal entry is invalid.")
    operation_id = payload.get("operationId")
    previous_scan_ids = payload.get("previousScanIds")
    try:
        normalized_operation_id = str(uuid.UUID(operation_id))
    except (AttributeError, TypeError, ValueError) as exc:
        raise SystemExit("The scan archive journal operation ID is invalid.") from exc
    if (
        operation_id != normalized_operation_id
        or journal_path.name != f"{operation_id}.json"
        or payload.get("version") != ARCHIVE_JOURNAL_VERSION
        or not isinstance(previous_scan_ids, list)
        or len(previous_scan_ids) > 128
        or not all(isinstance(scan_id, str) for scan_id in previous_scan_ids)
        or len(set(previous_scan_ids)) != len(previous_scan_ids)
    ):
        raise SystemExit("The scan archive journal entry is invalid.")
    try:
        if any(str(uuid.UUID(scan_id)) != scan_id for scan_id in previous_scan_ids):
            raise ValueError
    except (AttributeError, TypeError, ValueError) as exc:
        raise SystemExit("The scan archive journal scan IDs are invalid.") from exc
    scan_dir_value = payload.get("scanDir")
    archive_dir_value = payload.get("archiveDir")
    if not isinstance(scan_dir_value, str) or not isinstance(archive_dir_value, str):
        raise SystemExit("The scan archive journal paths are invalid.")
    scan_dir = Path(scan_dir_value)
    archive_dir = Path(archive_dir_value)
    if (
        not scan_dir.is_absolute()
        or not archive_dir.is_absolute()
        or scan_dir.parent != archive_dir.parent
        or not archive_dir.name.startswith(f"{scan_dir.name}.previous-")
        or not archive_dir.name.endswith(operation_id[:8])
    ):
        raise SystemExit("The scan archive journal paths are invalid.")
    try:
        canonical_parent = scan_dir.parent.resolve(strict=True)
    except OSError as exc:
        raise SystemExit("The scan archive journal parent is unavailable.") from exc
    if (
        not _ordinary_directory(scan_dir.parent)
        or os.path.normcase(str(canonical_parent)) != os.path.normcase(str(scan_dir.parent))
    ):
        raise SystemExit("The scan archive journal parent is unsafe.")
    return payload


def _same_path(left: str | Path, right: str | Path) -> bool:
    try:
        if os.path.samefile(left, right):
            return True
    except OSError:
        pass
    return os.path.normcase(os.path.normpath(os.fspath(left))) == os.path.normcase(
        os.path.normpath(os.fspath(right))
    )


def path_is_within(path: str | Path, directory: str | Path) -> bool:
    current = Path(os.path.abspath(os.fspath(path)))
    boundary = Path(os.path.abspath(os.fspath(directory)))
    while True:
        if _same_path(current, boundary):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _require_private_acl_listing(listing: str) -> None:
    for line in listing.splitlines()[1:]:
        entry = line.strip()
        if not entry:
            continue
        parts = entry.rsplit(maxsplit=2)
        if len(parts) != 3 or parts[1] not in {"allow", "deny"}:
            raise SystemExit(
                "Private scan directory has an unrecognized ACL."
            )
        if parts[1] == "allow":
            raise SystemExit(
                "Private scan directories require paths without extended ACL allow grants."
            )


def require_private_directory_acl(path: Path) -> None:
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["/bin/ls", "-lde", str(path)],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                env={"LANG": "C", "LC_ALL": "C"},
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise SystemExit(
                "Private scan directory ACLs could not be verified."
            ) from exc
        _require_private_acl_listing(result.stdout)
        return
    if sys.platform.startswith("linux"):
        try:
            attributes = os.listxattr(path, follow_symlinks=False)
        except OSError as exc:
            raise SystemExit(
                "Private scan directory ACLs could not be verified."
            ) from exc
        if any(
            attribute in {"system.posix_acl_access", "system.posix_acl_default"}
            or "acl" in attribute.lower()
            and attribute.startswith(("system.", "trusted."))
            for attribute in attributes
        ):
            raise SystemExit(
                "Private scan directories require paths without extended ACLs."
            )
        return
    if os.name != "nt":
        raise SystemExit(
            "Private scan output is not supported on this POSIX platform until ACL validation is available."
        )


def require_private_scan_directory(path: Path) -> os.stat_result:
    metadata = _require_ordinary_directory(path, "Scan output")
    if os.name == "nt":
        raise SystemExit(
            "Private scan output is not supported on Windows until DACL validation is available."
        )
    if metadata.st_mode & 0o777 != 0o700:
        raise SystemExit(
            "The scan artifact directory must use owner-only read, write, and execute permissions (chmod 700)."
        )
    if metadata.st_uid != os.geteuid():
        raise SystemExit("The scan artifact directory must be owned by the current user.")
    require_private_directory_acl(path)
    return metadata


def require_safe_scan_parents(
    parent: Path,
    *,
    allow_immediate_trusted_sticky: bool,
) -> None:
    if os.name == "nt":
        raise SystemExit(
            "Private scan output is not supported on Windows until DACL validation is available."
        )
    current = parent
    effective_uid = os.geteuid()
    while True:
        metadata = _require_ordinary_directory(current, "Scan output parent")
        trusted_owner = metadata.st_uid in {0, effective_uid}
        if not trusted_owner:
            raise SystemExit(
                "Private scan output requires parent directories owned by the current user or root."
            )
        writable_by_other_users = (metadata.st_mode & 0o022) != 0
        sticky = (metadata.st_mode & stat.S_ISVTX) != 0
        trusted_sticky_ancestor = (
            (current != parent or allow_immediate_trusted_sticky)
            and sticky
            and trusted_owner
        )
        if writable_by_other_users and not trusted_sticky_ancestor:
            raise SystemExit(
                "Private scan output requires a parent directory that other users cannot rewrite."
            )
        require_private_directory_acl(current)
        next_parent = current.parent
        if next_parent == current:
            return
        current = next_parent


def prepare_private_state_directory(directory: Path) -> Path:
    if os.name == "nt":
        raise SystemExit(
            "Private scan output is not supported on Windows until DACL validation is available."
        )

    existing_ancestor = directory
    missing_segments: list[str] = []
    while True:
        try:
            existing_ancestor.lstat()
            break
        except FileNotFoundError:
            parent = existing_ancestor.parent
            if parent == existing_ancestor:
                raise SystemExit(
                    "Private state parent must be an existing ordinary directory."
                )
            missing_segments.append(existing_ancestor.name)
            existing_ancestor = parent
        except OSError as exc:
            raise SystemExit(
                "Private state parent must be an existing ordinary directory."
            ) from exc
    require_safe_scan_parents(
        existing_ancestor,
        allow_immediate_trusted_sticky=True,
    )

    current = existing_ancestor
    created_directories: list[Path] = []
    try:
        for segment in reversed(missing_segments):
            current = current / segment
            try:
                current.mkdir(mode=0o700)
                created_directories.append(current)
                current.chmod(0o700)
            except FileExistsError:
                pass
        metadata = _require_ordinary_directory(directory, "Private state path")
        if metadata.st_uid != os.geteuid():
            raise SystemExit("Private state paths must be owned by the current user.")
        directory.chmod(0o700)
        require_private_scan_directory(directory)
        require_safe_scan_parents(
            directory.parent,
            allow_immediate_trusted_sticky=True,
        )
        return directory.resolve(strict=True)
    except BaseException:
        for created_directory in reversed(created_directories):
            try:
                created_directory.rmdir()
            except OSError:
                pass
        raise


def _entry_metadata(path: Path, label: str) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SystemExit(f"Interrupted scan archive recovery could not inspect {label}.") from exc


def _restore_uncommitted_archive(scan_dir: Path, archive_dir: Path) -> None:
    scan_metadata = _entry_metadata(scan_dir, "the scan output path")
    archive_metadata = _entry_metadata(archive_dir, "the archive path")
    scan_exists = scan_metadata is not None
    archive_exists = archive_metadata is not None
    scan_is_directory = scan_exists and stat.S_ISDIR(scan_metadata.st_mode)
    archive_is_directory = archive_exists and stat.S_ISDIR(archive_metadata.st_mode)
    if (scan_exists and not scan_is_directory) or (
        archive_exists and not archive_is_directory
    ):
        raise SystemExit("Interrupted scan archive recovery found an unsafe filesystem entry.")
    if archive_is_directory and scan_is_directory:
        if next(scan_dir.iterdir(), None) is not None:
            raise SystemExit(
                "Interrupted scan archive recovery found a non-empty replacement directory."
            )
        scan_dir.rmdir()
        os.rename(archive_dir, scan_dir)
    elif archive_is_directory and not scan_exists:
        os.rename(archive_dir, scan_dir)
    elif not archive_exists and not scan_exists:
        raise SystemExit("Interrupted scan archive recovery could not find either directory.")
    _fsync_directory(scan_dir.parent)


def recover_archive_journal(
    connection: sqlite3.Connection,
    journal_path: Path,
) -> None:
    payload = _validated_archive_journal(journal_path)
    operation_id = str(payload["operationId"])
    previous_scan_ids = list(payload["previousScanIds"])
    scan_dir = Path(str(payload["scanDir"]))
    archive_dir = Path(str(payload["archiveDir"]))
    new_scan = connection.execute(
        "SELECT scan_dir FROM scans WHERE id = ?", (operation_id,)
    ).fetchone()
    previous_rows = (
        connection.execute(
            f"SELECT id, scan_dir FROM scans WHERE id IN ({','.join('?' for _ in previous_scan_ids)})",
            previous_scan_ids,
        ).fetchall()
        if previous_scan_ids
        else []
    )
    previous_by_id = {row["id"]: row for row in previous_rows}
    if len(previous_by_id) != len(previous_scan_ids):
        raise SystemExit("The scan archive journal no longer matches workbench history.")
    committed = (
        new_scan is not None
        and _same_path(new_scan["scan_dir"], scan_dir)
        and all(
            _same_path(previous_by_id[scan_id]["scan_dir"], archive_dir)
            for scan_id in previous_scan_ids
        )
    )
    uncommitted = (
        new_scan is None
        and all(_same_path(previous_by_id[scan_id]["scan_dir"], scan_dir) for scan_id in previous_scan_ids)
    )
    if committed:
        if not _ordinary_directory(scan_dir) or not _ordinary_directory(archive_dir):
            raise SystemExit(
                "Committed scan archive recovery found missing or unsafe directories."
            )
    elif uncommitted:
        _restore_uncommitted_archive(scan_dir, archive_dir)
    else:
        raise SystemExit("The scan archive journal does not match a safe database state.")
    _remove_archive_journal(journal_path)


def recover_pending_archives(
    connection: sqlite3.Connection,
    journal_root: Path,
    *,
    transaction_open: bool = False,
) -> None:
    journal_root = require_archive_journal_root(journal_root)
    _remove_incomplete_archive_journals(journal_root)
    entries = sorted(journal_root.iterdir())
    if not entries:
        return
    if any(entry.suffix != ".json" for entry in entries):
        raise SystemExit("The scan archive journal contains an unexpected entry.")
    if transaction_open:
        if not connection.in_transaction:
            raise SystemExit("Scan archive recovery requires an active database transaction.")
        for journal_path in entries:
            recover_archive_journal(connection, journal_path)
        return
    connection.execute("BEGIN IMMEDIATE")
    try:
        for journal_path in entries:
            recover_archive_journal(connection, journal_path)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def _artifact_relative_path(artifact_path: str, scan_dir: Path) -> str | None:
    if not os.path.isabs(artifact_path):
        return None
    try:
        common = os.path.commonpath(
            [os.path.normcase(artifact_path), os.path.normcase(str(scan_dir))]
        )
    except ValueError:
        return None
    if common != os.path.normcase(str(scan_dir)):
        return None
    relative_path = os.path.relpath(artifact_path, scan_dir)
    if relative_path == os.pardir or relative_path.startswith(f"{os.pardir}{os.sep}"):
        return None
    return relative_path


def archive_scan(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    scan_dir: Path,
    timestamp: str,
    *,
    new_scan_id: str,
    journal_root: Path,
) -> tuple[
    Path | None,
    Path | None,
    tuple[os.stat_result, os.stat_result] | None,
]:
    initial_scan_directory = require_private_scan_directory(scan_dir)
    require_safe_scan_parents(
        scan_dir.parent,
        allow_immediate_trusted_sticky=not args.archive_existing,
    )
    candidate_scans = connection.execute(
        "SELECT id, status, scan_dir FROM scans ORDER BY id"
    ).fetchall()
    previous_scans = [
        scan for scan in candidate_scans if _same_path(scan["scan_dir"], scan_dir)
    ]
    descendant_scans = [
        scan
        for scan in candidate_scans
        if not _same_path(scan["scan_dir"], scan_dir)
        and path_is_within(scan["scan_dir"], scan_dir)
    ]
    entries = list(scan_dir.iterdir())
    if not args.archive_existing:
        if previous_scans:
            raise SystemExit(
                "The scan artifact directory belongs to an existing scan. "
                "Use --archive-existing to preserve that scan and start a new one."
            )
        if entries:
            raise SystemExit("The scan artifact directory must be empty before the scan starts.")
        return None, None, None
    if descendant_scans:
        raise SystemExit(
            "Cannot archive a directory that contains registered scan output directories."
        )
    if any(previous_scan["status"] == "running" for previous_scan in previous_scans):
        raise SystemExit("Cannot archive the output of a running scan.")
    if not previous_scans and not entries:
        current_scan_directory = _require_ordinary_directory(scan_dir, "Scan output")
        if not _same_directory_identity(initial_scan_directory, current_scan_directory):
            raise SystemExit("The scan output directory changed while the scan was starting.")
        if next(scan_dir.iterdir(), None) is not None:
            raise SystemExit("The scan artifact directory must be empty before the scan starts.")
        return None, None, None

    archived_scan_dir = scan_dir.with_name(
        f"{scan_dir.name}.previous-{compact_timestamp()}-{new_scan_id[:8]}"
    )
    if archived_scan_dir.exists() or archived_scan_dir.is_symlink():
        raise SystemExit("The generated scan archive directory already exists.")
    journal_path = _write_archive_journal(
        journal_root,
        {
            "archiveDir": str(archived_scan_dir),
            "operationId": new_scan_id,
            "previousScanIds": [scan["id"] for scan in previous_scans],
            "scanDir": str(scan_dir),
            "version": ARCHIVE_JOURNAL_VERSION,
        },
    )
    try:
        source_before_move = _require_ordinary_directory(scan_dir, "Scan output")
        if not _same_directory_identity(initial_scan_directory, source_before_move):
            raise SystemExit("The scan output directory changed while the scan was starting.")
        os.rename(scan_dir, archived_scan_dir)
        archived_after_move = _require_ordinary_directory(
            archived_scan_dir, "Archived scan output"
        )
        if not _same_directory_identity(source_before_move, archived_after_move):
            raise SystemExit("The scan output directory changed while it was being archived.")
        scan_dir.mkdir(mode=0o700)
        if os.name != "nt":
            scan_dir.chmod(0o700)
        replacement_after_create = require_private_scan_directory(scan_dir)
        if next(scan_dir.iterdir(), None) is not None:
            raise SystemExit("The replacement scan output directory must be empty.")
        _fsync_directory(scan_dir.parent)
        for previous_scan in previous_scans:
            previous_scan_dir = Path(previous_scan["scan_dir"])
            connection.execute(
                "UPDATE scans SET scan_dir = ?, updated_at = ? WHERE id = ?",
                (str(archived_scan_dir), timestamp, previous_scan["id"]),
            )
            artifacts = connection.execute(
                "SELECT kind, path FROM scan_artifacts WHERE scan_id = ?",
                (previous_scan["id"],),
            ).fetchall()
            for artifact in artifacts:
                relative_path = _artifact_relative_path(
                    artifact["path"], previous_scan_dir
                )
                if relative_path is None:
                    continue
                connection.execute(
                    "UPDATE scan_artifacts SET path = ? WHERE scan_id = ? AND kind = ?",
                    (
                        str(archived_scan_dir / relative_path),
                        previous_scan["id"],
                        artifact["kind"],
                    ),
                )
        archive_guard = (archived_after_move, replacement_after_create)
        validate_archive_guard(scan_dir, archived_scan_dir, archive_guard)
        return archived_scan_dir, journal_path, archive_guard
    except BaseException:
        try:
            _restore_uncommitted_archive(scan_dir, archived_scan_dir)
            _remove_archive_journal(journal_path)
        except BaseException as recovery_error:
            raise SystemExit(
                f"Scan output archival failed and requires recovery from {journal_path}."
            ) from recovery_error
        raise


def create_private_native_scan_directory(target_root: Path, revision: str) -> Path:
    if os.name == "nt":
        raise SystemExit(
            "Private scan output is not supported on Windows until DACL validation is available."
        )
    scan_dir = Path(
        tempfile.mkdtemp(
            prefix=f"{safe_segment(revision)}_{compact_timestamp()}_",
            dir=target_root,
        )
    ).resolve()
    try:
        scan_dir.chmod(0o700)
        require_private_scan_directory(scan_dir)
        require_safe_scan_parents(
            scan_dir.parent,
            allow_immediate_trusted_sticky=False,
        )
    except BaseException:
        try:
            scan_dir.rmdir()
        except OSError:
            pass
        raise
    return scan_dir


def insert_running_scan(
    connection: sqlite3.Connection,
    *,
    scan_id: str,
    workspace: sqlite3.Row,
    target: Path,
    scope: str,
    diff_target: dict[str, str] | None,
    target_identity: tuple[str, str | None, int | str, int | str],
    target_root: Path,
    target_summary: str | None,
    scope_file_count: int,
    timestamp: str,
    handoff_status: str = "pending",
    scan_dir: Path | None = None,
) -> str:
    revision = target_identity[0]
    native_scan = scan_dir is None
    if scan_dir is None:
        if os.name == "nt":
            raise SystemExit(
                "Private scan output is not supported on Windows until DACL validation is available."
            )
        if path_is_within(target_root, target):
            raise SystemExit(
                "The scan artifact directory must be outside the selected target."
            )
        # Native workbench scans create their own output directory. Validate the
        # complete parent chain before creating it so Windows fails closed before
        # any filesystem write, then repeat both checks on the concrete directory
        # while the caller's registration transaction is still open.
        require_safe_scan_parents(
            target_root,
            allow_immediate_trusted_sticky=False,
        )
        scan_dir = create_private_native_scan_directory(target_root, revision)
    connection.execute(
        """
        INSERT INTO scans (
            id, workspace_id, target_id, target_path, target_revision, target_snapshot_digest,
            target_device, target_inode, scope, mode, user_context,
            deep_scan_owner_thread_id, diff_target_kind, diff_base_revision,
            diff_head_revision, diff_content_digest, target_summary, scan_dir, status, phase,
            handoff_status, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', 'preflight',
            ?, ?, ?, ?)
        """,
        (
            scan_id,
            workspace["id"],
            workspace["target_id"],
            str(target),
            *target_identity,
            scope,
            workspace["default_mode"],
            workspace["user_context"],
            workspace["thread_id"] if workspace["default_mode"] == "deep" else None,
            diff_target["kind"] if diff_target else None,
            diff_target["baseRevision"] if diff_target else None,
            diff_target["headRevision"] if diff_target else None,
            diff_target.get("contentDigest") if diff_target else None,
            target_summary,
            str(scan_dir),
            handoff_status,
            timestamp,
            timestamp,
            timestamp,
        ),
    )
    connection.execute(
        """
        INSERT INTO scan_progress (
            scan_id, scope_file_count, review_items_total, review_items_completed,
            reportable_findings_count, updated_at
        ) VALUES (?, ?, 0, 0, 0, ?)
        """,
        (scan_id, scope_file_count, timestamp),
    )
    connection.execute(
        "UPDATE workspaces SET active_scan_id = ?, updated_at = ? WHERE id = ?",
        (scan_id, timestamp, workspace["id"]),
    )
    if native_scan:
        scan = next(connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)))
        false_positives = get_scan_feedback(connection, scan)["falsePositives"]
        if false_positives:
            write_scan_local_bytes(
                scan_dir,
                "artifacts/01_context/false_positive_feedback.json",
                (json.dumps(false_positives, allow_nan=False) + "\n").encode(),
            )
    return scan_id


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()

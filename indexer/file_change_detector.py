# File Change Detector - Enhanced File Tracking for Incremental Indexing
# Based on ACI's IndexMetadataStore design
#
# Features:
# - Content hash based change detection (not just mtime)
# - Batch operations for efficiency
# - Pending batch tracking for crash recovery
# - Repository-scoped file tracking
# - Stale file detection

import hashlib
import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple, Any

logger = logging.getLogger(__name__)


@dataclass
class IndexedFileInfo:
    """Information about an indexed file (ACI compatible)"""
    file_path: str
    content_hash: str
    language: str
    line_count: int
    chunk_count: int
    indexed_at: datetime
    modified_time: float
    chunk_ids: List[str] = field(default_factory=list)


@dataclass
class PendingBatch:
    """Information about a pending batch operation for crash recovery"""
    batch_id: str
    file_paths: List[str]
    chunk_ids: List[str]
    created_at: datetime


@dataclass
class FileChangeResult:
    """Result of file change detection"""
    new_files: List[Path]
    modified_files: List[Path]
    deleted_files: List[str]
    unchanged_files: List[str]

    @property
    def has_changes(self) -> bool:
        return bool(self.new_files or self.modified_files or self.deleted_files)

    @property
    def total_changes(self) -> int:
        return len(self.new_files) + len(self.modified_files) + len(self.deleted_files)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "new_files": len(self.new_files),
            "modified_files": len(self.modified_files),
            "deleted_files": len(self.deleted_files),
            "unchanged_files": len(self.unchanged_files),
            "has_changes": self.has_changes,
        }


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA-256 hash of file content"""
    content = file_path.read_bytes()
    return hashlib.sha256(content).hexdigest()


class FileChangeDetector:
    """Enhanced file change detector for incremental indexing

    Based on ACI's IndexMetadataStore design with improvements:
    - Thread-safe SQLite operations
    - Batch operations for efficiency
    - Pending batch tracking for crash recovery
    - Repository-scoped file tracking

    Example:
        detector = FileChangeDetector(".audit_cache/file_index.db")
        changes = detector.detect_changes(root_path, current_files)
        # Process changes...
        detector.update_files_batch(processed_files)
    """

    def __init__(self, db_path: str = ".audit_cache/file_index.db"):
        """Initialize file change detector

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()
        self._closed = False
        self._initialized = False

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create database connection (thread-safe)"""
        with self._lock:
            if self._conn is None:
                self._conn = sqlite3.connect(
                    str(self.db_path),
                    check_same_thread=False
                )
                self._conn.row_factory = sqlite3.Row
                # Enable WAL mode for better concurrency
                self._conn.execute("PRAGMA journal_mode=WAL;")
                self._conn.execute("PRAGMA busy_timeout=5000;")
            return self._conn

    def initialize(self) -> None:
        """Initialize database schema"""
        if self._initialized:
            return

        conn = self._get_connection()
        with self._lock:
            # Main file index table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS indexed_files (
                    file_path TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    language TEXT,
                    line_count INTEGER DEFAULT 0,
                    chunk_count INTEGER DEFAULT 0,
                    chunk_ids TEXT,
                    indexed_at TEXT NOT NULL,
                    modified_time REAL NOT NULL
                )
            """)

            # Index for faster queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_content_hash
                ON indexed_files(content_hash)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_modified_time
                ON indexed_files(modified_time)
            """)

            # Repository info table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS repositories (
                    root_path TEXT PRIMARY KEY,
                    collection_name TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            # Pending batches for crash recovery
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pending_batches (
                    batch_id TEXT PRIMARY KEY,
                    file_paths TEXT NOT NULL,
                    chunk_ids TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            conn.commit()
            self._initialized = True
            logger.info(f"Initialized file change detector: {self.db_path}")

    def _ensure_initialized(self) -> None:
        """Ensure database is initialized"""
        if not self._initialized:
            self.initialize()

    # ─────────────────────────────────────────────────────────────────
    # Change Detection
    # ─────────────────────────────────────────────────────────────────

    def detect_changes(
        self,
        root_path: Path,
        current_files: List[Path],
        use_content_hash: bool = True
    ) -> FileChangeResult:
        """Detect file changes compared to indexed state

        Args:
            root_path: Root directory path
            current_files: List of current files to check
            use_content_hash: Use content hash for change detection (slower but accurate)

        Returns:
            FileChangeResult with categorized files
        """
        self._ensure_initialized()

        # Get existing file hashes from database
        existing_hashes = self.get_file_hashes_under_root(str(root_path))
        existing_paths = set(existing_hashes.keys())
        current_paths = {str(f) for f in current_files}

        # Categorize files
        new_paths = current_paths - existing_paths
        deleted_paths = existing_paths - current_paths
        common_paths = current_paths & existing_paths

        # Check for modifications in common files
        new_files = [Path(p) for p in new_paths]
        modified_files = []
        unchanged_files = []

        for path_str in common_paths:
            file_path = Path(path_str)
            if not file_path.exists():
                continue

            is_modified = False

            if use_content_hash:
                # Accurate: compare content hash
                try:
                    current_hash = compute_file_hash(file_path)
                    if current_hash != existing_hashes.get(path_str):
                        is_modified = True
                except Exception as e:
                    logger.debug(f"Failed to hash {path_str}: {e}")
                    is_modified = True
            else:
                # Fast: compare mtime only
                try:
                    file_info = self.get_file_info(path_str)
                    if file_info:
                        current_mtime = file_path.stat().st_mtime
                        if current_mtime != file_info.modified_time:
                            is_modified = True
                except Exception:
                    is_modified = True

            if is_modified:
                modified_files.append(file_path)
            else:
                unchanged_files.append(path_str)

        return FileChangeResult(
            new_files=new_files,
            modified_files=modified_files,
            deleted_files=list(deleted_paths),
            unchanged_files=unchanged_files,
        )

    def check_file_changed(self, file_path: Path) -> bool:
        """Check if a single file has changed

        Args:
            file_path: Path to check

        Returns:
            True if file is new or modified
        """
        self._ensure_initialized()

        if not file_path.exists():
            return False

        path_str = str(file_path)
        file_info = self.get_file_info(path_str)

        if file_info is None:
            return True  # New file

        # Check mtime first (fast)
        try:
            current_mtime = file_path.stat().st_mtime
            if current_mtime == file_info.modified_time:
                return False

            # mtime changed, verify with content hash
            current_hash = compute_file_hash(file_path)
            return current_hash != file_info.content_hash
        except Exception:
            return True

    # ─────────────────────────────────────────────────────────────────
    # File Operations
    # ─────────────────────────────────────────────────────────────────

    def get_file_info(self, file_path: str) -> Optional[IndexedFileInfo]:
        """Get information about an indexed file"""
        self._ensure_initialized()

        with self._lock:
            cursor = self._get_connection().execute(
                "SELECT * FROM indexed_files WHERE file_path = ?",
                (file_path,)
            )
            row = cursor.fetchone()

            if row is None:
                return None

            chunk_ids = []
            if row["chunk_ids"]:
                try:
                    chunk_ids = json.loads(row["chunk_ids"])
                except json.JSONDecodeError:
                    chunk_ids = row["chunk_ids"].split(",")

            return IndexedFileInfo(
                file_path=row["file_path"],
                content_hash=row["content_hash"],
                language=row["language"] or "",
                line_count=row["line_count"] or 0,
                chunk_count=row["chunk_count"] or 0,
                indexed_at=datetime.fromisoformat(row["indexed_at"]),
                modified_time=row["modified_time"],
                chunk_ids=chunk_ids,
            )

    def upsert_file(self, info: IndexedFileInfo) -> None:
        """Insert or update file index information"""
        self._ensure_initialized()

        chunk_ids_json = json.dumps(info.chunk_ids) if info.chunk_ids else "[]"

        with self._lock:
            self._get_connection().execute("""
                INSERT OR REPLACE INTO indexed_files
                (file_path, content_hash, language, line_count, chunk_count,
                 chunk_ids, indexed_at, modified_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                info.file_path,
                info.content_hash,
                info.language,
                info.line_count,
                info.chunk_count,
                chunk_ids_json,
                info.indexed_at.isoformat(),
                info.modified_time,
            ))
            self._get_connection().commit()

    def upsert_files_batch(self, files: List[IndexedFileInfo]) -> None:
        """Batch insert or update file index information"""
        if not files:
            return

        self._ensure_initialized()

        with self._lock:
            conn = self._get_connection()
            conn.executemany("""
                INSERT OR REPLACE INTO indexed_files
                (file_path, content_hash, language, line_count, chunk_count,
                 chunk_ids, indexed_at, modified_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    f.file_path,
                    f.content_hash,
                    f.language,
                    f.line_count,
                    f.chunk_count,
                    json.dumps(f.chunk_ids) if f.chunk_ids else "[]",
                    f.indexed_at.isoformat(),
                    f.modified_time,
                )
                for f in files
            ])
            conn.commit()

    def delete_file(self, file_path: str) -> List[str]:
        """Delete file index and return associated chunk IDs"""
        self._ensure_initialized()

        with self._lock:
            # Get chunk IDs first
            cursor = self._get_connection().execute(
                "SELECT chunk_ids FROM indexed_files WHERE file_path = ?",
                (file_path,)
            )
            row = cursor.fetchone()

            chunk_ids = []
            if row and row["chunk_ids"]:
                try:
                    chunk_ids = json.loads(row["chunk_ids"])
                except json.JSONDecodeError:
                    chunk_ids = row["chunk_ids"].split(",")

            # Delete record
            self._get_connection().execute(
                "DELETE FROM indexed_files WHERE file_path = ?",
                (file_path,)
            )
            self._get_connection().commit()

            return chunk_ids

    def delete_files_batch(self, file_paths: List[str]) -> Dict[str, List[str]]:
        """Batch delete files and return file -> chunk IDs mapping"""
        if not file_paths:
            return {}

        self._ensure_initialized()

        with self._lock:
            conn = self._get_connection()

            # Get all chunk IDs first
            placeholders = ",".join("?" * len(file_paths))
            cursor = conn.execute(
                f"SELECT file_path, chunk_ids FROM indexed_files WHERE file_path IN ({placeholders})",
                file_paths
            )

            result = {}
            for row in cursor.fetchall():
                chunk_ids = []
                if row["chunk_ids"]:
                    try:
                        chunk_ids = json.loads(row["chunk_ids"])
                    except json.JSONDecodeError:
                        chunk_ids = row["chunk_ids"].split(",")
                result[row["file_path"]] = chunk_ids

            # Delete records
            conn.executemany(
                "DELETE FROM indexed_files WHERE file_path = ?",
                [(p,) for p in file_paths]
            )
            conn.commit()

            return result

    def get_file_hashes_under_root(self, root_path: str) -> Dict[str, str]:
        """Get all file paths and content hashes under a root path"""
        self._ensure_initialized()

        # Normalize root path
        root = Path(root_path).resolve()
        root_prefix = str(root).rstrip("/\\") + "/"

        with self._lock:
            cursor = self._get_connection().execute(
                "SELECT file_path, content_hash FROM indexed_files WHERE file_path LIKE ?",
                (root_prefix + "%",)
            )
            return {row["file_path"]: row["content_hash"] for row in cursor.fetchall()}

    def get_all_file_hashes(self) -> Dict[str, str]:
        """Get all file paths and their content hashes"""
        self._ensure_initialized()

        with self._lock:
            cursor = self._get_connection().execute(
                "SELECT file_path, content_hash FROM indexed_files"
            )
            return {row["file_path"]: row["content_hash"] for row in cursor.fetchall()}

    def get_all_tracked_files(self) -> Set[str]:
        """Get all tracked file paths"""
        self._ensure_initialized()

        with self._lock:
            cursor = self._get_connection().execute(
                "SELECT file_path FROM indexed_files"
            )
            return {row["file_path"] for row in cursor.fetchall()}

    def get_stale_files(self, limit: Optional[int] = None) -> List[Tuple[str, float]]:
        """Get files where modified_time exceeds indexed_at (stale files)

        Returns:
            List of (file_path, staleness_seconds) sorted by staleness descending
        """
        self._ensure_initialized()

        with self._lock:
            cursor = self._get_connection().execute(
                "SELECT file_path, modified_time, indexed_at FROM indexed_files"
            )

            stale_files = []
            for row in cursor.fetchall():
                indexed_at_ts = datetime.fromisoformat(row["indexed_at"]).timestamp()
                staleness = row["modified_time"] - indexed_at_ts
                if staleness > 0:
                    stale_files.append((row["file_path"], staleness))

            stale_files.sort(key=lambda x: x[1], reverse=True)
            return stale_files[:limit] if limit else stale_files

    # ─────────────────────────────────────────────────────────────────
    # Pending Batch Operations (Crash Recovery)
    # ─────────────────────────────────────────────────────────────────

    def create_pending_batch(
        self,
        batch_id: str,
        file_paths: List[str],
        chunk_ids: List[str]
    ) -> None:
        """Create a pending batch marker before writing to stores"""
        self._ensure_initialized()

        with self._lock:
            self._get_connection().execute("""
                INSERT OR REPLACE INTO pending_batches
                (batch_id, file_paths, chunk_ids, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                batch_id,
                json.dumps(file_paths),
                json.dumps(chunk_ids),
                datetime.now().isoformat(),
            ))
            self._get_connection().commit()
            logger.debug(f"Created pending batch: {batch_id}")

    def complete_pending_batch(self, batch_id: str) -> bool:
        """Mark a batch as complete. Returns True if found and deleted."""
        self._ensure_initialized()

        with self._lock:
            cursor = self._get_connection().execute(
                "DELETE FROM pending_batches WHERE batch_id = ?",
                (batch_id,)
            )
            self._get_connection().commit()
            deleted = cursor.rowcount > 0
            if deleted:
                logger.debug(f"Completed pending batch: {batch_id}")
            return deleted

    def get_pending_batches(self) -> List[PendingBatch]:
        """Get all pending batches for crash recovery"""
        self._ensure_initialized()

        with self._lock:
            cursor = self._get_connection().execute(
                "SELECT * FROM pending_batches"
            )
            return [
                PendingBatch(
                    batch_id=row["batch_id"],
                    file_paths=json.loads(row["file_paths"]),
                    chunk_ids=json.loads(row["chunk_ids"]),
                    created_at=datetime.fromisoformat(row["created_at"]),
                )
                for row in cursor.fetchall()
            ]

    def rollback_pending_batch(self, batch_id: str) -> bool:
        """Rollback a pending batch by removing associated file entries"""
        self._ensure_initialized()

        with self._lock:
            conn = self._get_connection()

            # Get batch info
            cursor = conn.execute(
                "SELECT file_paths FROM pending_batches WHERE batch_id = ?",
                (batch_id,)
            )
            row = cursor.fetchone()
            if row is None:
                return False

            file_paths = json.loads(row["file_paths"])

            # Delete file entries
            if file_paths:
                placeholders = ",".join("?" * len(file_paths))
                conn.execute(
                    f"DELETE FROM indexed_files WHERE file_path IN ({placeholders})",
                    file_paths
                )

            # Delete pending batch
            conn.execute(
                "DELETE FROM pending_batches WHERE batch_id = ?",
                (batch_id,)
            )
            conn.commit()

            logger.info(f"Rolled back pending batch {batch_id}: removed {len(file_paths)} file entries")
            return True

    # ─────────────────────────────────────────────────────────────────
    # Repository Operations
    # ─────────────────────────────────────────────────────────────────

    def register_repository(self, root_path: str, collection_name: Optional[str] = None) -> None:
        """Register or update a repository root path"""
        self._ensure_initialized()

        now = datetime.now().isoformat()
        with self._lock:
            self._get_connection().execute("""
                INSERT INTO repositories (root_path, collection_name, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(root_path) DO UPDATE SET
                    collection_name = excluded.collection_name,
                    updated_at = excluded.updated_at
            """, (root_path, collection_name, now, now))
            self._get_connection().commit()

    def get_repositories(self) -> List[Dict[str, Any]]:
        """Get all registered repositories"""
        self._ensure_initialized()

        with self._lock:
            cursor = self._get_connection().execute(
                "SELECT * FROM repositories"
            )
            return [
                {
                    "root_path": row["root_path"],
                    "collection_name": row["collection_name"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
                for row in cursor.fetchall()
            ]

    # ─────────────────────────────────────────────────────────────────
    # Statistics
    # ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Get index statistics"""
        self._ensure_initialized()

        with self._lock:
            conn = self._get_connection()

            # Aggregate stats
            cursor = conn.execute("""
                SELECT
                    COUNT(*) as total_files,
                    COALESCE(SUM(chunk_count), 0) as total_chunks,
                    COALESCE(SUM(line_count), 0) as total_lines
                FROM indexed_files
            """)
            row = cursor.fetchone()

            # Language breakdown
            cursor = conn.execute("""
                SELECT language, COUNT(*) as count
                FROM indexed_files
                WHERE language IS NOT NULL AND language != ''
                GROUP BY language
            """)
            languages = {row["language"]: row["count"] for row in cursor.fetchall()}

            # Pending batches
            cursor = conn.execute("SELECT COUNT(*) as count FROM pending_batches")
            pending = cursor.fetchone()["count"]

            return {
                "total_files": row["total_files"],
                "total_chunks": row["total_chunks"],
                "total_lines": row["total_lines"],
                "languages": languages,
                "pending_batches": pending,
                "db_path": str(self.db_path),
            }

    # ─────────────────────────────────────────────────────────────────
    # Lifecycle
    # ─────────────────────────────────────────────────────────────────

    def clear(self) -> None:
        """Clear all tracking data"""
        self._ensure_initialized()

        with self._lock:
            conn = self._get_connection()
            conn.execute("DELETE FROM indexed_files")
            conn.execute("DELETE FROM pending_batches")
            conn.commit()
            logger.info("Cleared all file tracking data")

    def close(self) -> None:
        """Close database connection"""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
            self._initialized = False

    def __enter__(self) -> "FileChangeDetector":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


# Global instance for convenience
_global_detector: Optional[FileChangeDetector] = None
_global_lock = threading.Lock()


def get_file_change_detector(db_path: str = ".audit_cache/file_index.db") -> FileChangeDetector:
    """Get or create global file change detector

    Args:
        db_path: Database path (only used on first call)

    Returns:
        Global FileChangeDetector instance
    """
    global _global_detector

    with _global_lock:
        if _global_detector is None:
            _global_detector = FileChangeDetector(db_path)
            _global_detector.initialize()
        return _global_detector


def reset_global_detector() -> None:
    """Reset global file change detector"""
    global _global_detector

    with _global_lock:
        if _global_detector is not None:
            _global_detector.close()
            _global_detector = None

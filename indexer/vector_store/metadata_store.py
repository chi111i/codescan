# Metadata store for vector indexing
# Handles file tracking, pending batches, and index consistency

import hashlib
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from contextlib import contextmanager
from enum import Enum

logger = logging.getLogger(__name__)


class BatchStatus(Enum):
    """Status of a pending batch"""
    PENDING = "pending"
    COMMITTED = "committed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class FileInfo:
    """Information about an indexed file"""
    file_path: str
    content_hash: str
    mtime: float
    size: int
    chunk_count: int = 0
    indexed_at: float = field(default_factory=time.time)


@dataclass
class PendingBatch:
    """A batch of changes pending commit to vector store"""
    batch_id: str
    file_paths: List[str]
    chunk_ids: List[str]
    status: BatchStatus = BatchStatus.PENDING
    created_at: float = field(default_factory=time.time)
    committed_at: Optional[float] = None
    error_message: Optional[str] = None


class IndexMetadataStore:
    """Metadata store for index consistency

    Provides:
    - File hash tracking for incremental indexing
    - PendingBatch transaction mechanism
    - Index statistics and health checks

    Based on ACI (augmented-codebase-indexer) best practices.
    """

    def __init__(self, db_path: str = ".audit_cache/index_metadata.db"):
        """Initialize metadata store

        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self._ensure_db_dir()
        self._init_schema()

    def _ensure_db_dir(self) -> None:
        """Ensure database directory exists"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

    def _init_schema(self) -> None:
        """Initialize database schema"""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS indexed_files (
                    file_path TEXT PRIMARY KEY,
                    content_hash TEXT NOT NULL,
                    mtime REAL NOT NULL,
                    size INTEGER NOT NULL,
                    chunk_count INTEGER DEFAULT 0,
                    indexed_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS pending_batches (
                    batch_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at REAL NOT NULL,
                    committed_at REAL,
                    error_message TEXT
                );

                CREATE TABLE IF NOT EXISTS batch_files (
                    batch_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    PRIMARY KEY (batch_id, file_path),
                    FOREIGN KEY (batch_id) REFERENCES pending_batches(batch_id)
                );

                CREATE TABLE IF NOT EXISTS batch_chunks (
                    batch_id TEXT NOT NULL,
                    chunk_id TEXT NOT NULL,
                    PRIMARY KEY (batch_id, chunk_id),
                    FOREIGN KEY (batch_id) REFERENCES pending_batches(batch_id)
                );

                CREATE INDEX IF NOT EXISTS idx_files_hash ON indexed_files(content_hash);
                CREATE INDEX IF NOT EXISTS idx_batches_status ON pending_batches(status);
            """)

    @contextmanager
    def _get_connection(self):
        """Get database connection with proper cleanup"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ========== File Tracking ==========

    def get_file_info(self, file_path: str) -> Optional[FileInfo]:
        """Get info for a tracked file

        Args:
            file_path: Path to the file

        Returns:
            FileInfo or None if not tracked
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM indexed_files WHERE file_path = ?",
                (file_path,)
            ).fetchone()

            if row:
                return FileInfo(
                    file_path=row["file_path"],
                    content_hash=row["content_hash"],
                    mtime=row["mtime"],
                    size=row["size"],
                    chunk_count=row["chunk_count"],
                    indexed_at=row["indexed_at"],
                )
            return None

    def get_files_batch(self, file_paths: List[str]) -> Dict[str, FileInfo]:
        """Get info for multiple files in one query

        Args:
            file_paths: List of file paths

        Returns:
            Dict mapping file_path to FileInfo
        """
        if not file_paths:
            return {}

        with self._get_connection() as conn:
            placeholders = ",".join("?" * len(file_paths))
            rows = conn.execute(
                f"SELECT * FROM indexed_files WHERE file_path IN ({placeholders})",
                file_paths
            ).fetchall()

            return {
                row["file_path"]: FileInfo(
                    file_path=row["file_path"],
                    content_hash=row["content_hash"],
                    mtime=row["mtime"],
                    size=row["size"],
                    chunk_count=row["chunk_count"],
                    indexed_at=row["indexed_at"],
                )
                for row in rows
            }

    def set_file_info(self, info: FileInfo) -> None:
        """Set info for a file

        Args:
            info: FileInfo to store
        """
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO indexed_files
                (file_path, content_hash, mtime, size, chunk_count, indexed_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                info.file_path,
                info.content_hash,
                info.mtime,
                info.size,
                info.chunk_count,
                info.indexed_at,
            ))

    def set_files_batch(self, infos: List[FileInfo]) -> None:
        """Set info for multiple files in one transaction

        Args:
            infos: List of FileInfo to store
        """
        if not infos:
            return

        with self._get_connection() as conn:
            conn.executemany("""
                INSERT OR REPLACE INTO indexed_files
                (file_path, content_hash, mtime, size, chunk_count, indexed_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, [
                (info.file_path, info.content_hash, info.mtime,
                 info.size, info.chunk_count, info.indexed_at)
                for info in infos
            ])

    def delete_file(self, file_path: str) -> None:
        """Delete a file from tracking

        Args:
            file_path: Path to remove
        """
        with self._get_connection() as conn:
            conn.execute(
                "DELETE FROM indexed_files WHERE file_path = ?",
                (file_path,)
            )

    def delete_files_batch(self, file_paths: List[str]) -> None:
        """Delete multiple files from tracking

        Args:
            file_paths: Paths to remove
        """
        if not file_paths:
            return

        with self._get_connection() as conn:
            placeholders = ",".join("?" * len(file_paths))
            conn.execute(
                f"DELETE FROM indexed_files WHERE file_path IN ({placeholders})",
                file_paths
            )

    def get_all_tracked_files(self) -> Set[str]:
        """Get all tracked file paths

        Returns:
            Set of file paths
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT file_path FROM indexed_files"
            ).fetchall()
            return {row["file_path"] for row in rows}

    def is_file_changed(self, file_path: str, current_mtime: float, current_size: int) -> bool:
        """Check if a file has changed since last index

        Args:
            file_path: Path to check
            current_mtime: Current modification time
            current_size: Current file size

        Returns:
            True if file has changed or is new
        """
        info = self.get_file_info(file_path)
        if info is None:
            return True

        # Check mtime and size first (fast path)
        if info.mtime != current_mtime or info.size != current_size:
            return True

        return False

    def is_file_content_changed(
        self,
        file_path: str,
        content_hash: str
    ) -> bool:
        """Check if file content has changed by hash

        Args:
            file_path: Path to check
            content_hash: Current content hash

        Returns:
            True if content has changed or file is new
        """
        info = self.get_file_info(file_path)
        if info is None:
            return True

        return info.content_hash != content_hash

    # ========== Pending Batches ==========

    def create_batch(self, batch_id: str) -> PendingBatch:
        """Create a new pending batch

        Args:
            batch_id: Unique batch identifier

        Returns:
            Created PendingBatch
        """
        now = time.time()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO pending_batches (batch_id, status, created_at)
                VALUES (?, ?, ?)
            """, (batch_id, BatchStatus.PENDING.value, now))

        return PendingBatch(
            batch_id=batch_id,
            file_paths=[],
            chunk_ids=[],
            status=BatchStatus.PENDING,
            created_at=now,
        )

    def add_to_batch(
        self,
        batch_id: str,
        file_paths: List[str],
        chunk_ids: List[str]
    ) -> None:
        """Add files and chunks to a batch

        Args:
            batch_id: Batch identifier
            file_paths: Files in this batch
            chunk_ids: Chunk IDs in this batch
        """
        with self._get_connection() as conn:
            if file_paths:
                conn.executemany(
                    "INSERT OR IGNORE INTO batch_files (batch_id, file_path) VALUES (?, ?)",
                    [(batch_id, fp) for fp in file_paths]
                )

            if chunk_ids:
                conn.executemany(
                    "INSERT OR IGNORE INTO batch_chunks (batch_id, chunk_id) VALUES (?, ?)",
                    [(batch_id, cid) for cid in chunk_ids]
                )

    def commit_batch(self, batch_id: str) -> None:
        """Mark a batch as committed

        Args:
            batch_id: Batch to commit
        """
        now = time.time()
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE pending_batches
                SET status = ?, committed_at = ?
                WHERE batch_id = ?
            """, (BatchStatus.COMMITTED.value, now, batch_id))

    def fail_batch(self, batch_id: str, error_message: str) -> None:
        """Mark a batch as failed

        Args:
            batch_id: Batch that failed
            error_message: Error description
        """
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE pending_batches
                SET status = ?, error_message = ?
                WHERE batch_id = ?
            """, (BatchStatus.FAILED.value, error_message, batch_id))

    def rollback_batch(self, batch_id: str) -> PendingBatch:
        """Get batch info for rollback

        Args:
            batch_id: Batch to rollback

        Returns:
            PendingBatch with file_paths and chunk_ids for cleanup
        """
        with self._get_connection() as conn:
            # Get batch info
            batch_row = conn.execute(
                "SELECT * FROM pending_batches WHERE batch_id = ?",
                (batch_id,)
            ).fetchone()

            if not batch_row:
                raise ValueError(f"Batch not found: {batch_id}")

            # Get file paths
            file_rows = conn.execute(
                "SELECT file_path FROM batch_files WHERE batch_id = ?",
                (batch_id,)
            ).fetchall()
            file_paths = [r["file_path"] for r in file_rows]

            # Get chunk IDs
            chunk_rows = conn.execute(
                "SELECT chunk_id FROM batch_chunks WHERE batch_id = ?",
                (batch_id,)
            ).fetchall()
            chunk_ids = [r["chunk_id"] for r in chunk_rows]

            # Mark as rolled back
            conn.execute("""
                UPDATE pending_batches
                SET status = ?
                WHERE batch_id = ?
            """, (BatchStatus.ROLLED_BACK.value, batch_id))

            return PendingBatch(
                batch_id=batch_id,
                file_paths=file_paths,
                chunk_ids=chunk_ids,
                status=BatchStatus.ROLLED_BACK,
                created_at=batch_row["created_at"],
            )

    def get_pending_batches(self) -> List[PendingBatch]:
        """Get all pending (uncommitted) batches

        Returns:
            List of pending batches
        """
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM pending_batches
                WHERE status = ?
                ORDER BY created_at
            """, (BatchStatus.PENDING.value,)).fetchall()

            batches = []
            for row in rows:
                # Get file paths
                file_rows = conn.execute(
                    "SELECT file_path FROM batch_files WHERE batch_id = ?",
                    (row["batch_id"],)
                ).fetchall()

                # Get chunk IDs
                chunk_rows = conn.execute(
                    "SELECT chunk_id FROM batch_chunks WHERE batch_id = ?",
                    (row["batch_id"],)
                ).fetchall()

                batches.append(PendingBatch(
                    batch_id=row["batch_id"],
                    file_paths=[r["file_path"] for r in file_rows],
                    chunk_ids=[r["chunk_id"] for r in chunk_rows],
                    status=BatchStatus(row["status"]),
                    created_at=row["created_at"],
                ))

            return batches

    def cleanup_old_batches(self, max_age_seconds: float = 86400) -> int:
        """Clean up old committed/failed batches

        Args:
            max_age_seconds: Maximum age for batch records

        Returns:
            Number of batches cleaned up
        """
        cutoff = time.time() - max_age_seconds

        with self._get_connection() as conn:
            # Get old batch IDs
            rows = conn.execute("""
                SELECT batch_id FROM pending_batches
                WHERE status IN (?, ?, ?)
                AND created_at < ?
            """, (
                BatchStatus.COMMITTED.value,
                BatchStatus.FAILED.value,
                BatchStatus.ROLLED_BACK.value,
                cutoff,
            )).fetchall()

            batch_ids = [r["batch_id"] for r in rows]

            if not batch_ids:
                return 0

            placeholders = ",".join("?" * len(batch_ids))

            # Delete related records
            conn.execute(
                f"DELETE FROM batch_files WHERE batch_id IN ({placeholders})",
                batch_ids
            )
            conn.execute(
                f"DELETE FROM batch_chunks WHERE batch_id IN ({placeholders})",
                batch_ids
            )
            conn.execute(
                f"DELETE FROM pending_batches WHERE batch_id IN ({placeholders})",
                batch_ids
            )

            return len(batch_ids)

    # ========== Statistics ==========

    def get_stats(self) -> Dict[str, Any]:
        """Get index statistics

        Returns:
            Dict with statistics
        """
        with self._get_connection() as conn:
            file_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM indexed_files"
            ).fetchone()["cnt"]

            total_chunks = conn.execute(
                "SELECT SUM(chunk_count) as total FROM indexed_files"
            ).fetchone()["total"] or 0

            pending_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM pending_batches WHERE status = ?",
                (BatchStatus.PENDING.value,)
            ).fetchone()["cnt"]

            failed_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM pending_batches WHERE status = ?",
                (BatchStatus.FAILED.value,)
            ).fetchone()["cnt"]

            return {
                "indexed_files": file_count,
                "total_chunks": total_chunks,
                "pending_batches": pending_count,
                "failed_batches": failed_count,
            }

    def clear(self) -> None:
        """Clear all metadata"""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM batch_chunks")
            conn.execute("DELETE FROM batch_files")
            conn.execute("DELETE FROM pending_batches")
            conn.execute("DELETE FROM indexed_files")


def compute_file_hash(file_path: str) -> str:
    """Compute SHA256 hash of file content

    Args:
        file_path: Path to file

    Returns:
        Hex-encoded hash
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

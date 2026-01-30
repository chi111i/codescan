# Incremental Indexing Pipeline - Efficient Updates for Changed Files
# Based on ACI's IndexingService incremental update design
#
# Features:
# - Content hash based change detection (not just mtime)
# - Only process new/modified files, skip unchanged
# - Delete stale entries for removed files
# - Pending batch tracking for crash recovery
# - Integration with 6-stage IndexingPipeline

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Callable, Dict, Any, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from llm_client import BaseLLMClient

from .models import CodeUnit
from .file_change_detector import (
    FileChangeDetector,
    FileChangeResult,
    IndexedFileInfo,
    compute_file_hash,
)
from .indexing_pipeline import (
    IndexingPipeline,
    PipelineConfig,
    PipelineStats,
    StageProgress,
    ProgressCallback,
)

logger = logging.getLogger(__name__)


@dataclass
class IncrementalStats:
    """Statistics for incremental indexing"""
    # File counts
    new_files: int = 0
    modified_files: int = 0
    deleted_files: int = 0
    unchanged_files: int = 0
    failed_files: int = 0

    # Chunk counts
    chunks_added: int = 0
    chunks_deleted: int = 0

    # Timings
    detection_time: float = 0.0
    deletion_time: float = 0.0
    indexing_time: float = 0.0
    total_time: float = 0.0

    # Nested pipeline stats
    pipeline_stats: Optional[PipelineStats] = None

    @property
    def has_changes(self) -> bool:
        return bool(self.new_files or self.modified_files or self.deleted_files)

    @property
    def total_processed(self) -> int:
        return self.new_files + self.modified_files

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            "files": {
                "new": self.new_files,
                "modified": self.modified_files,
                "deleted": self.deleted_files,
                "unchanged": self.unchanged_files,
                "failed": self.failed_files,
                "total_processed": self.total_processed,
            },
            "chunks": {
                "added": self.chunks_added,
                "deleted": self.chunks_deleted,
            },
            "timings": {
                "detection": round(self.detection_time, 3),
                "deletion": round(self.deletion_time, 3),
                "indexing": round(self.indexing_time, 3),
                "total": round(self.total_time, 3),
            },
            "has_changes": self.has_changes,
        }
        if self.pipeline_stats:
            result["pipeline"] = self.pipeline_stats.to_dict()
        return result


@dataclass
class IncrementalConfig:
    """Configuration for incremental indexing"""
    # Change detection
    use_content_hash: bool = True  # Use SHA-256 hash (slower but accurate)

    # Pipeline settings (passed to IndexingPipeline)
    max_workers: int = 4
    chunk_size: int = 2000
    embedding_batch_size: int = 150
    storage_batch_size: int = 100
    enable_parallel: bool = True
    parallel_threshold: int = 20

    # Crash recovery
    enable_pending_batch_tracking: bool = True
    cleanup_stale_batches_on_start: bool = True
    stale_batch_timeout_hours: int = 24

    def to_pipeline_config(self) -> PipelineConfig:
        """Convert to PipelineConfig"""
        return PipelineConfig(
            max_workers=self.max_workers,
            chunk_size=self.chunk_size,
            embedding_batch_size=self.embedding_batch_size,
            storage_batch_size=self.storage_batch_size,
            enable_parallel=self.enable_parallel,
            parallel_threshold=self.parallel_threshold,
        )


class IncrementalPipeline:
    """Incremental Indexing Pipeline

    Efficiently updates the index by only processing changed files.
    Uses FileChangeDetector for content hash based change detection
    and delegates actual indexing to IndexingPipeline.

    Based on ACI's IndexingService incremental update design with:
    - Pending batch tracking for crash recovery
    - Automatic cleanup of stale entries
    - Integration with 6-stage batch pipeline

    Example:
        pipeline = IncrementalPipeline(config, llm_client, vector_store, detector)
        stats = await pipeline.run_incremental(root_path, file_scanner)
    """

    STAGE_DETECT = "detect"
    STAGE_DELETE = "delete"
    STAGE_INDEX = "index"

    def __init__(
        self,
        config: IncrementalConfig,
        llm_client: "BaseLLMClient",
        vector_store,
        change_detector: Optional[FileChangeDetector] = None,
        db_path: str = ".audit_cache/file_index.db",
    ):
        """Initialize incremental pipeline

        Args:
            config: Incremental indexing configuration
            llm_client: LLM client for embedding generation
            vector_store: Vector store for persistence
            change_detector: Optional pre-configured FileChangeDetector
            db_path: Database path for change detector (if not provided)
        """
        self.config = config
        self.llm_client = llm_client
        self.vector_store = vector_store

        # Initialize or use provided change detector
        self._change_detector = change_detector or FileChangeDetector(db_path)
        self._change_detector.initialize()

        # Check for stale pending batches on startup
        if config.cleanup_stale_batches_on_start:
            self._cleanup_stale_batches()

        # Statistics
        self._stats = IncrementalStats()
        self._progress_callback: Optional[ProgressCallback] = None

    def _cleanup_stale_batches(self) -> int:
        """Clean up stale pending batches from previous failed runs

        Returns:
            Number of batches cleaned up
        """
        try:
            pending_batches = self._change_detector.get_pending_batches()
            if not pending_batches:
                return 0

            cleaned = 0
            cutoff = datetime.now().timestamp() - (
                self.config.stale_batch_timeout_hours * 3600
            )

            for batch in pending_batches:
                batch_age = datetime.now().timestamp() - batch.created_at.timestamp()
                if batch_age > self.config.stale_batch_timeout_hours * 3600:
                    logger.warning(
                        f"Cleaning up stale batch {batch.batch_id} "
                        f"(age: {batch_age / 3600:.1f} hours)"
                    )
                    if self._change_detector.rollback_pending_batch(batch.batch_id):
                        cleaned += 1

            if cleaned > 0:
                logger.info(f"Cleaned up {cleaned} stale pending batch(es)")

            return cleaned

        except Exception as e:
            logger.debug(f"Could not check pending batches: {e}")
            return 0

    def run_incremental_sync(
        self,
        root_path: Path,
        file_scanner: Optional[Callable[[Path], List[Path]]] = None,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> IncrementalStats:
        """Run incremental indexing synchronously

        Args:
            root_path: Root directory to index
            file_scanner: Optional file scanner function
            progress_callback: Optional progress callback

        Returns:
            Incremental indexing statistics
        """
        try:
            loop = asyncio.get_running_loop()
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(
                    asyncio.run,
                    self.run_incremental(root_path, file_scanner, progress_callback)
                )
                return future.result()
        except RuntimeError:
            return asyncio.run(
                self.run_incremental(root_path, file_scanner, progress_callback)
            )

    async def run_incremental(
        self,
        root_path: Path,
        file_scanner: Optional[Callable[[Path], List[Path]]] = None,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> IncrementalStats:
        """Run incremental indexing pipeline

        Workflow:
        1. Detect changes (new, modified, deleted files)
        2. Delete stale entries for removed/modified files
        3. Index new and modified files using IndexingPipeline

        Args:
            root_path: Root directory to index
            file_scanner: Optional function to scan files (default: rglob)
            progress_callback: Optional callback for progress updates

        Returns:
            Incremental indexing statistics
        """
        self._progress_callback = progress_callback
        self._stats = IncrementalStats()
        start_time = time.time()

        root_path = Path(root_path).resolve()
        logger.info(f"[Incremental] Starting incremental index: {root_path}")

        try:
            # Stage 1: Detect changes
            changes = await self._stage_detect_changes(root_path, file_scanner)

            if not changes.has_changes:
                logger.info("[Incremental] No changes detected, index is up to date")
                self._stats.total_time = time.time() - start_time
                return self._stats

            # Stage 2: Delete stale entries
            await self._stage_delete_stale(changes)

            # Stage 3: Index changed files
            if changes.new_files or changes.modified_files:
                await self._stage_index_changed(
                    root_path,
                    changes.new_files + changes.modified_files,
                    file_scanner,
                )

        except Exception as e:
            logger.error(f"[Incremental] Failed: {e}")
            raise

        finally:
            self._stats.total_time = time.time() - start_time
            logger.info(
                f"[Incremental] Complete in {self._stats.total_time:.2f}s: "
                f"new={self._stats.new_files}, modified={self._stats.modified_files}, "
                f"deleted={self._stats.deleted_files}, unchanged={self._stats.unchanged_files}"
            )

        return self._stats

    async def _stage_detect_changes(
        self,
        root_path: Path,
        file_scanner: Optional[Callable[[Path], List[Path]]] = None,
    ) -> FileChangeResult:
        """Stage 1: Detect file changes

        Args:
            root_path: Root directory
            file_scanner: Optional file scanner function

        Returns:
            FileChangeResult with categorized files
        """
        self._report_progress(self.STAGE_DETECT, 0, 0, "Detecting changes...")
        start = time.time()

        # Scan current files
        if file_scanner:
            current_files = file_scanner(root_path)
        else:
            current_files = [f for f in root_path.rglob("*") if f.is_file()]

        total_files = len(current_files)
        logger.info(f"[Stage 1/3] Scanning {total_files} files for changes")

        # Detect changes using FileChangeDetector
        changes = await asyncio.to_thread(
            self._change_detector.detect_changes,
            root_path,
            current_files,
            self.config.use_content_hash,
        )

        # Update stats
        self._stats.new_files = len(changes.new_files)
        self._stats.modified_files = len(changes.modified_files)
        self._stats.deleted_files = len(changes.deleted_files)
        self._stats.unchanged_files = len(changes.unchanged_files)
        self._stats.detection_time = time.time() - start

        self._report_progress(
            self.STAGE_DETECT, total_files, total_files,
            f"Detected: new={self._stats.new_files}, "
            f"modified={self._stats.modified_files}, "
            f"deleted={self._stats.deleted_files}"
        )

        logger.info(
            f"[Stage 1/3] Change detection in {self._stats.detection_time:.2f}s: "
            f"new={self._stats.new_files}, modified={self._stats.modified_files}, "
            f"deleted={self._stats.deleted_files}, unchanged={self._stats.unchanged_files}"
        )

        return changes

    async def _stage_delete_stale(self, changes: FileChangeResult) -> None:
        """Stage 2: Delete stale entries for removed/modified files

        For modified files, we delete old chunks before re-indexing.
        For deleted files, we remove all associated data.

        Args:
            changes: FileChangeResult from detection stage
        """
        files_to_delete = changes.deleted_files + [str(f) for f in changes.modified_files]

        if not files_to_delete:
            return

        total = len(files_to_delete)
        self._report_progress(self.STAGE_DELETE, 0, total, "Deleting stale entries...")
        start = time.time()

        deleted_chunks = 0

        for i, file_path in enumerate(files_to_delete):
            try:
                # Get and delete chunk IDs from change detector
                chunk_ids = await asyncio.to_thread(
                    self._change_detector.delete_file,
                    file_path
                )

                # Delete chunks from vector store
                if chunk_ids:
                    for chunk_id in chunk_ids:
                        try:
                            await asyncio.to_thread(
                                self.vector_store.delete,
                                chunk_id
                            )
                            deleted_chunks += 1
                        except Exception as e:
                            logger.debug(f"Failed to delete chunk {chunk_id}: {e}")

            except Exception as e:
                logger.warning(f"Failed to delete stale entry for {file_path}: {e}")

            if (i + 1) % 10 == 0 or i + 1 == total:
                self._report_progress(
                    self.STAGE_DELETE, i + 1, total,
                    f"Deleted {i + 1}/{total} stale entries"
                )

        self._stats.chunks_deleted = deleted_chunks
        self._stats.deletion_time = time.time() - start

        logger.info(
            f"[Stage 2/3] Deleted {deleted_chunks} chunks from {total} files "
            f"in {self._stats.deletion_time:.2f}s"
        )

    async def _stage_index_changed(
        self,
        root_path: Path,
        changed_files: List[Path],
        file_scanner: Optional[Callable[[Path], List[Path]]] = None,
    ) -> None:
        """Stage 3: Index new and modified files

        Delegates to IndexingPipeline for actual processing.

        Args:
            root_path: Root directory
            changed_files: List of files to index
            file_scanner: Original file scanner (for filtering)
        """
        total = len(changed_files)
        self._report_progress(self.STAGE_INDEX, 0, total, "Indexing changed files...")
        start = time.time()

        logger.info(f"[Stage 3/3] Indexing {total} changed files")

        # Create a custom file scanner that only returns changed files
        changed_set = set(str(f) for f in changed_files)

        def incremental_scanner(path: Path) -> List[Path]:
            if file_scanner:
                all_files = file_scanner(path)
                return [f for f in all_files if str(f) in changed_set]
            else:
                return [f for f in changed_files if f.exists()]

        # Create IndexingPipeline for processing
        pipeline_config = self.config.to_pipeline_config()
        pipeline = IndexingPipeline(
            config=pipeline_config,
            llm_client=self.llm_client,
            vector_store=self.vector_store,
            file_scanner=incremental_scanner,
            file_tracker=self._create_file_tracker_adapter(),
        )

        # Run pipeline with progress forwarding
        def pipeline_progress(progress: StageProgress):
            # Forward pipeline progress with stage prefix
            self._report_progress(
                f"{self.STAGE_INDEX}:{progress.stage}",
                progress.current,
                progress.total,
                progress.message,
            )

        # Run the pipeline
        pipeline_stats = await pipeline.run(root_path, pipeline_progress)

        # Update stats
        self._stats.chunks_added = pipeline_stats.chunks_created
        self._stats.failed_files = pipeline_stats.files_failed
        self._stats.pipeline_stats = pipeline_stats
        self._stats.indexing_time = time.time() - start

        # Update file tracking metadata
        await self._update_file_metadata(root_path, changed_files, pipeline)

        logger.info(
            f"[Stage 3/3] Indexed {pipeline_stats.files_parsed} files, "
            f"created {pipeline_stats.chunks_created} chunks "
            f"in {self._stats.indexing_time:.2f}s"
        )

    def _create_file_tracker_adapter(self):
        """Create an adapter that wraps FileChangeDetector for IndexingPipeline

        Returns:
            Object with update_file_state method compatible with pipeline
        """
        class FileTrackerAdapter:
            def __init__(self, detector: FileChangeDetector):
                self._detector = detector

            def update_file_state(
                self,
                file_path: str,
                mtime: float,
                content_hash: str,
                chunk_ids: List[str],
            ) -> None:
                """Update file state in detector"""
                info = IndexedFileInfo(
                    file_path=file_path,
                    content_hash=content_hash,
                    language="",  # Will be filled by pipeline
                    line_count=0,
                    chunk_count=len(chunk_ids),
                    indexed_at=datetime.now(),
                    modified_time=mtime,
                    chunk_ids=chunk_ids,
                )
                self._detector.upsert_file(info)

        return FileTrackerAdapter(self._change_detector)

    async def _update_file_metadata(
        self,
        root_path: Path,
        files: List[Path],
        pipeline: IndexingPipeline,
    ) -> None:
        """Update file metadata after successful indexing

        Args:
            root_path: Root directory
            files: Processed files
            pipeline: Pipeline with chunk mapping info
        """
        # Safely get chunk mapping
        chunk_mapping = {}
        if hasattr(pipeline, 'get_chunk_siblings'):
            try:
                chunk_mapping = pipeline.get_chunk_siblings()
            except Exception as e:
                logger.debug(f"Failed to get chunk siblings: {e}")

        for file_path in files:
            if not file_path.exists():
                continue

            try:
                path_str = str(file_path)
                mtime = file_path.stat().st_mtime
                content_hash = compute_file_hash(file_path)

                # Get chunk IDs for this file
                # Match by relative path or absolute path
                try:
                    rel_path = str(file_path.relative_to(root_path)).replace("\\", "/")
                except ValueError:
                    rel_path = str(file_path).replace("\\", "/")

                file_chunk_ids = []

                for parent_id, chunk_ids in chunk_mapping.items():
                    # Match by relative path, absolute path, or file name
                    if (rel_path in parent_id or
                        path_str in parent_id or
                        file_path.name in parent_id):
                        file_chunk_ids.extend(chunk_ids)

                # Determine language from extension
                ext_to_lang = {
                    ".py": "python",
                    ".js": "javascript",
                    ".ts": "typescript",
                    ".php": "php",
                    ".java": "java",
                    ".go": "go",
                    ".rb": "ruby",
                    ".rs": "rust",
                    ".c": "c",
                    ".cpp": "cpp",
                    ".cs": "csharp",
                }
                language = ext_to_lang.get(file_path.suffix.lower(), "")

                # Count lines
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    line_count = content.count("\n") + 1
                except Exception:
                    line_count = 0

                # Update metadata
                info = IndexedFileInfo(
                    file_path=path_str,
                    content_hash=content_hash,
                    language=language,
                    line_count=line_count,
                    chunk_count=len(file_chunk_ids),
                    indexed_at=datetime.now(),
                    modified_time=mtime,
                    chunk_ids=file_chunk_ids,
                )

                await asyncio.to_thread(self._change_detector.upsert_file, info)

            except Exception as e:
                logger.debug(f"Failed to update metadata for {file_path}: {e}")

    def _report_progress(
        self,
        stage: str,
        current: int,
        total: int,
        message: str,
    ) -> None:
        """Report progress to callback"""
        if self._progress_callback:
            progress = StageProgress(
                stage=stage,
                current=current,
                total=total,
                message=message,
            )
            try:
                self._progress_callback(progress)
            except Exception as e:
                logger.debug(f"Progress callback failed: {e}")

    def get_change_detector(self) -> FileChangeDetector:
        """Get the file change detector instance"""
        return self._change_detector

    def get_stats(self) -> IncrementalStats:
        """Get current statistics"""
        return self._stats

    def get_index_stats(self) -> Dict[str, Any]:
        """Get comprehensive index statistics"""
        detector_stats = self._change_detector.get_stats()
        return {
            "detector": detector_stats,
            "last_incremental": self._stats.to_dict() if self._stats.has_changes else None,
        }

    def cleanup_pending_batches(self) -> int:
        """Manually clean up all pending batches

        Returns:
            Number of batches cleaned up
        """
        pending = self._change_detector.get_pending_batches()
        cleaned = 0

        for batch in pending:
            if self._change_detector.rollback_pending_batch(batch.batch_id):
                cleaned += 1
                logger.info(f"Cleaned up pending batch: {batch.batch_id}")

        return cleaned

    def clear(self) -> None:
        """Clear all tracking data"""
        self._change_detector.clear()
        self._stats = IncrementalStats()
        logger.info("Cleared incremental pipeline tracking data")

    def close(self) -> None:
        """Close resources"""
        self._change_detector.close()

    def __enter__(self) -> "IncrementalPipeline":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# Factory function for convenience
def create_incremental_pipeline(
    llm_client: "BaseLLMClient",
    vector_store,
    config: Optional[IncrementalConfig] = None,
    db_path: str = ".audit_cache/file_index.db",
) -> IncrementalPipeline:
    """Create an incremental indexing pipeline

    Args:
        llm_client: LLM client for embedding generation
        vector_store: Vector store for persistence
        config: Optional configuration (uses defaults if not provided)
        db_path: Database path for file change tracking

    Returns:
        Configured IncrementalPipeline instance
    """
    config = config or IncrementalConfig()
    return IncrementalPipeline(
        config=config,
        llm_client=llm_client,
        vector_store=vector_store,
        db_path=db_path,
    )

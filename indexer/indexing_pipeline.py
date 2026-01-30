# Indexing Pipeline - 6-Stage Batch Processing
# Based on ACI's IndexingService design
#
# Pipeline Stages:
# 1. Scan - Collect files matching patterns
# 2. Parse - Extract code units from files (parallel)
# 3. Chunk - Split large units into token-limited chunks
# 4. Embed - Generate embedding vectors (batch with rate limiting)
# 5. Store - Persist to vector database
# 6. Metadata - Update file tracking and statistics
#
# Features:
# - Stage-by-stage progress tracking
# - Graceful error handling with partial success
# - Memory-efficient batch processing
# - Async/sync dual mode support

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Callable, Dict, Any, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from llm_client import BaseLLMClient

from .models import CodeUnit, CodeSpan
from .parallel_worker import ParallelFileProcessor

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    """Configuration for indexing pipeline

    Attributes:
        max_workers: Maximum parallel workers for file parsing
        chunk_size: Maximum token size per chunk
        embedding_batch_size: Batch size for embedding API calls
        storage_batch_size: Batch size for vector store upserts
        enable_parallel: Enable ProcessPoolExecutor for parsing
        parallel_threshold: Minimum files to trigger parallel mode
        progress_interval: Progress logging interval in seconds
    """
    max_workers: int = 4
    chunk_size: int = 2000
    embedding_batch_size: int = 150
    storage_batch_size: int = 100
    enable_parallel: bool = True
    parallel_threshold: int = 20
    progress_interval: float = 2.0


@dataclass
class PipelineStats:
    """Statistics for pipeline execution"""
    # Stage timings (seconds)
    scan_time: float = 0.0
    parse_time: float = 0.0
    chunk_time: float = 0.0
    embed_time: float = 0.0
    store_time: float = 0.0
    metadata_time: float = 0.0
    total_time: float = 0.0

    # Counts
    files_scanned: int = 0
    files_parsed: int = 0
    files_failed: int = 0
    units_extracted: int = 0
    chunks_created: int = 0
    embeddings_generated: int = 0
    vectors_stored: int = 0

    # Rates
    files_per_second: float = 0.0
    chunks_per_second: float = 0.0
    embeddings_per_second: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "timings": {
                "scan": round(self.scan_time, 3),
                "parse": round(self.parse_time, 3),
                "chunk": round(self.chunk_time, 3),
                "embed": round(self.embed_time, 3),
                "store": round(self.store_time, 3),
                "metadata": round(self.metadata_time, 3),
                "total": round(self.total_time, 3),
            },
            "counts": {
                "files_scanned": self.files_scanned,
                "files_parsed": self.files_parsed,
                "files_failed": self.files_failed,
                "units_extracted": self.units_extracted,
                "chunks_created": self.chunks_created,
                "embeddings_generated": self.embeddings_generated,
                "vectors_stored": self.vectors_stored,
            },
            "rates": {
                "files_per_second": round(self.files_per_second, 2),
                "chunks_per_second": round(self.chunks_per_second, 2),
                "embeddings_per_second": round(self.embeddings_per_second, 2),
            },
        }


@dataclass
class StageProgress:
    """Progress information for a pipeline stage"""
    stage: str
    current: int
    total: int
    message: str
    elapsed_seconds: float = 0.0

    @property
    def percent(self) -> int:
        if self.total == 0:
            return 0
        return min(100, int((self.current / self.total) * 100))


# Type alias for progress callback
ProgressCallback = Callable[[StageProgress], None]


class IndexingPipeline:
    """6-Stage Batch Indexing Pipeline

    Coordinates the complete indexing workflow with stage-by-stage
    progress tracking and efficient batch processing.

    Based on ACI's IndexingService architecture with enhancements
    for security-focused code analysis.

    Stages:
    1. SCAN: Collect files matching include/exclude patterns
    2. PARSE: Extract CodeUnits from files (parallel processing)
    3. CHUNK: Split large units into token-limited chunks
    4. EMBED: Generate embedding vectors (batched API calls)
    5. STORE: Persist embeddings to vector database
    6. METADATA: Update file tracking and statistics

    Example:
        pipeline = IndexingPipeline(config, llm_client, vector_store)
        stats = await pipeline.run(root_path, progress_callback)
    """

    STAGE_SCAN = "scan"
    STAGE_PARSE = "parse"
    STAGE_CHUNK = "chunk"
    STAGE_EMBED = "embed"
    STAGE_STORE = "store"
    STAGE_METADATA = "metadata"

    def __init__(
        self,
        config: PipelineConfig,
        llm_client: "BaseLLMClient",
        vector_store,
        file_scanner: Optional[Callable[[Path], List[Path]]] = None,
        file_tracker=None,
        embedding_cache=None,
    ):
        """Initialize indexing pipeline

        Args:
            config: Pipeline configuration
            llm_client: LLM client for embedding generation
            vector_store: Vector store for persistence
            file_scanner: Optional custom file scanner function
            file_tracker: Optional file change tracker
            embedding_cache: Optional embedding cache
        """
        self.config = config
        self.llm_client = llm_client
        self.vector_store = vector_store
        self._file_scanner = file_scanner
        self._file_tracker = file_tracker
        self._embedding_cache = embedding_cache

        # Parallel processor for CPU-intensive parsing
        self._parallel_processor = ParallelFileProcessor(
            max_workers=config.max_workers,
            batch_size=10,
            worker_config={"chunk_size": config.chunk_size},
        )

        # Chunk mapping for reconstruction
        self._chunk_parent_map: Dict[str, str] = {}
        self._chunk_siblings: Dict[str, List[str]] = {}

        # Statistics
        self._stats = PipelineStats()
        self._progress_callback: Optional[ProgressCallback] = None
        self._last_progress_time = 0.0

    def run_sync(
        self,
        root_path: Path,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> PipelineStats:
        """Run pipeline synchronously

        Args:
            root_path: Root directory to index
            progress_callback: Optional progress callback

        Returns:
            Pipeline execution statistics
        """
        import asyncio

        # Use existing event loop or create new one
        try:
            loop = asyncio.get_running_loop()
            # Already in async context, use to_thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(
                    asyncio.run,
                    self.run(root_path, progress_callback)
                )
                return future.result()
        except RuntimeError:
            # No running loop, create one
            return asyncio.run(self.run(root_path, progress_callback))

    async def run(
        self,
        root_path: Path,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> PipelineStats:
        """Run the complete indexing pipeline

        Args:
            root_path: Root directory to index
            progress_callback: Optional callback for progress updates

        Returns:
            Pipeline execution statistics
        """
        self._progress_callback = progress_callback
        self._stats = PipelineStats()
        start_time = time.time()

        logger.info(f"[Pipeline] Starting 6-stage indexing: {root_path}")

        try:
            # Stage 1: Scan files
            files = await self._stage_scan(root_path)
            if not files:
                logger.info("[Pipeline] No files to index")
                return self._stats

            # Stage 2: Parse files
            units = await self._stage_parse(files, root_path)
            if not units:
                logger.warning("[Pipeline] No code units extracted")
                return self._stats

            # Stage 3: Chunk units
            chunks = await self._stage_chunk(units)

            # Stage 4: Generate embeddings
            embeddings = await self._stage_embed(chunks)

            # Stage 5: Store vectors
            await self._stage_store(chunks, embeddings)

            # Stage 6: Update metadata
            await self._stage_metadata(files, chunks)

        except Exception as e:
            logger.error(f"[Pipeline] Failed: {e}")
            raise

        finally:
            self._stats.total_time = time.time() - start_time
            self._calculate_rates()
            logger.info(
                f"[Pipeline] Complete in {self._stats.total_time:.2f}s: "
                f"{self._stats.files_parsed} files, "
                f"{self._stats.chunks_created} chunks, "
                f"{self._stats.vectors_stored} vectors"
            )

        return self._stats

    async def _stage_scan(self, root_path: Path) -> List[Path]:
        """Stage 1: Scan directory for files

        Args:
            root_path: Root directory

        Returns:
            List of file paths to process
        """
        self._report_progress(self.STAGE_SCAN, 0, 0, "Scanning files...")
        start = time.time()

        if self._file_scanner:
            files = self._file_scanner(root_path)
        else:
            # Default: collect all files (caller should filter)
            files = [f for f in root_path.rglob("*") if f.is_file()]

        self._stats.scan_time = time.time() - start
        self._stats.files_scanned = len(files)

        self._report_progress(
            self.STAGE_SCAN, len(files), len(files),
            f"Found {len(files)} files"
        )
        logger.info(f"[Stage 1/6] Scan: {len(files)} files in {self._stats.scan_time:.2f}s")

        return files

    async def _stage_parse(
        self,
        files: List[Path],
        root_path: Path
    ) -> List[CodeUnit]:
        """Stage 2: Parse files to extract code units

        Args:
            files: List of files to parse
            root_path: Root directory for relative paths

        Returns:
            List of extracted CodeUnits
        """
        self._report_progress(self.STAGE_PARSE, 0, len(files), "Parsing files...")
        start = time.time()

        total = len(files)
        use_parallel = (
            self.config.enable_parallel and
            total >= self.config.parallel_threshold
        )

        def parse_progress(current: int, total: int):
            self._report_progress(
                self.STAGE_PARSE, current, total,
                f"Parsing {current}/{total} files"
            )

        if use_parallel:
            logger.info(f"[Stage 2/6] Using parallel parsing for {total} files")
            units, failed = self._parallel_processor.process_files(
                files, root_path, parse_progress
            )
            self._stats.files_failed = len(failed)
        else:
            logger.info(f"[Stage 2/6] Using sequential parsing for {total} files")
            units, failed = await self._parse_sequential(files, root_path, parse_progress)
            self._stats.files_failed = len(failed)

        self._stats.parse_time = time.time() - start
        self._stats.files_parsed = total - self._stats.files_failed
        self._stats.units_extracted = len(units)

        self._report_progress(
            self.STAGE_PARSE, total, total,
            f"Extracted {len(units)} units from {self._stats.files_parsed} files"
        )
        logger.info(
            f"[Stage 2/6] Parse: {len(units)} units from {self._stats.files_parsed} files "
            f"in {self._stats.parse_time:.2f}s (failed: {self._stats.files_failed})"
        )

        return units

    async def _parse_sequential(
        self,
        files: List[Path],
        root_path: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Tuple[List[CodeUnit], List[str]]:
        """Parse files sequentially (fallback)"""
        from .parser import get_parser_for_file

        units = []
        failed = []

        for i, file_path in enumerate(files):
            try:
                parser = get_parser_for_file(str(file_path))
                if not parser:
                    continue

                content = file_path.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(root_path)).replace("\\", "/")
                file_units = parser.parse_file(rel_path, content)
                units.extend(file_units)

            except Exception as e:
                failed.append(str(file_path))
                logger.debug(f"Failed to parse {file_path}: {e}")

            if progress_callback and (i + 1) % 10 == 0:
                progress_callback(i + 1, len(files))

        return units, failed

    async def _stage_chunk(self, units: List[CodeUnit]) -> List[CodeUnit]:
        """Stage 3: Split large units into chunks

        Args:
            units: List of code units

        Returns:
            List of chunked code units
        """
        self._report_progress(self.STAGE_CHUNK, 0, len(units), "Chunking code units...")
        start = time.time()

        chunks = self._chunk_units(units, self.config.chunk_size)

        self._stats.chunk_time = time.time() - start
        self._stats.chunks_created = len(chunks)

        self._report_progress(
            self.STAGE_CHUNK, len(units), len(units),
            f"Created {len(chunks)} chunks from {len(units)} units"
        )
        logger.info(
            f"[Stage 3/6] Chunk: {len(units)} units -> {len(chunks)} chunks "
            f"in {self._stats.chunk_time:.2f}s"
        )

        return chunks

    async def _stage_embed(self, chunks: List[CodeUnit]) -> List[List[float]]:
        """Stage 4: Generate embeddings for chunks

        Args:
            chunks: List of chunked code units

        Returns:
            List of embedding vectors
        """
        self._report_progress(self.STAGE_EMBED, 0, len(chunks), "Generating embeddings...")
        start = time.time()

        texts = [chunk.to_embedding_text() for chunk in chunks]
        total = len(texts)

        # Check embedding cache first
        if self._embedding_cache:
            embeddings = await self._embed_with_cache(texts)
        else:
            embeddings = await self._embed_batch(texts)

        self._stats.embed_time = time.time() - start
        self._stats.embeddings_generated = len(embeddings)

        self._report_progress(
            self.STAGE_EMBED, total, total,
            f"Generated {len(embeddings)} embeddings"
        )
        logger.info(
            f"[Stage 4/6] Embed: {len(embeddings)} vectors "
            f"in {self._stats.embed_time:.2f}s"
        )

        return embeddings

    async def _embed_with_cache(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings with cache lookup"""
        import hashlib

        total = len(texts)
        embeddings = [None] * total
        uncached_indices = []
        uncached_texts = []

        # Check cache
        for i, text in enumerate(texts):
            content_hash = hashlib.sha256(text.encode()).hexdigest()
            cached = self._embedding_cache.get(content_hash)
            if cached is not None:
                embeddings[i] = cached
            else:
                uncached_indices.append(i)
                uncached_texts.append(text)

        logger.debug(f"Cache hit: {total - len(uncached_indices)}/{total}")

        # Generate uncached embeddings
        if uncached_texts:
            new_embeddings = await self._embed_batch(uncached_texts)
            for idx, emb in zip(uncached_indices, new_embeddings):
                embeddings[idx] = emb
                # Store in cache
                content_hash = hashlib.sha256(texts[idx].encode()).hexdigest()
                self._embedding_cache.set(content_hash, emb)

        return embeddings

    async def _embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings in batches"""
        total = len(texts)
        batch_size = self.config.embedding_batch_size
        all_embeddings = []

        for i in range(0, total, batch_size):
            batch = texts[i:i + batch_size]

            try:
                # Use LLM client's embed method
                response = await asyncio.to_thread(
                    self.llm_client.embed, batch
                )
                all_embeddings.extend(response.embeddings)
            except Exception as e:
                logger.error(f"Embedding batch failed: {e}")
                # Fill with zero vectors to maintain alignment
                dim = getattr(self.llm_client, 'embedding_dim', 1536)
                all_embeddings.extend([[0.0] * dim] * len(batch))

            # Progress update
            self._report_progress(
                self.STAGE_EMBED,
                min(i + batch_size, total),
                total,
                f"Embedding {min(i + batch_size, total)}/{total}"
            )

        return all_embeddings

    async def _stage_store(
        self,
        chunks: List[CodeUnit],
        embeddings: List[List[float]]
    ) -> None:
        """Stage 5: Store vectors in database

        Args:
            chunks: List of code chunks
            embeddings: List of embedding vectors
        """
        total = len(chunks)
        self._report_progress(self.STAGE_STORE, 0, total, "Storing vectors...")
        start = time.time()

        batch_size = self.config.storage_batch_size

        for i in range(0, total, batch_size):
            batch_chunks = chunks[i:i + batch_size]
            batch_embeddings = embeddings[i:i + batch_size]

            try:
                await asyncio.to_thread(
                    self.vector_store.add,
                    batch_chunks,
                    batch_embeddings
                )
            except Exception as e:
                logger.error(f"Storage batch failed: {e}")

            self._report_progress(
                self.STAGE_STORE,
                min(i + batch_size, total),
                total,
                f"Stored {min(i + batch_size, total)}/{total}"
            )

        self._stats.store_time = time.time() - start
        self._stats.vectors_stored = total

        self._report_progress(
            self.STAGE_STORE, total, total,
            f"Stored {total} vectors"
        )
        logger.info(
            f"[Stage 5/6] Store: {total} vectors "
            f"in {self._stats.store_time:.2f}s"
        )

    async def _stage_metadata(
        self,
        files: List[Path],
        chunks: List[CodeUnit]
    ) -> None:
        """Stage 6: Update metadata and file tracking

        Args:
            files: Processed files
            chunks: Created chunks
        """
        self._report_progress(self.STAGE_METADATA, 0, 1, "Updating metadata...")
        start = time.time()

        if self._file_tracker:
            # Update file tracker with processed files
            for file_path in files:
                try:
                    path_str = str(file_path)
                    mtime = file_path.stat().st_mtime

                    # Get chunks for this file
                    file_chunks = [c for c in chunks if c.file_path in path_str]
                    chunk_ids = [c.id for c in file_chunks]

                    # Compute content hash
                    import hashlib
                    content = file_path.read_bytes()
                    content_hash = hashlib.sha256(content).hexdigest()

                    self._file_tracker.update_file_state(
                        path_str, mtime, content_hash, chunk_ids
                    )
                except Exception as e:
                    logger.debug(f"Failed to update metadata for {file_path}: {e}")

        self._stats.metadata_time = time.time() - start

        self._report_progress(
            self.STAGE_METADATA, 1, 1,
            "Metadata updated"
        )
        logger.info(f"[Stage 6/6] Metadata: updated in {self._stats.metadata_time:.2f}s")

    def _chunk_units(
        self,
        units: List[CodeUnit],
        max_tokens: int = 2000
    ) -> List[CodeUnit]:
        """Split large code units into chunks

        Args:
            units: List of code units
            max_tokens: Maximum tokens per chunk

        Returns:
            List of chunked units
        """
        result = []

        for unit in units:
            # Estimate tokens (0.3 tokens per character for code)
            estimated_tokens = len(unit.code) * 0.3

            if estimated_tokens <= max_tokens:
                # No chunking needed
                unit_metadata = dict(unit.metadata) if unit.metadata else {}
                unit_metadata["artifact_type"] = "base_unit"
                updated_unit = CodeUnit(
                    id=unit.id,
                    language=unit.language,
                    file_path=unit.file_path,
                    symbol=unit.symbol,
                    unit_type=unit.unit_type,
                    signature=unit.signature,
                    span=unit.span,
                    code=unit.code,
                    docstring=unit.docstring,
                    calls=unit.calls,
                    called_by=unit.called_by,
                    parent_class=unit.parent_class,
                    decorators=unit.decorators,
                    imports=unit.imports,
                    metadata=unit_metadata,
                    chunk_index=unit.chunk_index,
                    total_chunks=unit.total_chunks,
                )
                result.append(updated_unit)
            else:
                # Chunk the unit
                chunks = self._split_unit(unit, max_tokens)
                result.extend(chunks)

        return result

    def _split_unit(
        self,
        unit: CodeUnit,
        max_tokens: int
    ) -> List[CodeUnit]:
        """Split a single unit into chunks"""
        chunk_size = int(max_tokens / 0.3)  # Characters
        lines = unit.code.split("\n")

        chunk_data = []  # (code, start_offset, end_offset)
        current_lines = []
        current_size = 0
        current_start = 0

        for line_idx, line in enumerate(lines):
            line_size = len(line) + 1
            if current_size + line_size > chunk_size and current_lines:
                chunk_data.append((
                    "\n".join(current_lines),
                    current_start,
                    line_idx - 1
                ))
                current_lines = [line]
                current_size = line_size
                current_start = line_idx
            else:
                current_lines.append(line)
                current_size += line_size

        if current_lines:
            chunk_data.append((
                "\n".join(current_lines),
                current_start,
                len(lines) - 1
            ))

        # Create chunk units
        chunks = []
        total_chunks = len(chunk_data)
        chunk_ids = []

        for i, (chunk_code, start_offset, end_offset) in enumerate(chunk_data):
            chunk_id = f"{unit.id}_chunk{i}"
            chunk_ids.append(chunk_id)
            self._chunk_parent_map[chunk_id] = unit.id

            # Calculate span
            orig_start = unit.span.start_line if unit.span else 1
            chunk_span = CodeSpan(
                start_line=orig_start + start_offset,
                end_line=orig_start + end_offset,
                start_col=0,
                end_col=0,
            )

            chunk_metadata = dict(unit.metadata) if unit.metadata else {}
            chunk_metadata.update({
                "artifact_type": "chunk_unit",
                "parent_id": unit.id,
                "chunk_start_offset": start_offset,
                "chunk_end_offset": end_offset,
            })

            chunked_unit = CodeUnit(
                id=chunk_id,
                language=unit.language,
                file_path=unit.file_path,
                symbol=unit.symbol,
                unit_type=unit.unit_type,
                signature=unit.signature,
                span=chunk_span,
                code=chunk_code,
                docstring=unit.docstring if i == 0 else None,
                calls=unit.calls,
                called_by=unit.called_by,
                parent_class=unit.parent_class,
                decorators=unit.decorators if i == 0 else [],
                imports=unit.imports,
                metadata=chunk_metadata,
                chunk_index=i,
                total_chunks=total_chunks,
            )
            chunks.append(chunked_unit)

        self._chunk_siblings[unit.id] = chunk_ids

        return chunks

    def _report_progress(
        self,
        stage: str,
        current: int,
        total: int,
        message: str
    ) -> None:
        """Report progress to callback with rate limiting"""
        now = time.time()

        # Rate limit progress updates
        if (now - self._last_progress_time) < self.config.progress_interval:
            if current < total:  # Always report completion
                return

        self._last_progress_time = now

        if self._progress_callback:
            progress = StageProgress(
                stage=stage,
                current=current,
                total=total,
                message=message,
                elapsed_seconds=now - (getattr(self, '_stage_start', now)),
            )
            try:
                self._progress_callback(progress)
            except Exception as e:
                logger.debug(f"Progress callback failed: {e}")

    def _calculate_rates(self) -> None:
        """Calculate processing rates"""
        if self._stats.parse_time > 0:
            self._stats.files_per_second = (
                self._stats.files_parsed / self._stats.parse_time
            )
        if self._stats.chunk_time > 0:
            self._stats.chunks_per_second = (
                self._stats.chunks_created / self._stats.chunk_time
            )
        if self._stats.embed_time > 0:
            self._stats.embeddings_per_second = (
                self._stats.embeddings_generated / self._stats.embed_time
            )

    @property
    def stats(self) -> PipelineStats:
        """Get current statistics"""
        return self._stats

    def get_chunk_mapping(self) -> Dict[str, str]:
        """Get chunk to parent mapping"""
        return self._chunk_parent_map.copy()

    def get_chunk_siblings(self) -> Dict[str, List[str]]:
        """Get parent to chunks mapping"""
        return self._chunk_siblings.copy()

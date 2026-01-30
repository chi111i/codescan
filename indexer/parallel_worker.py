# Parallel Worker for Code Indexing
# Based on ACI's indexing_worker.py design
#
# Features:
# - ProcessPoolExecutor worker functions for CPU-intensive tasks
# - Global parser instances per worker (avoid repeated initialization)
# - Serializable results for cross-process communication
# - Error handling with graceful fallback

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Global variables for worker processes (initialized once per worker)
_worker_parsers: Dict[str, Any] = {}
_worker_initialized: bool = False
_worker_config: Dict[str, Any] = {}


def init_worker(config: Optional[Dict[str, Any]] = None) -> None:
    """Initialize worker process with parsers.

    This runs once per worker process to avoid repeatedly creating
    parser instances. Parsers are created lazily on first use per language.

    Args:
        config: Optional configuration dict with:
            - chunk_size: Maximum chunk size in tokens
            - languages: List of languages to pre-initialize parsers for
    """
    global _worker_parsers, _worker_initialized, _worker_config

    _worker_config = config or {}
    _worker_initialized = True

    # Pre-initialize parsers for common languages if specified
    languages = _worker_config.get("languages", [])
    if languages:
        from indexer.parser import get_parser
        for lang in languages:
            try:
                parser = get_parser(lang)
                if parser:
                    _worker_parsers[lang] = parser
            except Exception as e:
                logger.debug(f"Failed to pre-initialize parser for {lang}: {e}")


def _get_parser(language: str):
    """Get or create parser for language (lazy initialization).

    Args:
        language: Programming language

    Returns:
        Parser instance or None if not supported
    """
    global _worker_parsers

    if language in _worker_parsers:
        return _worker_parsers[language]

    try:
        from indexer.parser import get_parser
        parser = get_parser(language)
        if parser:
            _worker_parsers[language] = parser
        return parser
    except Exception as e:
        logger.debug(f"Failed to get parser for {language}: {e}")
        return None


def parse_file_worker(
    file_path: str,
    root_path: str,
    content: Optional[str] = None,
) -> Tuple[str, List[Dict[str, Any]], str, Optional[str]]:
    """Worker function for parallel file parsing.

    This function runs in a separate process to handle CPU-intensive
    AST parsing operations. Uses global parser instances initialized
    by init_worker.

    Args:
        file_path: Absolute path to the file
        root_path: Root directory path for relative path calculation
        content: Optional pre-read file content (if None, reads from disk)

    Returns:
        Tuple of (file_path, units_data, language, error)
        where units_data is a list of serializable unit dictionaries
    """
    try:
        file_path_obj = Path(file_path)
        root_path_obj = Path(root_path)

        # Read content if not provided
        if content is None:
            try:
                content = file_path_obj.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                return (file_path, [], "", f"Failed to read file: {e}")

        # Get parser for file
        from indexer.parser import get_parser_for_file
        parser = get_parser_for_file(file_path)

        if not parser:
            return (file_path, [], "", None)  # No parser available, not an error

        # Calculate relative path
        try:
            rel_path = str(file_path_obj.relative_to(root_path_obj)).replace("\\", "/")
        except ValueError:
            rel_path = file_path_obj.name

        # Parse file
        units = parser.parse_file(rel_path, content)

        # Convert CodeUnit objects to serializable dictionaries
        units_data = []
        for unit in units:
            unit_dict = {
                "id": unit.id,
                "language": unit.language,
                "file_path": unit.file_path,
                "symbol": unit.symbol,
                "unit_type": unit.unit_type.value if hasattr(unit.unit_type, 'value') else str(unit.unit_type),
                "signature": unit.signature,
                "code": unit.code,
                "docstring": unit.docstring,
                "calls": list(unit.calls) if unit.calls else [],
                "called_by": list(unit.called_by) if unit.called_by else [],
                "parent_class": unit.parent_class,
                "decorators": list(unit.decorators) if unit.decorators else [],
                "imports": list(unit.imports) if unit.imports else [],
                "metadata": dict(unit.metadata) if unit.metadata else {},
                "chunk_index": unit.chunk_index,
                "total_chunks": unit.total_chunks,
            }

            # Handle span (can be CodeSpan object or tuple)
            if unit.span:
                if hasattr(unit.span, 'start_line'):
                    unit_dict["span"] = {
                        "start_line": unit.span.start_line,
                        "end_line": unit.span.end_line,
                        "start_col": getattr(unit.span, 'start_col', 0),
                        "end_col": getattr(unit.span, 'end_col', 0),
                    }
                elif isinstance(unit.span, tuple):
                    unit_dict["span"] = {
                        "start_line": unit.span[0] if len(unit.span) > 0 else 1,
                        "end_line": unit.span[1] if len(unit.span) > 1 else 1,
                        "start_col": unit.span[2] if len(unit.span) > 2 else 0,
                        "end_col": unit.span[3] if len(unit.span) > 3 else 0,
                    }
                else:
                    unit_dict["span"] = None
            else:
                unit_dict["span"] = None

            units_data.append(unit_dict)

        language = units[0].language if units else ""

        return (file_path, units_data, language, None)

    except Exception as e:
        logger.error(f"Error parsing {file_path}: {e}")
        return (file_path, [], "", str(e))


def reconstruct_code_unit(unit_dict: Dict[str, Any]) -> 'CodeUnit':
    """Reconstruct CodeUnit from serializable dictionary.

    Args:
        unit_dict: Dictionary representation of CodeUnit

    Returns:
        CodeUnit object
    """
    from indexer.models import CodeUnit, CodeSpan, CodeUnitType

    # Reconstruct span
    span = None
    if unit_dict.get("span"):
        span_data = unit_dict["span"]
        span = CodeSpan(
            start_line=span_data.get("start_line", 1),
            end_line=span_data.get("end_line", 1),
            start_col=span_data.get("start_col", 0),
            end_col=span_data.get("end_col", 0),
        )

    # Reconstruct unit_type
    unit_type_value = unit_dict.get("unit_type", "function")
    try:
        unit_type = CodeUnitType(unit_type_value)
    except (ValueError, KeyError):
        unit_type = CodeUnitType.FUNCTION

    return CodeUnit(
        id=unit_dict["id"],
        language=unit_dict["language"],
        file_path=unit_dict["file_path"],
        symbol=unit_dict["symbol"],
        unit_type=unit_type,
        signature=unit_dict.get("signature"),
        span=span,
        code=unit_dict["code"],
        docstring=unit_dict.get("docstring"),
        calls=set(unit_dict.get("calls", [])),
        called_by=set(unit_dict.get("called_by", [])),
        parent_class=unit_dict.get("parent_class"),
        decorators=unit_dict.get("decorators", []),
        imports=unit_dict.get("imports", []),
        metadata=unit_dict.get("metadata", {}),
        chunk_index=unit_dict.get("chunk_index"),
        total_chunks=unit_dict.get("total_chunks"),
    )


def batch_parse_files_worker(
    file_batch: List[Tuple[str, str]],
) -> List[Tuple[str, List[Dict[str, Any]], str, Optional[str]]]:
    """Worker function for batch file parsing.

    Processes multiple files in a single worker call to reduce
    inter-process communication overhead.

    Args:
        file_batch: List of (file_path, root_path) tuples

    Returns:
        List of parse results
    """
    results = []
    for file_path, root_path in file_batch:
        result = parse_file_worker(file_path, root_path)
        results.append(result)
    return results


class ParallelFileProcessor:
    """Parallel file processor using ProcessPoolExecutor.

    Based on ACI's IndexingService design for efficient parallel
    processing of CPU-intensive file parsing operations.

    Features:
    - ProcessPoolExecutor for true parallelism (bypass GIL)
    - Worker initialization to avoid repeated parser creation
    - Batch processing to reduce IPC overhead
    - Graceful fallback to sequential processing on errors
    """

    def __init__(
        self,
        max_workers: int = 4,
        batch_size: int = 10,
        worker_config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize parallel processor.

        Args:
            max_workers: Maximum number of parallel workers
            batch_size: Number of files per batch for batch processing
            worker_config: Configuration passed to worker init
        """
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.worker_config = worker_config or {}

    def process_files(
        self,
        files: List[Path],
        root_path: Path,
        progress_callback: Optional[callable] = None,
    ) -> Tuple[List['CodeUnit'], List[str]]:
        """Process files in parallel.

        Args:
            files: List of file paths to process
            root_path: Root directory for relative path calculation
            progress_callback: Optional callback(current, total) for progress

        Returns:
            Tuple of (list of CodeUnits, list of failed file paths)
        """
        from concurrent.futures import ProcessPoolExecutor, as_completed
        import multiprocessing

        total_files = len(files)
        if total_files == 0:
            return [], []

        all_units = []
        failed_files = []

        # Use sequential processing for small batches or single file
        if total_files <= 2 or self.max_workers <= 1:
            return self._process_sequential(files, root_path, progress_callback)

        # Determine optimal worker count
        effective_workers = min(self.max_workers, total_files, multiprocessing.cpu_count())

        try:
            # Get multiprocessing context (avoid fork issues on some platforms)
            mp_context = self._get_mp_context()

            executor_kwargs = {
                "max_workers": effective_workers,
                "initializer": init_worker,
                "initargs": (self.worker_config,),
            }
            if mp_context is not None:
                executor_kwargs["mp_context"] = mp_context

            with ProcessPoolExecutor(**executor_kwargs) as executor:
                # Submit all tasks
                futures = {}
                for file_path in files:
                    future = executor.submit(
                        parse_file_worker,
                        str(file_path),
                        str(root_path),
                    )
                    futures[future] = file_path

                # Collect results
                processed = 0
                for future in as_completed(futures):
                    file_path = futures[future]
                    try:
                        result_path, units_data, language, error = future.result()

                        if error:
                            failed_files.append(result_path)
                            logger.warning(f"Failed to parse {result_path}: {error}")
                        else:
                            # Reconstruct CodeUnit objects
                            for unit_dict in units_data:
                                try:
                                    unit = reconstruct_code_unit(unit_dict)
                                    all_units.append(unit)
                                except Exception as e:
                                    logger.warning(f"Failed to reconstruct unit: {e}")

                    except Exception as e:
                        failed_files.append(str(file_path))
                        logger.error(f"Worker failed for {file_path}: {e}")

                    processed += 1
                    if progress_callback and (processed % 10 == 0 or processed == total_files):
                        progress_callback(processed, total_files)

        except Exception as e:
            logger.warning(f"ProcessPoolExecutor failed ({e}), falling back to sequential")
            return self._process_sequential(files, root_path, progress_callback)

        return all_units, failed_files

    def _process_sequential(
        self,
        files: List[Path],
        root_path: Path,
        progress_callback: Optional[callable] = None,
    ) -> Tuple[List['CodeUnit'], List[str]]:
        """Process files sequentially (fallback).

        Args:
            files: List of file paths
            root_path: Root directory
            progress_callback: Optional progress callback

        Returns:
            Tuple of (units, failed_files)
        """
        all_units = []
        failed_files = []
        total = len(files)

        for i, file_path in enumerate(files):
            try:
                result_path, units_data, language, error = parse_file_worker(
                    str(file_path), str(root_path)
                )

                if error:
                    failed_files.append(result_path)
                else:
                    for unit_dict in units_data:
                        try:
                            unit = reconstruct_code_unit(unit_dict)
                            all_units.append(unit)
                        except Exception as e:
                            logger.warning(f"Failed to reconstruct unit: {e}")

            except Exception as e:
                failed_files.append(str(file_path))
                logger.error(f"Failed to process {file_path}: {e}")

            if progress_callback and ((i + 1) % 10 == 0 or i + 1 == total):
                progress_callback(i + 1, total)

        return all_units, failed_files

    def _get_mp_context(self):
        """Get multiprocessing context.

        Chooses a safe start method when multiple threads are active
        (fork can cause deadlocks in multi-threaded processes).

        Returns:
            multiprocessing context or None for default
        """
        import os
        import threading
        import multiprocessing

        # Check for environment override
        forced_method = os.environ.get("CODESCAN_PROCESS_START_METHOD")
        if forced_method:
            try:
                return multiprocessing.get_context(forced_method)
            except ValueError:
                logger.warning(f"Invalid start method: {forced_method}")
                return None

        # On Windows, spawn is default and safest
        if os.name == 'nt':
            return None

        # On Unix, check if fork is problematic
        try:
            start_method = multiprocessing.get_start_method(allow_none=True)
        except TypeError:
            start_method = multiprocessing.get_start_method()

        if start_method != "fork":
            return None

        # Fork is problematic with multiple threads
        if threading.active_count() <= 1:
            return None

        # Try safer methods
        for candidate in ("forkserver", "spawn"):
            try:
                return multiprocessing.get_context(candidate)
            except ValueError:
                continue

        return None


# Convenience function for async processing
async def process_files_async(
    files: List[Path],
    root_path: Path,
    max_workers: int = 4,
    progress_callback: Optional[callable] = None,
) -> Tuple[List['CodeUnit'], List[str]]:
    """Process files in parallel (async wrapper).

    Args:
        files: List of file paths
        root_path: Root directory
        max_workers: Number of parallel workers
        progress_callback: Optional progress callback

    Returns:
        Tuple of (units, failed_files)
    """
    import asyncio

    processor = ParallelFileProcessor(max_workers=max_workers)

    # Run in thread pool to avoid blocking event loop
    return await asyncio.to_thread(
        processor.process_files,
        files,
        root_path,
        progress_callback,
    )

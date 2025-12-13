"""
通用工具函数和异常定义
"""

import hashlib
import re
import logging
from pathlib import Path
from typing import Optional, List, Any, Callable, TypeVar
from functools import wraps
import time

logger = logging.getLogger(__name__)

T = TypeVar('T')


# ============ 自定义异常 ============

class AuditError(Exception):
    """审计工具基础异常"""
    pass


class ConfigError(AuditError):
    """配置相关异常"""
    pass


class IndexingError(AuditError):
    """索引相关异常"""
    pass


class AnalysisError(AuditError):
    """分析相关异常"""
    pass


class LLMError(AuditError):
    """LLM 调用相关异常"""
    pass


class VectorStoreError(AuditError):
    """向量存储相关异常"""
    pass


# ============ 重试装饰器 ============

def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
    on_retry: Optional[Callable[[Exception, int], None]] = None,
):
    """重试装饰器

    Args:
        max_attempts: 最大尝试次数
        delay: 初始延迟（秒）
        backoff: 退避因子
        exceptions: 需要重试的异常类型
        on_retry: 重试时的回调函数
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts:
                        if on_retry:
                            on_retry(e, attempt)
                        else:
                            logger.warning(
                                f"{func.__name__} 失败 (尝试 {attempt}/{max_attempts}): {e}"
                            )
                        time.sleep(current_delay)
                        current_delay *= backoff

            raise last_exception

        return wrapper
    return decorator


# ============ 文本处理工具 ============

def truncate_text(text: str, max_length: int, suffix: str = "...") -> str:
    """截断文本到指定长度"""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def estimate_tokens(text: str) -> int:
    """估算文本的 token 数量

    粗略估算：
    - 英文约 4 字符/token
    - 中文约 1.5 字符/token
    """
    # 统计中文字符
    chinese_chars = len(re.findall(r'[\u4e00-\u9fff]', text))
    other_chars = len(text) - chinese_chars

    return int(chinese_chars / 1.5 + other_chars / 4)


def chunk_text(
    text: str,
    max_tokens: int,
    overlap_tokens: int = 100,
) -> List[str]:
    """将文本分割成多个块

    Args:
        text: 原始文本
        max_tokens: 每块最大 token 数
        overlap_tokens: 块之间的重叠 token 数

    Returns:
        文本块列表
    """
    if estimate_tokens(text) <= max_tokens:
        return [text]

    chunks = []
    lines = text.split('\n')
    current_chunk = []
    current_tokens = 0

    for line in lines:
        line_tokens = estimate_tokens(line)

        if current_tokens + line_tokens > max_tokens:
            if current_chunk:
                chunks.append('\n'.join(current_chunk))

                # 保留部分内容作为重叠
                overlap_content = []
                overlap_count = 0
                for prev_line in reversed(current_chunk):
                    line_tok = estimate_tokens(prev_line)
                    if overlap_count + line_tok > overlap_tokens:
                        break
                    overlap_content.insert(0, prev_line)
                    overlap_count += line_tok

                current_chunk = overlap_content
                current_tokens = overlap_count

        current_chunk.append(line)
        current_tokens += line_tokens

    if current_chunk:
        chunks.append('\n'.join(current_chunk))

    return chunks


def sanitize_filename(name: str) -> str:
    """清理文件名，移除不安全字符"""
    # 移除或替换不安全字符
    safe_name = re.sub(r'[<>:"/\\|?*]', '_', name)
    # 移除控制字符
    safe_name = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', safe_name)
    # 限制长度
    if len(safe_name) > 200:
        safe_name = safe_name[:200]
    return safe_name


def generate_hash(content: str, length: int = 16) -> str:
    """生成内容的哈希值"""
    return hashlib.sha256(content.encode()).hexdigest()[:length]


# ============ 路径工具 ============

def normalize_path(path: str) -> str:
    """规范化路径（统一使用正斜杠）"""
    return str(Path(path)).replace('\\', '/')


def is_subpath(child: Path, parent: Path) -> bool:
    """检查 child 是否是 parent 的子路径"""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def get_relative_path(path: Path, base: Path) -> str:
    """获取相对路径"""
    try:
        return str(path.resolve().relative_to(base.resolve())).replace('\\', '/')
    except ValueError:
        return str(path)


# ============ 代码处理工具 ============

def extract_function_name(code: str) -> Optional[str]:
    """从代码片段中提取函数名"""
    # Python
    match = re.search(r'def\s+(\w+)\s*\(', code)
    if match:
        return match.group(1)

    # JavaScript/TypeScript
    match = re.search(r'function\s+(\w+)\s*\(', code)
    if match:
        return match.group(1)

    # 箭头函数
    match = re.search(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(', code)
    if match:
        return match.group(1)

    return None


def extract_class_name(code: str) -> Optional[str]:
    """从代码片段中提取类名"""
    match = re.search(r'class\s+(\w+)', code)
    if match:
        return match.group(1)
    return None


def remove_comments(code: str, language: str) -> str:
    """移除代码中的注释"""
    if language in ('python',):
        # 移除 Python 注释
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        # 移除多行字符串（简化处理）
        code = re.sub(r'"""[\s\S]*?"""', '', code)
        code = re.sub(r"'''[\s\S]*?'''", '', code)

    elif language in ('javascript', 'typescript'):
        # 移除单行注释
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        # 移除多行注释
        code = re.sub(r'/\*[\s\S]*?\*/', '', code)

    return code


def count_lines(code: str) -> int:
    """统计代码行数（不含空行）"""
    return len([line for line in code.split('\n') if line.strip()])


# ============ 验证工具 ============

def validate_url(url: str) -> bool:
    """验证 URL 格式"""
    pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    return bool(pattern.match(url))


def validate_file_path(path: str) -> bool:
    """验证文件路径是否安全（防止路径遍历）"""
    try:
        normalized = Path(path).resolve()
        # 检查是否包含危险字符
        if '..' in path:
            return False
        return True
    except Exception:
        return False


# ============ 格式化工具 ============

def format_file_size(size_bytes: int) -> str:
    """格式化文件大小"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def format_duration(seconds: float) -> str:
    """格式化持续时间"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


# ============ 批处理工具 ============

def batch_process(
    items: List[T],
    batch_size: int,
    processor: Callable[[List[T]], Any],
    on_batch_complete: Optional[Callable[[int, int], None]] = None,
) -> List[Any]:
    """批量处理项目

    Args:
        items: 项目列表
        batch_size: 批次大小
        processor: 处理函数
        on_batch_complete: 批次完成回调

    Returns:
        处理结果列表
    """
    results = []
    total_batches = (len(items) + batch_size - 1) // batch_size

    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        result = processor(batch)
        results.append(result)

        if on_batch_complete:
            batch_num = i // batch_size + 1
            on_batch_complete(batch_num, total_batches)

    return results

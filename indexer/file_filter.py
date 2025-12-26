"""文件过滤器

支持 .auditignore 和 .gitignore 规则，智能过滤不需要审计的文件。
"""

import fnmatch
import logging
from pathlib import Path
from typing import List, Set, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FilterStats:
    """过滤统计"""
    total_files: int = 0
    filtered_files: int = 0
    filtered_by_gitignore: int = 0
    filtered_by_auditignore: int = 0
    filtered_by_size: int = 0
    filtered_by_extension: int = 0
    accepted_files: int = 0


class FileFilter:
    """文件过滤器

    支持：
    - .gitignore 规则自动读取
    - .auditignore 自定义规则
    - 文件大小过滤
    - 扩展名白名单/黑名单
    - 统计过滤日志
    """

    def __init__(
        self,
        root_path: Path,
        max_file_size_kb: int = 500,
        supported_extensions: Optional[List[str]] = None,
        auto_load_gitignore: bool = True,
        auto_load_auditignore: bool = True,
    ):
        """初始化文件过滤器

        Args:
            root_path: 项目根目录
            max_file_size_kb: 最大文件大小（KB）
            supported_extensions: 支持的文件扩展名列表（如 ['.py', '.js']）
            auto_load_gitignore: 自动加载 .gitignore
            auto_load_auditignore: 自动加载 .auditignore
        """
        self.root_path = Path(root_path).resolve()
        self.max_file_size_kb = max_file_size_kb
        self.supported_extensions = supported_extensions or []

        # 规则存储
        self.gitignore_patterns: List[str] = []
        self.auditignore_patterns: List[str] = []

        # 统计
        self.stats = FilterStats()

        # 默认忽略模式（始终生效）
        self.default_patterns = [
            ".git/",
            "__pycache__/",
            "*.pyc",
            ".DS_Store",
            "node_modules/",
            "venv/",
            ".venv/",
            "dist/",
            "build/",
            "*.egg-info/",
        ]

        # 加载规则文件
        if auto_load_gitignore:
            self._load_gitignore()
        if auto_load_auditignore:
            self._load_auditignore()

        logger.info(
            f"[FileFilter] 初始化: root={root_path}, "
            f"gitignore={len(self.gitignore_patterns)} 条, "
            f"auditignore={len(self.auditignore_patterns)} 条"
        )

    def _load_gitignore(self):
        """加载 .gitignore 文件"""
        gitignore_path = self.root_path / ".gitignore"
        if not gitignore_path.exists():
            logger.debug("[FileFilter] .gitignore 不存在")
            return

        try:
            with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.gitignore_patterns.append(line)

            logger.info(f"[FileFilter] 加载 .gitignore: {len(self.gitignore_patterns)} 条规则")
        except Exception as e:
            logger.warning(f"[FileFilter] 加载 .gitignore 失败: {e}")

    def _load_auditignore(self):
        """加载 .auditignore 文件"""
        auditignore_path = self.root_path / ".auditignore"
        if not auditignore_path.exists():
            logger.debug("[FileFilter] .auditignore 不存在，跳过")
            return

        try:
            with open(auditignore_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    # 支持 ! 取反规则
                    if line and not line.startswith("#"):
                        self.auditignore_patterns.append(line)

            logger.info(f"[FileFilter] 加载 .auditignore: {len(self.auditignore_patterns)} 条规则")
        except Exception as e:
            logger.warning(f"[FileFilter] 加载 .auditignore 失败: {e}")

    def _matches_pattern(self, rel_path: str, pattern: str) -> bool:
        """检查路径是否匹配模式

        支持：
        - 普通 glob 模式：*.py
        - 目录模式：node_modules/
        - ** 递归模式：**/test/**
        - ! 取反规则（仅 auditignore）

        Args:
            rel_path: 相对路径
            pattern: 匹配模式

        Returns:
            是否匹配
        """
        # 取反规则（! 开头）
        if pattern.startswith("!"):
            return False  # 后续单独处理

        # 目录模式（以 / 结尾）
        if pattern.endswith("/"):
            # 匹配目录本身或其下所有文件
            dir_pattern = pattern[:-1]
            if rel_path == dir_pattern or rel_path.startswith(dir_pattern + "/"):
                return True
            # 使用 Path.match() 处理目录模式
            try:
                if Path(rel_path).match(pattern):
                    return True
            except (ValueError, IndexError) as e:
                logger.debug(f"Path.match() 模式匹配出错: {pattern}, {e}")

        # ** 递归模式 - 使用 Path.match()
        if "**" in pattern:
            try:
                if Path(rel_path).match(pattern):
                    return True
            except (ValueError, IndexError) as e:
                logger.debug(f"Path.match() 递归模式匹配出错: {pattern}, {e}")
            # 回退到简化模式
            # **/*_test.py -> *_test.py 匹配文件名
            # **/tests/** -> tests/ 匹配路径包含
            simplified = pattern.replace("**/", "").replace("/**", "")
            if fnmatch.fnmatch(rel_path, simplified):
                return True
            # 检查路径的每个部分
            parts = rel_path.split("/")
            for part in parts:
                if fnmatch.fnmatch(part, simplified):
                    return True

        # 普通 glob 匹配
        if fnmatch.fnmatch(rel_path, pattern):
            return True

        # 检查路径的每个部分（用于简单模式如 *.py）
        if "*" in pattern or "?" in pattern:
            parts = rel_path.split("/")
            for part in parts:
                if fnmatch.fnmatch(part, pattern):
                    return True

        return False

    def should_ignore(self, file_path: Path) -> tuple[bool, str]:
        """判断文件是否应该忽略

        Args:
            file_path: 文件路径

        Returns:
            (should_ignore, reason)
        """
        self.stats.total_files += 1

        # 计算相对路径
        try:
            rel_path = file_path.relative_to(self.root_path)
        except ValueError:
            # 不在根目录下
            self.stats.filtered_files += 1
            return True, "不在项目根目录下"

        rel_path_str = str(rel_path).replace("\\", "/")

        # 1. 检查默认模式
        for pattern in self.default_patterns:
            if self._matches_pattern(rel_path_str, pattern):
                self.stats.filtered_files += 1
                return True, f"默认忽略规则: {pattern}"

        # 2. 检查 .gitignore
        for pattern in self.gitignore_patterns:
            if self._matches_pattern(rel_path_str, pattern):
                self.stats.filtered_files += 1
                self.stats.filtered_by_gitignore += 1
                return True, f".gitignore: {pattern}"

        # 3. 检查 .auditignore
        negation_patterns = []  # 取反规则
        for pattern in self.auditignore_patterns:
            if pattern.startswith("!"):
                negation_patterns.append(pattern[1:])
            elif self._matches_pattern(rel_path_str, pattern):
                # 检查是否有取反规则
                negated = False
                for neg_pattern in negation_patterns:
                    if self._matches_pattern(rel_path_str, neg_pattern):
                        negated = True
                        break

                if not negated:
                    self.stats.filtered_files += 1
                    self.stats.filtered_by_auditignore += 1
                    return True, f".auditignore: {pattern}"

        # 4. 检查文件大小
        if file_path.is_file():
            size_kb = file_path.stat().st_size / 1024
            if size_kb > self.max_file_size_kb:
                self.stats.filtered_files += 1
                self.stats.filtered_by_size += 1
                return True, f"文件过大: {size_kb:.1f}KB > {self.max_file_size_kb}KB"

        # 5. 检查扩展名白名单
        if self.supported_extensions:
            if not any(rel_path_str.endswith(ext) for ext in self.supported_extensions):
                self.stats.filtered_files += 1
                self.stats.filtered_by_extension += 1
                return True, f"不支持的扩展名: {file_path.suffix}"

        # 通过所有检查
        self.stats.accepted_files += 1
        return False, ""

    def filter_files(self, file_paths: List[Path], verbose: bool = False) -> List[Path]:
        """批量过滤文件

        Args:
            file_paths: 文件路径列表
            verbose: 是否输出详细日志

        Returns:
            过滤后的文件列表
        """
        accepted = []

        for file_path in file_paths:
            should_ignore, reason = self.should_ignore(file_path)

            if should_ignore:
                if verbose:
                    logger.debug(f"[FileFilter] 忽略: {file_path} ({reason})")
            else:
                accepted.append(file_path)
                if verbose:
                    logger.debug(f"[FileFilter] 接受: {file_path}")

        return accepted

    def get_stats(self) -> FilterStats:
        """获取过滤统计

        Returns:
            FilterStats 对象
        """
        return self.stats

    def reset_stats(self):
        """重置统计"""
        self.stats = FilterStats()

    def add_pattern(self, pattern: str, source: str = "auditignore"):
        """动态添加过滤规则

        Args:
            pattern: 匹配模式
            source: 规则来源 (gitignore/auditignore)
        """
        if source == "gitignore":
            self.gitignore_patterns.append(pattern)
        else:
            self.auditignore_patterns.append(pattern)

        logger.debug(f"[FileFilter] 添加规则: {pattern} (来源: {source})")


def create_default_auditignore(path: Path) -> bool:
    """创建默认的 .auditignore 文件

    Args:
        path: 项目根目录

    Returns:
        是否创建成功
    """
    auditignore_path = path / ".auditignore"

    if auditignore_path.exists():
        logger.info(f"[FileFilter] .auditignore 已存在: {auditignore_path}")
        return False

    default_content = """# CodeScan 审计忽略规则
# 语法与 .gitignore 相同，支持 ! 取反规则

# 测试文件
**/*test*.py
**/*_test.py
**/tests/**
**/*.spec.js
**/*.test.js

# 文档和配置
*.md
*.txt
*.json
*.yaml
*.yml
!audit.config.yaml
!.auditignore

# 依赖和构建产物
node_modules/
venv/
.venv/
dist/
build/
*.egg-info/

# IDE 和编辑器
.vscode/
.idea/
*.swp
*.swo

# 日志和临时文件
*.log
*.tmp
*.cache
.audit_cache/
.audit_data/

# 静态资源
*.css
*.scss
*.less
*.min.js
*.bundle.js

# 示例和模板
**/examples/**
**/templates/**
**/demo/**

# 特定文件（示例）
# config/secrets.py
# utils/deprecated.py
"""

    try:
        auditignore_path.write_text(default_content, encoding="utf-8")
        logger.info(f"[FileFilter] 创建默认 .auditignore: {auditignore_path}")
        return True
    except Exception as e:
        logger.error(f"[FileFilter] 创建 .auditignore 失败: {e}")
        return False

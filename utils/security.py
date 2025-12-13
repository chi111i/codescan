"""
安全与隐私保护模块

功能:
- 代码脱敏 (敏感信息替换)
- API Key 遮蔽
- 日志安全控制
- 敏感操作拦截
"""

import re
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple, Any, Set
from functools import wraps

logger = logging.getLogger(__name__)


@dataclass
class DesensitizationConfig:
    """脱敏配置"""
    enabled: bool = False
    patterns: List[str] = field(default_factory=list)
    replacement_prefix: str = "[REDACTED:"
    replacement_suffix: str = "]"
    preserve_length: bool = False  # 是否保留原始长度

    def __post_init__(self):
        if not self.patterns:
            self.patterns = [
                # Email
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                # SSN (美国社会安全号)
                r'\b\d{3}-\d{2}-\d{4}\b',
                # 信用卡号
                r'\b(?:\d{4}[- ]?){3}\d{4}\b',
                # 中国身份证号
                r'\b\d{17}[\dXx]\b',
                # 中国手机号
                r'\b1[3-9]\d{9}\b',
                # 密码/密钥赋值
                r'(?:password|passwd|pwd|secret|token|api_key|apikey|auth_token)\s*[=:]\s*["\']?[\w\-\.]{8,}["\']?',
                # Bearer Token
                r'Bearer\s+[A-Za-z0-9\-_\.]+',
                # AWS Access Key
                r'\bAKIA[0-9A-Z]{16}\b',
                # JWT Token
                r'\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b',
                # 私钥开始
                r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                # IP 地址 (可选)
                # r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            ]


class DataDesensitizer:
    """数据脱敏器

    用于在将代码发送给 LLM 之前移除或替换敏感信息
    """

    def __init__(self, config: Optional[DesensitizationConfig] = None):
        """初始化

        Args:
            config: 脱敏配置
        """
        self.config = config or DesensitizationConfig()
        self._compiled_patterns: List[Tuple[Pattern, str]] = []
        self._compile_patterns()

        # 脱敏映射表 (用于可逆脱敏)
        self._mapping: Dict[str, str] = {}
        self._reverse_mapping: Dict[str, str] = {}

    def _compile_patterns(self) -> None:
        """编译正则表达式模式"""
        for i, pattern in enumerate(self.config.patterns):
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                type_name = self._get_type_name(pattern)
                self._compiled_patterns.append((compiled, type_name))
            except re.error as e:
                logger.warning(f"Invalid regex pattern: {pattern}, error: {e}")

    def _get_type_name(self, pattern: str) -> str:
        """根据模式推断类型名称"""
        pattern_lower = pattern.lower()
        if 'email' in pattern_lower or '@' in pattern:
            return "EMAIL"
        elif 'password' in pattern_lower or 'passwd' in pattern_lower:
            return "PASSWORD"
        elif 'token' in pattern_lower:
            return "TOKEN"
        elif 'key' in pattern_lower:
            return "KEY"
        elif 'credit' in pattern_lower or r'\d{4}' in pattern:
            return "CARD"
        elif 'phone' in pattern_lower or r'1[3-9]' in pattern:
            return "PHONE"
        elif 'ssn' in pattern_lower or r'\d{3}-\d{2}' in pattern:
            return "SSN"
        elif 'identity' in pattern_lower or r'\d{17}' in pattern:
            return "ID"
        elif 'bearer' in pattern_lower:
            return "AUTH"
        elif 'private' in pattern_lower:
            return "PRIVATE_KEY"
        else:
            return "SENSITIVE"

    def desensitize(self, text: str, reversible: bool = False) -> str:
        """脱敏文本

        Args:
            text: 原始文本
            reversible: 是否支持可逆脱敏 (保存原始值的哈希映射)

        Returns:
            脱敏后的文本
        """
        if not self.config.enabled:
            return text

        result = text
        for compiled_pattern, type_name in self._compiled_patterns:
            def replace_func(match):
                original = match.group(0)
                if reversible:
                    # 生成唯一标识
                    hash_id = hashlib.md5(original.encode()).hexdigest()[:8]
                    replacement = f"{self.config.replacement_prefix}{type_name}:{hash_id}{self.config.replacement_suffix}"
                    self._mapping[hash_id] = original
                    self._reverse_mapping[original] = replacement
                else:
                    if self.config.preserve_length:
                        replacement = f"{self.config.replacement_prefix}{type_name}{self.config.replacement_suffix}"
                        # 填充到原始长度
                        replacement = replacement.ljust(len(original), '*')[:len(original)]
                    else:
                        replacement = f"{self.config.replacement_prefix}{type_name}{self.config.replacement_suffix}"
                return replacement

            result = compiled_pattern.sub(replace_func, result)

        return result

    def restore(self, text: str) -> str:
        """恢复脱敏内容 (仅支持可逆脱敏)

        Args:
            text: 脱敏后的文本

        Returns:
            恢复后的文本
        """
        result = text
        # 查找所有脱敏标记
        pattern = re.compile(
            rf'{re.escape(self.config.replacement_prefix)}(\w+):([a-f0-9]{{8}}){re.escape(self.config.replacement_suffix)}'
        )

        def restore_func(match):
            hash_id = match.group(2)
            return self._mapping.get(hash_id, match.group(0))

        return pattern.sub(restore_func, result)

    def get_stats(self) -> Dict[str, int]:
        """获取脱敏统计"""
        return {
            "mapped_items": len(self._mapping),
            "patterns_count": len(self._compiled_patterns)
        }

    def clear_mapping(self) -> None:
        """清空映射表"""
        self._mapping.clear()
        self._reverse_mapping.clear()


class APIKeyMasker:
    """API Key 遮蔽器"""

    def __init__(self, visible_chars: int = 4):
        """初始化

        Args:
            visible_chars: 显示的字符数 (前 N 位)
        """
        self.visible_chars = visible_chars

    def mask(self, key: str) -> str:
        """遮蔽 API Key

        Args:
            key: 原始 API Key

        Returns:
            遮蔽后的字符串
        """
        if not key:
            return ""

        if len(key) <= self.visible_chars:
            return "*" * len(key)

        visible_part = key[:self.visible_chars]
        masked_length = len(key) - self.visible_chars
        return f"{visible_part}{'*' * masked_length}"

    def mask_in_text(self, text: str, key: str) -> str:
        """在文本中遮蔽 API Key

        Args:
            text: 原始文本
            key: 要遮蔽的 API Key

        Returns:
            处理后的文本
        """
        if not key or len(key) < 8:
            return text
        return text.replace(key, self.mask(key))


class SecureLogger:
    """安全日志记录器

    自动过滤敏感信息
    """

    def __init__(
        self,
        logger_name: str = "audit",
        desensitizer: Optional[DataDesensitizer] = None,
        max_code_chars: int = 200,
        mask_api_keys: bool = True
    ):
        """初始化

        Args:
            logger_name: 日志器名称
            desensitizer: 脱敏器
            max_code_chars: 日志中最大代码字符数
            mask_api_keys: 是否遮蔽 API Key
        """
        self.logger = logging.getLogger(logger_name)
        self.desensitizer = desensitizer or DataDesensitizer()
        self.max_code_chars = max_code_chars
        self.mask_api_keys = mask_api_keys
        self.api_key_masker = APIKeyMasker()

        # 已知的 API Key (用于遮蔽)
        self._api_keys: Set[str] = set()

    def register_api_key(self, key: str) -> None:
        """注册 API Key (用于自动遮蔽)"""
        if key and len(key) >= 8:
            self._api_keys.add(key)

    def _sanitize(self, message: str) -> str:
        """净化日志消息"""
        result = message

        # 脱敏处理
        if self.desensitizer.config.enabled:
            result = self.desensitizer.desensitize(result)

        # 遮蔽 API Key
        if self.mask_api_keys:
            for key in self._api_keys:
                result = self.api_key_masker.mask_in_text(result, key)

        # 截断代码
        if len(result) > self.max_code_chars * 2:
            # 检查是否包含代码块
            if "```" in result or "def " in result or "function " in result:
                # 截断代码部分
                result = result[:self.max_code_chars] + f"... [truncated, total {len(message)} chars]"

        return result

    def debug(self, message: str, *args, **kwargs):
        """记录 DEBUG 日志"""
        self.logger.debug(self._sanitize(message), *args, **kwargs)

    def info(self, message: str, *args, **kwargs):
        """记录 INFO 日志"""
        self.logger.info(self._sanitize(message), *args, **kwargs)

    def warning(self, message: str, *args, **kwargs):
        """记录 WARNING 日志"""
        self.logger.warning(self._sanitize(message), *args, **kwargs)

    def error(self, message: str, *args, **kwargs):
        """记录 ERROR 日志"""
        self.logger.error(self._sanitize(message), *args, **kwargs)

    def critical(self, message: str, *args, **kwargs):
        """记录 CRITICAL 日志"""
        self.logger.critical(self._sanitize(message), *args, **kwargs)


class OperationGuard:
    """敏感操作防护器

    阻止 LLM 自动执行危险操作
    """

    # 危险操作关键词
    DANGEROUS_OPERATIONS = {
        "file_delete": ["rm ", "remove(", "unlink(", "rmdir(", "shutil.rmtree"],
        "file_write": ["open(", "write(", "writelines("],
        "shell_exec": ["os.system(", "subprocess.", "exec(", "eval(", "shell=True"],
        "network": ["requests.", "urllib.", "socket.", "http.client"],
        "database": ["DROP ", "DELETE ", "TRUNCATE ", "cursor.execute("],
    }

    def __init__(
        self,
        block_dangerous: bool = True,
        require_confirmation: bool = True,
        allowed_operations: Optional[List[str]] = None
    ):
        """初始化

        Args:
            block_dangerous: 是否阻止危险操作
            require_confirmation: 是否需要确认
            allowed_operations: 允许的操作类型列表
        """
        self.block_dangerous = block_dangerous
        self.require_confirmation = require_confirmation
        self.allowed_operations = set(allowed_operations or [])

        # 操作日志
        self._operation_log: List[Dict[str, Any]] = []

    def check_code(self, code: str) -> Dict[str, Any]:
        """检查代码中的危险操作

        Args:
            code: 要检查的代码

        Returns:
            检查结果
        """
        detected_operations = []

        for op_type, keywords in self.DANGEROUS_OPERATIONS.items():
            for keyword in keywords:
                if keyword.lower() in code.lower():
                    detected_operations.append({
                        "type": op_type,
                        "keyword": keyword,
                        "blocked": self.block_dangerous and op_type not in self.allowed_operations
                    })

        is_safe = not any(op["blocked"] for op in detected_operations)
        needs_confirmation = (
            self.require_confirmation and
            detected_operations and
            not all(op["type"] in self.allowed_operations for op in detected_operations)
        )

        result = {
            "is_safe": is_safe,
            "detected_operations": detected_operations,
            "needs_confirmation": needs_confirmation,
            "message": self._generate_message(detected_operations)
        }

        # 记录日志
        self._operation_log.append({
            "code_preview": code[:200],
            "result": result
        })

        return result

    def _generate_message(self, operations: List[Dict[str, Any]]) -> str:
        """生成检查消息"""
        if not operations:
            return "No dangerous operations detected."

        blocked = [op for op in operations if op["blocked"]]
        if blocked:
            types = set(op["type"] for op in blocked)
            return f"Blocked dangerous operations: {', '.join(types)}"

        types = set(op["type"] for op in operations)
        return f"Detected operations requiring review: {', '.join(types)}"

    def log_operation(
        self,
        operation_type: str,
        description: str,
        approved: bool = False,
        approver: Optional[str] = None
    ) -> None:
        """记录操作日志"""
        self._operation_log.append({
            "type": operation_type,
            "description": description,
            "approved": approved,
            "approver": approver,
            "timestamp": __import__("time").time()
        })

    def get_operation_log(self) -> List[Dict[str, Any]]:
        """获取操作日志"""
        return self._operation_log.copy()


def require_human_confirmation(operation_name: str):
    """装饰器：要求人工确认

    用于标记需要人工确认的函数
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 在非交互模式下，记录警告
            logger.warning(
                f"Operation '{operation_name}' would require human confirmation in production mode"
            )
            return func(*args, **kwargs)
        wrapper._requires_confirmation = True
        wrapper._operation_name = operation_name
        return wrapper
    return decorator


# 便捷函数
def create_desensitizer(config) -> DataDesensitizer:
    """从配置创建脱敏器"""
    desensitization_config = DesensitizationConfig(
        enabled=config.security.enable_desensitization,
        patterns=config.security.desensitize_patterns
    )
    return DataDesensitizer(desensitization_config)


def create_secure_logger(config, logger_name: str = "audit") -> SecureLogger:
    """从配置创建安全日志器"""
    desensitizer = create_desensitizer(config)
    return SecureLogger(
        logger_name=logger_name,
        desensitizer=desensitizer,
        max_code_chars=config.security.max_code_in_logs,
        mask_api_keys=config.security.mask_api_key_in_logs
    )


def create_operation_guard(config) -> OperationGuard:
    """从配置创建操作防护器"""
    return OperationGuard(
        block_dangerous=config.security.prevent_auto_execution,
        require_confirmation=config.security.require_human_confirm
    )

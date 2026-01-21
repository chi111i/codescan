"""外部扫描器集成模块

P1-1: 集成 Semgrep/CodeQL 等外部扫描工具
用于生成候选点，补充内部 sink scanner 的召回率
"""

from .semgrep_runner import (
    SemgrepRunner,
    SemgrepConfig,
    SemgrepResult,
    SemgrepFinding,
)
from .sarif_importer import (
    SarifImporter,
    SarifFinding,
    SarifLocation,
)

__all__ = [
    # Semgrep 集成
    "SemgrepRunner",
    "SemgrepConfig",
    "SemgrepResult",
    "SemgrepFinding",
    # SARIF 导入
    "SarifImporter",
    "SarifFinding",
    "SarifLocation",
]

#!/usr/bin/env python3
"""CodeScan 模块入口

使用方式::

    python -m codescan scan ./my_project
    python -m codescan index ./my_project
    python -m codescan rules list

实现说明：
本项目历史上采用“平铺式”模块组织（config/cli/indexer 等在同一层级），
大量使用 `from xxx import ...` 的导入方式。

当通过 `python -m codescan` 从父目录运行时，默认 sys.path 不包含本目录，
会导致无法导入 cli/config 等模块。

这里显式将本目录加入 sys.path，确保开箱即用。
"""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cli.main import main as cli_main


def main() -> None:
    """CLI 入口"""
    cli_main()


if __name__ == "__main__":
    main()

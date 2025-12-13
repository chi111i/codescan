#!/usr/bin/env python3
"""
LLM 驱动的代码安全审计工具

使用方式:
    python -m codescan scan ./my_project
    python -m codescan index ./my_project
    python -m codescan rules list
"""

from cli import main

if __name__ == "__main__":
    main()

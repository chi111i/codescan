"""
项目管理模块 - 支持多项目隔离存储
"""

from .manager import ProjectManager, generate_project_id, generate_collection_name
from .models import ProjectInfo, ProjectConfig

__all__ = [
    "ProjectManager",
    "ProjectInfo",
    "ProjectConfig",
    "generate_project_id",
    "generate_collection_name",
]

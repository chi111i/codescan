"""
项目数据模型
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime


@dataclass
class ProjectConfig:
    """项目配置"""
    languages: list = field(default_factory=lambda: ["python", "javascript", "php"])
    include_patterns: list = field(default_factory=lambda: ["**/*.py", "**/*.js", "**/*.ts", "**/*.php"])
    exclude_patterns: list = field(default_factory=lambda: ["**/node_modules/**", "**/__pycache__/**", "**/venv/**"])
    max_file_size_kb: int = 500


@dataclass
class ProjectInfo:
    """项目信息"""
    id: str
    name: str
    path: str
    collection_name: str
    created_at: str
    last_indexed_at: Optional[str] = None
    total_units: int = 0
    config: Optional[ProjectConfig] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "name": self.name,
            "path": self.path,
            "collection_name": self.collection_name,
            "created_at": self.created_at,
            "last_indexed_at": self.last_indexed_at,
            "total_units": self.total_units,
            "config": {
                "languages": self.config.languages if self.config else [],
                "include_patterns": self.config.include_patterns if self.config else [],
                "exclude_patterns": self.config.exclude_patterns if self.config else [],
                "max_file_size_kb": self.config.max_file_size_kb if self.config else 500,
            } if self.config else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProjectInfo":
        """从字典创建"""
        config_data = data.get("config")
        config = None
        if config_data:
            config = ProjectConfig(
                languages=config_data.get("languages", []),
                include_patterns=config_data.get("include_patterns", []),
                exclude_patterns=config_data.get("exclude_patterns", []),
                max_file_size_kb=config_data.get("max_file_size_kb", 500),
            )

        return cls(
            id=data["id"],
            name=data["name"],
            path=data["path"],
            collection_name=data["collection_name"],
            created_at=data["created_at"],
            last_indexed_at=data.get("last_indexed_at"),
            total_units=data.get("total_units", 0),
            config=config,
            metadata=data.get("metadata", {}),
        )

    def update_index_stats(self, total_units: int):
        """更新索引统计"""
        self.last_indexed_at = datetime.now().isoformat()
        self.total_units = total_units

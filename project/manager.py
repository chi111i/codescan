"""
项目管理器 - 管理多个扫描项目的隔离存储
"""

import re
import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

from config import AuditConfig, VectorStoreConfig
from .models import ProjectInfo, ProjectConfig

logger = logging.getLogger(__name__)


def generate_project_id(project_path: str) -> str:
    """生成项目唯一 ID

    基于项目绝对路径的 MD5 哈希生成唯一标识符

    Args:
        project_path: 项目路径

    Returns:
        12 字符的唯一 ID
    """
    abs_path = str(Path(project_path).resolve())
    return hashlib.md5(abs_path.encode()).hexdigest()[:12]


def generate_collection_name(project_path: str, prefix: str = "code_audit") -> str:
    """生成项目专属向量集合名

    格式: {prefix}_{项目名}_{ID}

    Args:
        project_path: 项目路径
        prefix: 集合名前缀

    Returns:
        集合名称
    """
    project_id = generate_project_id(project_path)
    project_name = Path(project_path).name
    # 清理项目名：只保留字母、数字和下划线，限制长度
    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', project_name)[:20]
    # 移除连续下划线
    safe_name = re.sub(r'_+', '_', safe_name).strip('_')
    return f"{prefix}_{safe_name}_{project_id}"


class ProjectManager:
    """项目管理器

    功能：
    - 创建、获取、删除项目
    - 项目元数据持久化
    - 每个项目使用独立的向量集合
    """

    def __init__(
        self,
        config: AuditConfig,
        storage_path: Optional[str] = None,
    ):
        """初始化项目管理器

        Args:
            config: 审计配置
            storage_path: 项目元数据存储路径，默认使用配置中的缓存目录
        """
        self.config = config
        self.storage_dir = Path(storage_path or config.vector_store.cache_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.projects_file = self.storage_dir / "projects.json"
        self._projects: Dict[str, ProjectInfo] = {}
        self._load_projects()

    def _load_projects(self) -> None:
        """从文件加载项目列表"""
        if self.projects_file.exists():
            try:
                with open(self.projects_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for project_data in data.get("projects", []):
                        project = ProjectInfo.from_dict(project_data)
                        self._projects[project.id] = project
                logger.info(f"Loaded {len(self._projects)} projects from storage")
            except Exception as e:
                logger.warning(f"Failed to load projects file: {e}")
                self._projects = {}

    def _save_projects(self) -> None:
        """保存项目列表到文件"""
        try:
            data = {
                "version": "1.0",
                "updated_at": datetime.now().isoformat(),
                "projects": [p.to_dict() for p in self._projects.values()],
            }
            with open(self.projects_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.debug(f"Saved {len(self._projects)} projects to storage")
        except Exception as e:
            logger.error(f"Failed to save projects file: {e}")

    def create_project(
        self,
        project_path: str,
        name: Optional[str] = None,
        config: Optional[ProjectConfig] = None,
    ) -> ProjectInfo:
        """创建新项目

        如果项目已存在（基于路径），则返回现有项目

        Args:
            project_path: 项目路径
            name: 项目名称，默认使用目录名
            config: 项目配置

        Returns:
            ProjectInfo 对象
        """
        abs_path = str(Path(project_path).resolve())
        project_id = generate_project_id(abs_path)

        # 检查是否已存在
        if project_id in self._projects:
            logger.info(f"Project already exists: {project_id}")
            return self._projects[project_id]

        # 生成集合名
        collection_name = generate_collection_name(
            abs_path,
            prefix=self.config.vector_store.collection_name.split("_")[0]  # 使用配置的前缀
        )

        # 创建项目信息
        project = ProjectInfo(
            id=project_id,
            name=name or Path(abs_path).name,
            path=abs_path,
            collection_name=collection_name,
            created_at=datetime.now().isoformat(),
            config=config or ProjectConfig(),
        )

        self._projects[project_id] = project
        self._save_projects()

        logger.info(f"Created project: {project.name} (id={project_id}, collection={collection_name})")
        return project

    def get_project(self, project_id: str) -> Optional[ProjectInfo]:
        """根据 ID 获取项目

        Args:
            project_id: 项目 ID

        Returns:
            ProjectInfo 对象，如果不存在则返回 None
        """
        return self._projects.get(project_id)

    def get_project_by_path(self, project_path: str) -> Optional[ProjectInfo]:
        """根据路径获取项目

        Args:
            project_path: 项目路径

        Returns:
            ProjectInfo 对象，如果不存在则返回 None
        """
        project_id = generate_project_id(project_path)
        return self._projects.get(project_id)

    def get_or_create_project(
        self,
        project_path: str,
        name: Optional[str] = None,
    ) -> ProjectInfo:
        """获取或创建项目

        Args:
            project_path: 项目路径
            name: 项目名称

        Returns:
            ProjectInfo 对象
        """
        project = self.get_project_by_path(project_path)
        if project:
            return project
        return self.create_project(project_path, name)

    def update_project(self, project: ProjectInfo) -> None:
        """更新项目信息

        Args:
            project: 项目信息对象
        """
        if project.id in self._projects:
            self._projects[project.id] = project
            self._save_projects()

    def delete_project(self, project_id: str, delete_vectors: bool = True) -> bool:
        """删除项目

        Args:
            project_id: 项目 ID
            delete_vectors: 是否同时删除向量数据

        Returns:
            是否删除成功
        """
        if project_id not in self._projects:
            logger.warning(f"Project not found: {project_id}")
            return False

        project = self._projects[project_id]

        # 删除向量数据
        if delete_vectors:
            try:
                from indexer.vector_store import create_vector_store
                vector_config = VectorStoreConfig(
                    provider=self.config.vector_store.provider,
                    host=self.config.vector_store.host,
                    port=self.config.vector_store.port,
                    collection_name=project.collection_name,
                    api_key=self.config.vector_store.api_key,
                    https=self.config.vector_store.https,
                )
                vector_store = create_vector_store(
                    vector_config,
                    embedding_dim=self.config.llm.embedding_dim
                )
                vector_store.clear()
                logger.info(f"Deleted vector collection: {project.collection_name}")
            except Exception as e:
                logger.warning(f"Failed to delete vector collection: {e}")

        # 从列表中删除
        del self._projects[project_id]
        self._save_projects()

        logger.info(f"Deleted project: {project.name} (id={project_id})")
        return True

    def list_projects(self) -> List[ProjectInfo]:
        """列出所有项目

        Returns:
            ProjectInfo 列表
        """
        return list(self._projects.values())

    def get_project_vector_config(self, project: ProjectInfo) -> VectorStoreConfig:
        """获取项目的向量存储配置

        创建一个使用项目专属集合名的配置副本

        Args:
            project: 项目信息

        Returns:
            VectorStoreConfig 对象
        """
        return VectorStoreConfig(
            provider=self.config.vector_store.provider,
            host=self.config.vector_store.host,
            port=self.config.vector_store.port,
            collection_name=project.collection_name,
            api_key=self.config.vector_store.api_key,
            https=self.config.vector_store.https,
            enable_cache=self.config.vector_store.enable_cache,
            cache_dir=self.config.vector_store.cache_dir,
            cache_ttl_days=self.config.vector_store.cache_ttl_days,
        )

    def project_exists(self, project_path: str) -> bool:
        """检查项目是否存在

        Args:
            project_path: 项目路径

        Returns:
            是否存在
        """
        project_id = generate_project_id(project_path)
        return project_id in self._projects

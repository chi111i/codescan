"""
回归测试：skip_index（直接解析）模式下，read_file 应该使用本次扫描目录作为根路径。
"""

from config.settings import AuditConfig
from indexer.indexer import CodeIndexer


class _DummyLLMClient:
    """仅用于初始化 CodeIndexer，避免真实网络调用。"""

    def embed(self, texts):
        return [[0.0] * 1536 for _ in texts]


def test_parse_directory_without_index_updates_target_path_for_read_file(tmp_path):
    """直接解析后，read_file 应能读取扫描目录内文件（回归 BUG: 目标路径未更新）。"""
    # 构造最小 PHP 目录结构（模拟 DVWA 风格路径）
    source_dir = tmp_path / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    php_file = source_dir / "impossible.php"
    php_file.write_text(
        "<?php\n"
        "if(isset($_POST['Submit'])) {\n"
        "    $cmd = escapeshellcmd($_POST['ip']);\n"
        "    echo $cmd;\n"
        "}\n",
        encoding="utf-8",
    )

    config = AuditConfig()
    config.vector_store.enable_cache = False
    config.vector_store.cache_dir = str(tmp_path / ".audit_cache")

    indexer = CodeIndexer(config, _DummyLLMClient())
    try:
        units = indexer.parse_directory_without_index(str(tmp_path), languages=["php"])

        # 关键断言 1：当前目标路径被更新到本次扫描目录
        assert indexer.get_current_target_path() == tmp_path.resolve()

        # 关键断言 2：代码单元确实包含目标文件
        assert any("impossible.php" in u.file_path.replace("\\", "/") for u in units)

        # 关键断言 3：read_file 能从扫描目录读取到相对路径文件
        content = indexer.read_file("source/impossible.php")
        assert content is not None
        assert "escapeshellcmd" in content
    finally:
        # 避免 sqlite 句柄泄露；不调用 indexer.close() 以规避现有异步 close 的无 await 警告
        indexer.file_tracker.close()

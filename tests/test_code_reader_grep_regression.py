"""
CodeReader.grep_code 回归测试

修复点：当索引中的 file_path 是相对路径时，grep 应基于 project_path 解析，
而不是把相对路径当作当前工作目录路径，导致匹配结果为 0。
"""

from pathlib import Path

from indexer.code_reader import CodeReader


class _Unit:
    def __init__(self, file_path: str):
        self.file_path = file_path


class _DummyIndexer:
    def __init__(self, units):
        self._units = units
        self._current_target_path = None

    def get_all_units(self):
        return self._units


def test_grep_code_resolves_relative_indexed_paths(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir(parents=True, exist_ok=True)
    target = source_dir / "high.php"
    target.write_text(
        "<?php\n"
        "$cmd = shell_exec('ping 127.0.0.1');\n",
        encoding="utf-8",
    )

    # 模拟索引里只有相对路径（这在 skip_index/混合流程中很常见）
    indexer = _DummyIndexer(units=[_Unit("source/high.php")])
    reader = CodeReader(project_path=str(tmp_path), indexer=indexer)

    result = reader.grep_code(
        pattern="shell_exec",
        file_glob="*.php",
        use_regex=False,
        case_sensitive=True,
    )

    assert result["success"] is True
    assert result["total_matches"] >= 1
    assert any("source/high.php" in m["file_path"].replace("\\", "/") for m in result["matches"])

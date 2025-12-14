"""
使用示例：LLM 智能代码读取与项目隔离

演示如何使用 Agent 进行代码分析。
"""

import json
from pathlib import Path

from config import load_config
from llm_client import create_llm_client, MockLLMClient, ToolCall
from project import ProjectManager
from indexer import CodeIndexer, CodeReader, create_vector_store
from agent import CodeAnalysisAgent, SecurityAnalysisAgent, CODE_READER_TOOLS


def demo_project_isolation():
    """演示项目隔离功能"""
    print("=" * 60)
    print("项目隔离演示")
    print("=" * 60)

    config = load_config()
    project_manager = ProjectManager(config)

    # 创建两个项目
    project1 = project_manager.create_project("/path/to/project-a", name="Project A")
    project2 = project_manager.create_project("/path/to/project-b", name="Project B")

    print(f"\n项目 1: {project1.name}")
    print(f"  ID: {project1.id}")
    print(f"  集合名: {project1.collection_name}")

    print(f"\n项目 2: {project2.name}")
    print(f"  ID: {project2.id}")
    print(f"  集合名: {project2.collection_name}")

    print(f"\n所有项目: {[p.name for p in project_manager.list_projects()]}")


def demo_mock_agent():
    """使用 Mock 客户端演示 Agent 功能"""
    print("\n" + "=" * 60)
    print("Agent 功能演示 (Mock 模式)")
    print("=" * 60)

    # 使用 Mock 客户端
    llm_client = MockLLMClient()

    # 设置模拟的工具调用响应
    llm_client.set_mock_tool_calls([
        ToolCall(
            id="call_1",
            name="search_code",
            arguments={"query": "用户认证", "top_k": 3}
        )
    ])

    # 创建简单的 Mock CodeReader
    class MockCodeReader:
        def __init__(self, project_path):
            self.project_path = Path(project_path)

        def search_code(self, query, top_k=5, **kwargs):
            return {
                "success": True,
                "query": query,
                "results": [
                    {
                        "file_path": "src/auth/login.py",
                        "symbol": "authenticate_user",
                        "type": "function",
                        "start_line": 10,
                        "end_line": 25,
                        "code": "def authenticate_user(username, password):\n    ...",
                        "signature": "authenticate_user(username, password)",
                        "language": "python",
                    }
                ],
                "total": 1,
            }

        def read_file(self, file_path, **kwargs):
            return {"success": True, "content": "# Mock file content", "total_lines": 10}

        def read_symbol(self, symbol_name, **kwargs):
            return {"success": True, "definitions": []}

        def list_files(self, **kwargs):
            return {"success": True, "files": [], "total": 0}

        def get_file_outline(self, file_path):
            return {"success": True, "outline": [], "total_symbols": 0}

    mock_reader = MockCodeReader(".")

    # 创建 Agent
    agent = CodeAnalysisAgent(
        llm_client=llm_client,
        code_reader=mock_reader,
        max_tool_calls=5,
    )

    # 执行分析
    result = agent.analyze(
        task="分析用户认证模块的安全性",
    )

    print(f"\n工具调用次数: {result.total_tool_calls}")
    print(f"总 Token 数: {result.total_tokens}")
    print(f"是否截断: {result.truncated}")

    if result.tool_calls_history:
        print("\n工具调用历史:")
        for record in result.tool_calls_history:
            print(f"  - {record.tool_name}: {json.dumps(record.arguments, ensure_ascii=False)}")

    print(f"\n最终结果: {result.content[:200]}..." if result.content else "\n无最终结果")


def demo_tools_schema():
    """演示 Tools Schema"""
    print("\n" + "=" * 60)
    print("Tools Schema 定义")
    print("=" * 60)

    for tool in CODE_READER_TOOLS:
        func = tool["function"]
        print(f"\n工具: {func['name']}")
        print(f"  描述: {func['description'][:80]}...")
        params = func["parameters"]["properties"]
        print(f"  参数: {list(params.keys())}")


def main():
    """运行所有演示"""
    print("\n🚀 LLM 智能代码读取功能演示\n")

    try:
        demo_project_isolation()
    except Exception as e:
        print(f"项目隔离演示失败: {e}")

    try:
        demo_mock_agent()
    except Exception as e:
        print(f"Agent 演示失败: {e}")

    demo_tools_schema()

    print("\n" + "=" * 60)
    print("演示完成!")
    print("=" * 60)


if __name__ == "__main__":
    main()

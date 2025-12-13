#!/usr/bin/env python
"""
启动脚本 - 同时运行后端 API 和前端开发服务器
"""

import subprocess
import sys
import os
import signal
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent


def run_backend():
    """运行后端 API"""
    print("启动后端 API 服务...")
    os.chdir(PROJECT_ROOT)
    subprocess.run([
        sys.executable, "-m", "uvicorn",
        "api.main:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--reload"
    ])


def run_frontend():
    """运行前端开发服务器"""
    print("启动前端开发服务器...")
    frontend_dir = PROJECT_ROOT / "frontend"
    os.chdir(frontend_dir)

    # 检查是否已安装依赖
    if not (frontend_dir / "node_modules").exists():
        print("安装前端依赖...")
        subprocess.run(["npm", "install"], check=True)

    subprocess.run(["npm", "run", "dev"])


def main():
    import argparse

    parser = argparse.ArgumentParser(description="CodeScan 启动脚本")
    parser.add_argument(
        "command",
        choices=["api", "frontend", "all"],
        default="api",
        nargs="?",
        help="启动命令: api (仅后端), frontend (仅前端), all (全部)"
    )
    parser.add_argument(
        "--host", default="0.0.0.0",
        help="API 服务器地址"
    )
    parser.add_argument(
        "--port", type=int, default=8000,
        help="API 服务器端口"
    )

    args = parser.parse_args()

    if args.command == "api":
        run_backend()
    elif args.command == "frontend":
        run_frontend()
    elif args.command == "all":
        import threading

        # 在后台线程运行后端
        backend_thread = threading.Thread(target=run_backend, daemon=True)
        backend_thread.start()

        # 主线程运行前端
        run_frontend()


if __name__ == "__main__":
    main()

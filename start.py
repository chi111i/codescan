#!/usr/bin/env python
"""
启动脚本 - 同时运行后端 API 和前端开发服务器
"""

import subprocess
import sys
import os
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent

# 后台线程异常标志
_backend_error = None
_backend_started = False

# Windows 终端 UTF-8 支持 + 禁用输出缓冲
if sys.platform == 'win32':
    os.environ.setdefault('PYTHONIOENCODING', 'utf-8')
os.environ['PYTHONUNBUFFERED'] = '1'  # 禁用 Python 输出缓冲，确保日志实时显示


def run_backend(use_subprocess: bool = False):
    """运行后端 API

    参数:
        use_subprocess: 是否使用 subprocess 启动。在后台线程中必须使用 subprocess，
                        因为 uvicorn reload 模式需要信号处理，只能在主线程中工作。

    Windows + uvicorn --reload 日志显示问题的解决方案：

    核心问题：uvicorn --reload 会创建一个 worker 子进程处理请求。
    如果使用 subprocess.PIPE 捕获输出，Windows 上 worker 子进程不会继承 PIPE，
    导致 worker 进程中的日志（HTTP 请求、LLM 调用）全部丢失。

    解决方案：设置 log_config=None 禁止 uvicorn 覆盖应用日志配置。
    """
    global _backend_error, _backend_started
    print("启动后端 API 服务...", flush=True)
    os.chdir(PROJECT_ROOT)

    # 设置环境变量确保 Python 使用 UTF-8 编码和禁用缓冲
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    env['PYTHONUNBUFFERED'] = '1'
    # Windows 特殊设置：确保子进程输出不被缓冲
    env['PYTHONLEGACYWINDOWSSTDIO'] = '1'

    if use_subprocess:
        # 在后台线程中使用 subprocess 启动 uvicorn
        # 因为 uvicorn reload 模式的信号处理只能在主线程中工作
        #
        # 注意：命令行方式无法直接设置 log_config=None，但可以通过设置
        # UVICORN_LOG_CONFIG 环境变量为空字符串来达到类似效果
        # 实际上，我们依赖 api/main.py 中的 lifespan 重新配置日志
        env['UVICORN_LOG_CONFIG'] = ''  # 禁用默认日志配置

        cmd = [
            sys.executable, "-u", "-m", "uvicorn",
            "api.main:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--reload",
            "--log-level", "info",
            "--access-log",
        ]
        try:
            process = subprocess.Popen(
                cmd,
                env=env,
                close_fds=False if sys.platform == 'win32' else True,
            )
            result_code = process.wait()
            if result_code != 0:
                _backend_error = f"后端退出，退出码: {result_code}"
        except Exception as e:
            _backend_error = str(e)
            print(f"[ERROR] 后端启动失败: {e}", flush=True)
    else:
        # 在主线程中使用程序化方式启动 uvicorn
        try:
            import uvicorn

            # 更新当前进程环境变量（uvicorn 会继承）
            os.environ.update(env)

            # 使用程序化方式启动 uvicorn，设置 log_config=None 禁止覆盖应用日志
            config = uvicorn.Config(
                "api.main:app",
                host="0.0.0.0",
                port=8000,
                reload=True,
                log_level="info",
                log_config=None,  # 关键：禁止 uvicorn 覆盖日志配置
                access_log=True,
            )
            server = uvicorn.Server(config)
            server.run()
        except Exception as e:
            _backend_error = str(e)
            print(f"[ERROR] 后端启动失败: {e}", flush=True)


def run_backend_with_exception_handling():
    """后台线程运行后端（带异常处理和启动确认）

    注意：使用 subprocess 模式，因为 uvicorn reload 在非主线程中无法使用信号处理
    """
    global _backend_started, _backend_error
    try:
        _backend_started = True
        run_backend(use_subprocess=True)  # 在后台线程中必须使用 subprocess
    except Exception as e:
        _backend_error = str(e)
        print(f"[ERROR] 后端线程异常: {e}")


def run_frontend():
    """运行前端开发服务器"""
    print("启动前端开发服务器...")
    frontend_dir = PROJECT_ROOT / "frontend"
    os.chdir(frontend_dir)

    # Windows 上需要 shell=True 来运行 npm（因为 npm 是 npm.cmd）
    use_shell = sys.platform == 'win32'

    # 检查是否已安装依赖
    if not (frontend_dir / "node_modules").exists():
        print("安装前端依赖...")
        subprocess.run(["npm", "install"], check=True, shell=use_shell)

    subprocess.run(["npm", "run", "dev"], shell=use_shell)


def main():
    import argparse
    import threading

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
        global _backend_error, _backend_started

        # 在后台线程运行后端（带异常处理）
        backend_thread = threading.Thread(
            target=run_backend_with_exception_handling,
            daemon=True,
            name="backend-thread"
        )
        backend_thread.start()

        # 等待后端启动（最多 5 秒）
        for _ in range(50):
            if _backend_started or _backend_error:
                break
            time.sleep(0.1)

        # 检查是否启动失败
        if _backend_error:
            print(f"[FATAL] 后端启动失败: {_backend_error}")
            sys.exit(1)

        # 短暂等待确保后端稳定
        time.sleep(1)

        # 检查后端线程是否仍在运行
        if not backend_thread.is_alive():
            if _backend_error:
                print(f"[FATAL] 后端已退出: {_backend_error}")
            else:
                print("[FATAL] 后端线程意外退出")
            sys.exit(1)

        print("[INFO] 后端已启动，正在启动前端...")

        # 主线程运行前端
        try:
            run_frontend()
        except KeyboardInterrupt:
            print("\n[INFO] 收到中断信号，正在关闭...")
        finally:
            # 前端退出后，给后端一点时间完成关闭
            print("[INFO] 前端已关闭")


if __name__ == "__main__":
    main()

"""JSON 序列化辅助工具

本项目包含大量需要将运行时对象持久化/通过 WebSocket 发送的场景。
Starlette/FastAPI 的 ``WebSocket.send_json`` 内部使用 ``json.dumps``，
不会自动处理 ``datetime`` 等对象，容易触发：

    Object of type datetime is not JSON serializable

为避免类似问题在“智能审计/交互式审计/扫描记录”链路中反复出现，
这里提供统一的安全序列化方法：

- ``to_jsonable``: 将对象递归转换为 JSON 兼容的 Python 对象
- ``safe_json_dumps``: 基于 ``to_jsonable`` 的 ``json.dumps`` 封装

设计目标：
1) **永不抛出** "not JSON serializable" 这类异常（最坏情况退化为字符串）。
2) 对常见类型（datetime/Enum/Path/dataclass/pydantic）尽量保真。
3) 仅依赖标准库，避免循环依赖。
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import date, datetime, time
from enum import Enum
from pathlib import Path
from typing import Any

# orjson 可选加速 (比标准库快 3-10x)
try:
    import orjson
    _HAS_ORJSON = True
except ImportError:
    orjson = None  # type: ignore
    _HAS_ORJSON = False


def to_jsonable(obj: Any) -> Any:
    """将任意对象转换为 JSON 兼容的 Python 对象。

    该函数会递归处理 dict/list/tuple/set 等容器，并对常见不可序列化类型做降级：
    - datetime/date/time -> isoformat 字符串
    - Enum -> value
    - Path -> str
    - dataclass -> asdict
    - pydantic BaseModel -> model_dump(mode='json')
    - 其它对象优先尝试 to_dict()/dict()/__dict__，最后退化为 str(obj)
    """
    # Fast path: JSON 原生类型
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    # 常见不可 JSON 序列化类型
    if isinstance(obj, (datetime, date, time)):
        try:
            return obj.isoformat()
        except Exception:
            return str(obj)

    if isinstance(obj, Enum):
        try:
            return obj.value
        except Exception:
            return str(obj)

    if isinstance(obj, Path):
        return str(obj)

    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")

    # 容器类型
    if isinstance(obj, dict):
        # JSON 要求 key 为字符串；这里统一转成 str
        return {str(k): to_jsonable(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in obj]

    # dataclass
    if is_dataclass(obj):
        try:
            return to_jsonable(asdict(obj))
        except Exception:
            return str(obj)

    # pydantic v2 BaseModel（避免直接 import pydantic，减少依赖）
    if hasattr(obj, "model_dump") and callable(getattr(obj, "model_dump")):
        try:
            # mode='json' 会尽量把 datetime 等转换为可 JSON 的类型
            return to_jsonable(obj.model_dump(mode="json"))
        except TypeError:
            # 兼容某些自定义 model_dump 签名
            try:
                return to_jsonable(obj.model_dump())
            except Exception:
                pass
        except Exception:
            pass

    # 优先使用显式的 to_dict/dict
    if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        try:
            return to_jsonable(obj.to_dict())
        except Exception:
            pass

    if hasattr(obj, "dict") and callable(getattr(obj, "dict")):
        try:
            return to_jsonable(obj.dict())
        except Exception:
            pass

    # 回退：__dict__
    if hasattr(obj, "__dict__"):
        try:
            return to_jsonable(vars(obj))
        except Exception:
            pass

    # 最终兜底
    return str(obj)


def safe_json_dumps(
    data: Any,
    *,
    ensure_ascii: bool = False,
    **kwargs: Any,
) -> str:
    """安全版 json.dumps。

    Args:
        data: 任意对象
        ensure_ascii: 默认 False，便于中文显示
        **kwargs: 透传给 json.dumps 的其它参数（indent 等）

    Returns:
        JSON 字符串
    """
    return json.dumps(to_jsonable(data), ensure_ascii=ensure_ascii, **kwargs)


def fast_json_dumps(data: Any) -> str:
    """高性能 JSON 序列化 (用于 WebSocket 等高频场景)。

    使用 orjson 加速序列化。如果 orjson 不可用，回退到标准 json 模块。
    注意：此函数假设数据已经过 to_jsonable() 处理，即不包含不可序列化类型。

    Args:
        data: 已处理为 JSON 兼容的 Python 对象

    Returns:
        紧凑的 JSON 字符串（无多余空格）
    """
    if _HAS_ORJSON:
        # orjson.dumps 返回 bytes，需要解码
        return orjson.dumps(data).decode("utf-8")
    # 标准库回退，使用紧凑分隔符
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def fast_json_loads(payload: str | bytes) -> Any:
    """高性能 JSON 反序列化。

    使用 orjson 加速反序列化。如果 orjson 不可用，回退到标准 json 模块。

    Args:
        payload: JSON 字符串或 bytes

    Returns:
        解析后的 Python 对象
    """
    if _HAS_ORJSON:
        return orjson.loads(payload)
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    return json.loads(payload)


def fast_safe_json_dumps(data: Any) -> str:
    """安全 + 高性能 JSON 序列化。

    组合 to_jsonable() 和 fast_json_dumps()，适用于 WebSocket 发送。

    Args:
        data: 任意对象

    Returns:
        紧凑的 JSON 字符串
    """
    return fast_json_dumps(to_jsonable(data))

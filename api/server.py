"""
API 服务模块

提供 RESTful API 接口供前端调用
"""

from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import logging
import json
from pathlib import Path

# 导入核心模块
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

logger = logging.getLogger(__name__)

app = FastAPI(
    title="CodeScan API",
    description="LLM 驱动的代码安全审计工具 API",
    version="1.0.0",
)

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== 数据模型 ====================

class ConfirmVulnRequest(BaseModel):
    """确认漏洞请求"""
    finding_id: str
    finding: Dict[str, Any]
    code_context: str
    call_chain: Optional[List[str]] = None


class SearchVariantsRequest(BaseModel):
    """搜索变体请求"""
    pattern_id: str
    top_k: int = 20
    similarity_threshold: float = 0.75
    use_llm_verification: bool = True


class GenerateRuleRequest(BaseModel):
    """生成规则请求"""
    pattern_id: str
    rule_type: str = "semantic"


class ConfirmVariantRequest(BaseModel):
    """确认变体请求"""
    variant_id: str
    is_true_positive: bool
    confirmed_by: str = "user"


class BuildGraphRequest(BaseModel):
    """构建代码图请求"""
    code: str
    file_path: str
    language: str


class AnalyzeDataFlowRequest(BaseModel):
    """数据流分析请求"""
    graph_id: str
    source_node_id: str
    sink_node_id: str
    max_depth: int = 10


class SearchSimilarGraphRequest(BaseModel):
    """搜索相似代码图请求"""
    graph_id: str
    top_k: int = 10


# ==================== 全局状态（实际应用中应使用依赖注入） ====================

# 懒加载的服务实例（全局单例）
_variant_analyzer = None
_graph_manager = None


def get_variant_analyzer():
    """获取变体分析器实例（单例）"""
    global _variant_analyzer
    if _variant_analyzer is None:
        from analyzer.variant_analysis import VariantAnalyzer
        # 这里需要实际的依赖注入
        # 目前使用 mock 模式
        _variant_analyzer = MockVariantAnalyzer()
    return _variant_analyzer


def get_graph_manager():
    """获取代码图管理器实例（单例）

    使用全局单例确保图数据在请求之间持久化
    """
    global _graph_manager
    if _graph_manager is None:
        from indexer.code_graph import CodeGraphManager
        _graph_manager = CodeGraphManager()
        logger.info("Initialized global CodeGraphManager singleton")
    return _graph_manager


def reset_graph_manager():
    """重置图管理器（用于测试）"""
    global _graph_manager
    _graph_manager = None


class MockVariantAnalyzer:
    """Mock 变体分析器（用于演示）"""

    def __init__(self):
        self.patterns = {}
        self.generated_rules = {}

    def confirm_vulnerability(self, finding, code_context, call_chain=None):
        from analyzer.variant_analysis import VulnPattern, PatternType
        import hashlib
        from datetime import datetime

        pattern_id = f"PAT-{hashlib.md5(code_context.encode()).hexdigest()[:8]}"
        pattern = VulnPattern(
            id=pattern_id,
            name=finding.get("issue_type", "Unknown"),
            pattern_type=PatternType.CUSTOM,
            description=finding.get("summary", ""),
            code_signature=code_context[:200],
            severity=finding.get("severity", "medium"),
            created_at=datetime.now().isoformat(),
        )
        self.patterns[pattern_id] = pattern
        return pattern

    def search_variants(self, pattern_id, top_k=20, similarity_threshold=0.75, use_llm_verification=True):
        from analyzer.variant_analysis import VariantMatch
        # 返回模拟数据
        return [
            VariantMatch(
                id=f"VAR-{i:04d}",
                pattern_id=pattern_id,
                file_path=f"src/example_{i}.py",
                function_name=f"vulnerable_func_{i}",
                line_start=10 + i * 5,
                line_end=20 + i * 5,
                code_snippet=f"# Example vulnerable code snippet {i}\ndef process_input(user_data):\n    exec(user_data)",
                similarity_score=0.95 - i * 0.05,
                embedding_similarity=0.92 - i * 0.04,
                structural_similarity=0.88 - i * 0.06,
                llm_verified=use_llm_verification,
                llm_confidence=0.85 - i * 0.05,
                llm_explanation=f"代码结构与模式 {pattern_id} 高度相似，存在相同的安全风险。",
            )
            for i in range(min(top_k, 5))
        ]

    def generate_rule_from_pattern(self, pattern_id, rule_type="semantic"):
        from analyzer.variant_analysis import GeneratedRule
        import hashlib
        from datetime import datetime

        rule_id = f"RULE-{hashlib.md5(pattern_id.encode()).hexdigest()[:8]}"
        rule = GeneratedRule(
            id=rule_id,
            name=f"Auto: Pattern {pattern_id}",
            source_pattern_id=pattern_id,
            rule_type=rule_type,
            rule_content={
                "detection_logic": "检测用户输入直接传递给危险函数的情况",
                "patterns": ["exec\\s*\\(", "eval\\s*\\(", "subprocess\\.call"],
                "anti_patterns": ["sanitize\\(", "validate\\("],
                "sink_patterns": ["exec", "eval", "system"],
                "source_patterns": ["request\\.", "input\\("],
            },
            description="自动生成的安全规则",
            detection_logic="检测用户输入直接传递给危险函数",
            languages=["python"],
            frameworks=["flask", "django"],
            auto_generated=True,
            approved=False,
            created_at=datetime.now().isoformat(),
        )
        self.generated_rules[rule_id] = rule
        return rule

    def get_pattern(self, pattern_id):
        return self.patterns.get(pattern_id)

    def list_patterns(self):
        return [p.to_dict() for p in self.patterns.values()]

    def list_rules(self):
        return [r.to_dict() for r in self.generated_rules.values()]

    def get_rule(self, rule_id):
        return self.generated_rules.get(rule_id)

    def approve_rule(self, rule_id):
        if rule_id in self.generated_rules:
            self.generated_rules[rule_id].approved = True
            return True
        return False

    def delete_rule(self, rule_id):
        if rule_id in self.generated_rules:
            del self.generated_rules[rule_id]
            return True
        return False

    def get_stats(self):
        return {
            "total_patterns": len(self.patterns),
            "total_rules": len(self.generated_rules),
            "approved_rules": len([r for r in self.generated_rules.values() if r.approved]),
            "total_variants_found": sum(p.variants_found for p in self.patterns.values()),
        }

    def confirm_variant(self, variant_id, is_true_positive, confirmed_by="user"):
        """确认变体结果"""
        from datetime import datetime
        # 更新统计
        for pattern in self.patterns.values():
            if is_true_positive:
                pattern.variants_found += 1
            else:
                pattern.false_positives = getattr(pattern, 'false_positives', 0) + 1
            break
        return {
            "variant_id": variant_id,
            "is_true_positive": is_true_positive,
            "confirmed_by": confirmed_by,
            "confirmed_at": datetime.now().isoformat(),
            "success": True,
        }


# ==================== 变体分析 API ====================

@app.post("/api/variant/confirm", tags=["变体分析"])
async def confirm_vulnerability(request: ConfirmVulnRequest):
    """确认漏洞并创建模式"""
    try:
        analyzer = get_variant_analyzer()
        pattern = analyzer.confirm_vulnerability(
            finding=request.finding,
            code_context=request.code_context,
            call_chain=request.call_chain,
        )
        return {
            "success": True,
            "pattern": pattern.to_dict(),
            "message": f"已创建漏洞模式: {pattern.id}"
        }
    except Exception as e:
        logger.error(f"Failed to confirm vulnerability: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/variant/search", tags=["变体分析"])
async def search_variants(request: SearchVariantsRequest):
    """搜索漏洞变体"""
    try:
        analyzer = get_variant_analyzer()
        variants = analyzer.search_variants(
            pattern_id=request.pattern_id,
            top_k=request.top_k,
            similarity_threshold=request.similarity_threshold,
            use_llm_verification=request.use_llm_verification,
        )
        return {
            "success": True,
            "variants": [v.to_dict() for v in variants],
            "total": len(variants),
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to search variants: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/variant/confirm-variant", tags=["变体分析"])
async def confirm_variant(request: ConfirmVariantRequest):
    """确认变体结果（真阳性/假阳性）"""
    try:
        analyzer = get_variant_analyzer()
        result = analyzer.confirm_variant(
            variant_id=request.variant_id,
            is_true_positive=request.is_true_positive,
            confirmed_by=request.confirmed_by,
        )
        return {
            "success": True,
            "result": result,
            "message": f"变体 {request.variant_id} 已确认为 {'真实漏洞' if request.is_true_positive else '误报'}"
        }
    except Exception as e:
        logger.error(f"Failed to confirm variant: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/variant/generate-rule", tags=["变体分析"])
async def generate_rule(request: GenerateRuleRequest):
    """从模式生成规则"""
    try:
        analyzer = get_variant_analyzer()
        rule = analyzer.generate_rule_from_pattern(
            pattern_id=request.pattern_id,
            rule_type=request.rule_type,
        )
        return {
            "success": True,
            "rule": rule.to_dict(),
            "message": f"已生成规则: {rule.id}"
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to generate rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/variant/patterns", tags=["变体分析"])
async def list_patterns():
    """获取所有漏洞模式"""
    analyzer = get_variant_analyzer()
    return {
        "success": True,
        "patterns": analyzer.list_patterns(),
    }


@app.get("/api/variant/patterns/{pattern_id}", tags=["变体分析"])
async def get_pattern(pattern_id: str):
    """获取模式详情"""
    analyzer = get_variant_analyzer()
    pattern = analyzer.get_pattern(pattern_id)
    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")
    return {
        "success": True,
        "pattern": pattern.to_dict(),
    }


@app.get("/api/variant/rules", tags=["变体分析"])
async def list_rules():
    """获取所有生成的规则"""
    analyzer = get_variant_analyzer()
    return {
        "success": True,
        "rules": analyzer.list_rules(),
    }


@app.get("/api/variant/rules/{rule_id}", tags=["变体分析"])
async def get_rule(rule_id: str):
    """获取规则详情"""
    analyzer = get_variant_analyzer()
    rule = analyzer.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {
        "success": True,
        "rule": rule.to_dict(),
    }


@app.post("/api/variant/rules/{rule_id}/approve", tags=["变体分析"])
async def approve_rule(rule_id: str):
    """批准规则"""
    analyzer = get_variant_analyzer()
    if analyzer.approve_rule(rule_id):
        return {"success": True, "message": "规则已批准"}
    raise HTTPException(status_code=404, detail="Rule not found")


@app.delete("/api/variant/rules/{rule_id}", tags=["变体分析"])
async def delete_rule(rule_id: str):
    """删除规则"""
    analyzer = get_variant_analyzer()
    if analyzer.delete_rule(rule_id):
        return {"success": True, "message": "规则已删除"}
    raise HTTPException(status_code=404, detail="Rule not found")


@app.get("/api/variant/stats", tags=["变体分析"])
async def get_variant_stats():
    """获取统计信息"""
    analyzer = get_variant_analyzer()
    return {
        "success": True,
        "stats": analyzer.get_stats(),
    }


# ==================== 代码图 API ====================

@app.post("/api/graph/build", tags=["代码图"])
async def build_code_graph(request: BuildGraphRequest):
    """构建代码属性图"""
    try:
        manager = get_graph_manager()
        graph = manager.build_graph(
            code=request.code,
            file_path=request.file_path,
            language=request.language,
        )
        return {
            "success": True,
            "graph": graph.to_dict(),
            "summary": graph.to_summary(),
        }
    except Exception as e:
        logger.error(f"Failed to build graph: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graph/list", tags=["代码图"])
async def list_graphs():
    """列出所有代码图"""
    manager = get_graph_manager()
    return {
        "success": True,
        "graphs": manager.list_graphs(),
    }


@app.get("/api/graph/{graph_id}", tags=["代码图"])
async def get_graph(graph_id: str):
    """获取代码图详情"""
    manager = get_graph_manager()
    graph = manager.get_graph(graph_id)
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")
    return {
        "success": True,
        "graph": graph.to_dict(),
    }


@app.get("/api/graph/{graph_id}/summary", tags=["代码图"])
async def get_graph_summary(graph_id: str):
    """获取代码图的 LLM 摘要"""
    manager = get_graph_manager()
    summary = manager.get_summary_for_llm(graph_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Graph not found")
    return {
        "success": True,
        "summary": summary,
    }


@app.get("/api/graph/{graph_id}/dot", tags=["代码图"])
async def get_graph_dot(graph_id: str):
    """获取 DOT 格式（用于 Graphviz 可视化）"""
    manager = get_graph_manager()
    dot = manager.export_to_dot(graph_id)
    if not dot:
        raise HTTPException(status_code=404, detail="Graph not found")
    return {
        "success": True,
        "dot": dot,
    }


@app.post("/api/graph/{graph_id}/data-flow", tags=["代码图"])
async def analyze_data_flow(graph_id: str, request: AnalyzeDataFlowRequest):
    """分析数据流路径"""
    manager = get_graph_manager()
    graph = manager.get_graph(graph_id)
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")

    paths = graph.get_data_flow_paths(
        source_id=request.source_node_id,
        sink_id=request.sink_node_id,
        max_depth=request.max_depth,
    )

    return {
        "success": True,
        "paths": paths,
        "total": len(paths),
    }


@app.get("/api/graph/{graph_id}/control-flow", tags=["代码图"])
async def get_control_flow_paths(
    graph_id: str,
    start_id: Optional[str] = None,
    end_id: Optional[str] = None,
    max_paths: int = 10,
):
    """获取控制流路径"""
    manager = get_graph_manager()
    graph = manager.get_graph(graph_id)
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")

    paths = graph.get_control_flow_paths(
        start_id=start_id,
        end_id=end_id,
        max_paths=max_paths,
    )

    return {
        "success": True,
        "paths": paths,
        "total": len(paths),
    }


@app.post("/api/graph/search-similar", tags=["代码图"])
async def search_similar_structures(request: SearchSimilarGraphRequest):
    """搜索相似结构的代码图"""
    manager = get_graph_manager()
    pattern_graph = manager.get_graph(request.graph_id)
    if not pattern_graph:
        raise HTTPException(status_code=404, detail="Graph not found")

    try:
        similarities = manager.search_similar_structures(pattern_graph, request.top_k)
        return {
            "success": True,
            "results": [
                {"graph_id": gid, "similarity": sim}
                for gid, sim in similarities
            ],
        }
    except Exception as e:
        logger.error(f"Failed to search similar structures: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 通用 API ====================

@app.get("/api/health", tags=["系统"])
async def health_check():
    """健康检查"""
    return {"status": "ok", "version": "1.0.0"}


@app.get("/api/stats", tags=["系统"])
async def get_system_stats():
    """获取系统统计"""
    analyzer = get_variant_analyzer()
    manager = get_graph_manager()

    return {
        "success": True,
        "variant_stats": analyzer.get_stats(),
        "graph_count": len(manager.list_graphs()),
    }


# ==================== 启动入口 ====================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

"""
变体分析模块 (Variant Analysis)

功能：
1. 确认漏洞后记录 embedding 特征
2. 在向量库中搜索相似调用模式
3. LLM 总结漏洞模式为规则
4. 自动生成泛化规则供未来扫描

类似 CodeQL 的 variant analysis 概念
"""

import json
import logging
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)


class PatternType(Enum):
    """漏洞模式类型"""
    DANGEROUS_CALL = "dangerous_call"          # 危险函数调用
    TAINT_FLOW = "taint_flow"                  # 污点数据流
    AUTH_BYPASS = "auth_bypass"                # 认证绕过
    ACCESS_CONTROL = "access_control"          # 访问控制缺陷
    BUSINESS_LOGIC = "business_logic"          # 业务逻辑漏洞
    DATA_EXPOSURE = "data_exposure"            # 数据泄露
    INJECTION = "injection"                    # 注入类漏洞
    CUSTOM = "custom"                          # 自定义模式


@dataclass
class VulnPattern:
    """漏洞模式定义"""
    id: str
    name: str
    pattern_type: PatternType
    description: str

    # 模式特征
    code_signature: str                        # 代码签名/摘要
    embedding_vector: Optional[List[float]] = None  # 嵌入向量

    # 结构化特征
    sink_functions: List[str] = field(default_factory=list)
    source_types: List[str] = field(default_factory=list)
    call_chain_pattern: List[str] = field(default_factory=list)

    # 规则 DSL
    rule_dsl: Optional[str] = None

    # 元数据
    severity: str = "medium"
    confidence: float = 0.8
    created_from_finding: Optional[str] = None
    created_at: str = ""

    # 统计
    variants_found: int = 0
    false_positives: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "pattern_type": self.pattern_type.value,
            "embedding_vector": None  # 不序列化大向量
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VulnPattern":
        data["pattern_type"] = PatternType(data.get("pattern_type", "custom"))
        return cls(**data)


@dataclass
class VariantMatch:
    """变体匹配结果"""
    id: str
    pattern_id: str
    file_path: str
    function_name: str
    line_start: int
    line_end: int
    code_snippet: str

    # 相似度
    similarity_score: float
    embedding_similarity: float
    structural_similarity: float

    # LLM 验证结果
    llm_verified: bool = False
    llm_confidence: float = 0.0
    llm_explanation: str = ""

    # 状态
    status: str = "pending"  # pending, confirmed, false_positive, ignored
    confirmed_by: Optional[str] = None
    confirmed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GeneratedRule:
    """自动生成的规则"""
    id: str
    name: str
    source_pattern_id: str

    # 规则内容
    rule_type: str  # "regex", "ast", "semantic", "llm"
    rule_content: Dict[str, Any] = field(default_factory=dict)

    # 自然语言描述
    description: str = ""
    detection_logic: str = ""

    # 适用范围
    languages: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)

    # 元数据
    auto_generated: bool = True
    approved: bool = False
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VariantAnalyzer:
    """变体分析器"""

    def __init__(
        self,
        vector_store,
        llm_client,
        embedding_client,
        patterns_dir: str = ".audit_data/patterns",
    ):
        self.vector_store = vector_store
        self.llm_client = llm_client
        self.embedding_client = embedding_client
        self.patterns_dir = Path(patterns_dir)
        self.patterns_dir.mkdir(parents=True, exist_ok=True)

        # 加载已有模式
        self.patterns: Dict[str, VulnPattern] = {}
        self.generated_rules: Dict[str, GeneratedRule] = {}
        self._load_patterns()

    def _load_patterns(self) -> None:
        """加载已保存的漏洞模式"""
        patterns_file = self.patterns_dir / "vuln_patterns.json"
        if patterns_file.exists():
            try:
                with open(patterns_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for p in data.get("patterns", []):
                        pattern = VulnPattern.from_dict(p)
                        self.patterns[pattern.id] = pattern
                logger.info(f"Loaded {len(self.patterns)} vulnerability patterns")
            except Exception as e:
                logger.warning(f"Failed to load patterns: {e}")

        rules_file = self.patterns_dir / "generated_rules.json"
        if rules_file.exists():
            try:
                with open(rules_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for r in data.get("rules", []):
                        rule = GeneratedRule(**r)
                        self.generated_rules[rule.id] = rule
                logger.info(f"Loaded {len(self.generated_rules)} generated rules")
            except Exception as e:
                logger.warning(f"Failed to load rules: {e}")

    def _save_patterns(self) -> None:
        """保存漏洞模式"""
        patterns_file = self.patterns_dir / "vuln_patterns.json"
        with open(patterns_file, "w", encoding="utf-8") as f:
            json.dump({
                "patterns": [p.to_dict() for p in self.patterns.values()],
                "saved_at": datetime.now().isoformat()
            }, f, ensure_ascii=False, indent=2)

        rules_file = self.patterns_dir / "generated_rules.json"
        with open(rules_file, "w", encoding="utf-8") as f:
            json.dump({
                "rules": [r.to_dict() for r in self.generated_rules.values()],
                "saved_at": datetime.now().isoformat()
            }, f, ensure_ascii=False, indent=2)

    def confirm_vulnerability(
        self,
        finding: Dict[str, Any],
        code_context: str,
        call_chain: Optional[List[str]] = None,
    ) -> VulnPattern:
        """确认漏洞并创建模式

        Args:
            finding: 漏洞发现结果
            code_context: 相关代码上下文
            call_chain: 调用链

        Returns:
            创建的漏洞模式
        """
        # 生成唯一ID
        pattern_id = f"PAT-{hashlib.md5(code_context.encode()).hexdigest()[:8]}"

        # 生成代码签名
        code_signature = self._generate_code_signature(code_context)

        # 生成 embedding
        embedding = self._generate_embedding(code_context)

        # 从 finding 提取信息
        pattern_type = self._infer_pattern_type(finding)

        pattern = VulnPattern(
            id=pattern_id,
            name=finding.get("issue_type", "Unknown Vulnerability"),
            pattern_type=pattern_type,
            description=finding.get("summary", ""),
            code_signature=code_signature,
            embedding_vector=embedding,
            sink_functions=finding.get("sinks", []),
            source_types=finding.get("sources", []),
            call_chain_pattern=call_chain or [],
            severity=finding.get("severity", "medium"),
            confidence=finding.get("confidence", 0.8),
            created_from_finding=finding.get("id"),
            created_at=datetime.now().isoformat(),
        )

        self.patterns[pattern_id] = pattern
        self._save_patterns()

        logger.info(f"Created vulnerability pattern: {pattern_id}")
        return pattern

    def _generate_code_signature(self, code: str) -> str:
        """生成代码签名（抽象化的代码摘要）"""
        # 简化代码：移除具体变量名，保留结构
        import re

        # 移除字符串字面量
        signature = re.sub(r'["\'][^"\']*["\']', '"STR"', code)
        # 移除数字
        signature = re.sub(r'\b\d+\b', 'NUM', signature)
        # 简化变量名
        signature = re.sub(r'\b[a-z_][a-z0-9_]*\b', 'VAR', signature, flags=re.IGNORECASE)
        # 压缩空白
        signature = ' '.join(signature.split())

        return signature[:500]  # 限制长度

    def _generate_embedding(self, code: str) -> List[float]:
        """生成代码嵌入向量"""
        try:
            embeddings = self.embedding_client.embed([code])
            return embeddings[0] if embeddings else []
        except Exception as e:
            logger.warning(f"Failed to generate embedding: {e}")
            return []

    def _infer_pattern_type(self, finding: Dict[str, Any]) -> PatternType:
        """从 finding 推断模式类型"""
        issue_type = finding.get("issue_type", "").lower()
        category = finding.get("category", "").lower()

        if "injection" in issue_type or "sqli" in issue_type or "xss" in issue_type:
            return PatternType.INJECTION
        elif "auth" in issue_type or "authentication" in category:
            return PatternType.AUTH_BYPASS
        elif "access" in issue_type or "authorization" in category or "idor" in issue_type:
            return PatternType.ACCESS_CONTROL
        elif "taint" in issue_type or "flow" in issue_type:
            return PatternType.TAINT_FLOW
        elif "business" in category or "logic" in issue_type:
            return PatternType.BUSINESS_LOGIC
        elif "exposure" in issue_type or "leak" in issue_type:
            return PatternType.DATA_EXPOSURE
        elif "dangerous" in issue_type or "sink" in issue_type:
            return PatternType.DANGEROUS_CALL
        else:
            return PatternType.CUSTOM

    def search_variants(
        self,
        pattern_id: str,
        top_k: int = 20,
        similarity_threshold: float = 0.75,
        use_llm_verification: bool = True,
    ) -> List[VariantMatch]:
        """搜索漏洞变体

        Args:
            pattern_id: 漏洞模式ID
            top_k: 返回最相似的K个结果
            similarity_threshold: 相似度阈值
            use_llm_verification: 是否使用LLM验证

        Returns:
            变体匹配列表
        """
        if pattern_id not in self.patterns:
            raise ValueError(f"Pattern not found: {pattern_id}")

        pattern = self.patterns[pattern_id]

        if not pattern.embedding_vector:
            logger.warning(f"Pattern {pattern_id} has no embedding vector")
            return []

        # 向量相似度搜索
        search_results = self.vector_store.search(
            query_vector=pattern.embedding_vector,
            top_k=top_k * 2,  # 搜索更多以便过滤
            filter_conditions={}
        )

        variants = []
        for result in search_results:
            if result.score < similarity_threshold:
                continue

            # 计算结构相似度
            structural_sim = self._calculate_structural_similarity(
                pattern.code_signature,
                result.metadata.get("code", "")
            )

            # 综合相似度
            combined_score = (result.score * 0.6) + (structural_sim * 0.4)

            if combined_score < similarity_threshold:
                continue

            variant = VariantMatch(
                id=f"VAR-{result.id[:8]}",
                pattern_id=pattern_id,
                file_path=result.metadata.get("file_path", ""),
                function_name=result.metadata.get("symbol", ""),
                line_start=result.metadata.get("line_start", 0),
                line_end=result.metadata.get("line_end", 0),
                code_snippet=result.metadata.get("code", "")[:500],
                similarity_score=combined_score,
                embedding_similarity=result.score,
                structural_similarity=structural_sim,
            )

            variants.append(variant)

        # 按相似度排序
        variants.sort(key=lambda x: x.similarity_score, reverse=True)
        variants = variants[:top_k]

        # LLM 验证
        if use_llm_verification and variants:
            variants = self._llm_verify_variants(pattern, variants)

        # 更新统计
        pattern.variants_found = len([v for v in variants if v.llm_confidence > 0.5])
        self._save_patterns()

        return variants

    def _calculate_structural_similarity(self, sig1: str, code2: str) -> float:
        """计算结构相似度"""
        sig2 = self._generate_code_signature(code2)

        # 简单的 Jaccard 相似度
        tokens1 = set(sig1.split())
        tokens2 = set(sig2.split())

        if not tokens1 or not tokens2:
            return 0.0

        intersection = tokens1 & tokens2
        union = tokens1 | tokens2

        return len(intersection) / len(union)

    def _llm_verify_variants(
        self,
        pattern: VulnPattern,
        variants: List[VariantMatch],
    ) -> List[VariantMatch]:
        """使用 LLM 验证变体"""
        try:
            from llm_client import ChatMessage
        except ImportError:
            logger.warning("llm_client module not available, skipping LLM verification")
            return variants

        system_prompt = """你是一名安全代码审计专家。你需要判断给定的代码片段是否与已知漏洞模式相似。

已知漏洞模式：
- 类型: {pattern_type}
- 描述: {description}
- 特征: {signature}

请分析代码片段，判断是否存在类似的安全问题。输出 JSON 格式：
{{
  "is_similar": boolean,
  "confidence": 0.0-1.0,
  "explanation": "简要说明"
}}"""

        for variant in variants:
            try:
                messages = [
                    ChatMessage(
                        role="system",
                        content=system_prompt.format(
                            pattern_type=pattern.pattern_type.value,
                            description=pattern.description,
                            signature=pattern.code_signature[:200]
                        )
                    ),
                    ChatMessage(
                        role="user",
                        content=f"请分析以下代码片段：\n\n```\n{variant.code_snippet}\n```"
                    )
                ]

                response = self.llm_client.chat_completion(
                    messages=messages,
                    temperature=0.1,
                    response_format={"type": "json_object"}
                )

                result = json.loads(response.content)
                variant.llm_verified = True
                variant.llm_confidence = result.get("confidence", 0.0)
                variant.llm_explanation = result.get("explanation", "")

            except Exception as e:
                logger.warning(f"LLM verification failed for {variant.id}: {e}")
                variant.llm_verified = False

        return variants

    def generate_rule_from_pattern(
        self,
        pattern_id: str,
        rule_type: str = "semantic",
    ) -> GeneratedRule:
        """从漏洞模式生成规则

        Args:
            pattern_id: 漏洞模式ID
            rule_type: 规则类型 (regex, ast, semantic, llm)

        Returns:
            生成的规则
        """
        if pattern_id not in self.patterns:
            raise ValueError(f"Pattern not found: {pattern_id}")

        pattern = self.patterns[pattern_id]

        # 使用 LLM 生成规则
        rule_content = self._llm_generate_rule(pattern, rule_type)

        rule_id = f"RULE-{hashlib.md5(pattern_id.encode()).hexdigest()[:8]}"

        rule = GeneratedRule(
            id=rule_id,
            name=f"Auto: {pattern.name}",
            source_pattern_id=pattern_id,
            rule_type=rule_type,
            rule_content=rule_content,
            description=pattern.description,
            detection_logic=rule_content.get("detection_logic", ""),
            languages=rule_content.get("languages", []),
            frameworks=rule_content.get("frameworks", []),
            auto_generated=True,
            approved=False,
            created_at=datetime.now().isoformat(),
        )

        self.generated_rules[rule_id] = rule
        self._save_patterns()

        logger.info(f"Generated rule: {rule_id}")
        return rule

    def _llm_generate_rule(
        self,
        pattern: VulnPattern,
        rule_type: str,
    ) -> Dict[str, Any]:
        """使用 LLM 生成规则内容"""
        try:
            from llm_client import ChatMessage
        except ImportError:
            logger.warning("llm_client module not available, returning default rule")
            return {
                "detection_logic": pattern.description,
                "patterns": [pattern.code_signature],
                "languages": [],
                "frameworks": [],
            }

        prompt = f"""基于以下漏洞模式，生成一条可复用的检测规则。

漏洞模式：
- 名称: {pattern.name}
- 类型: {pattern.pattern_type.value}
- 描述: {pattern.description}
- 危险函数: {pattern.sink_functions}
- 数据源: {pattern.source_types}
- 调用链: {pattern.call_chain_pattern}
- 代码特征: {pattern.code_signature[:300]}

请生成 {rule_type} 类型的规则，输出 JSON 格式：
{{
  "detection_logic": "检测逻辑的自然语言描述",
  "patterns": ["匹配模式1", "匹配模式2"],
  "anti_patterns": ["排除模式（非漏洞情况）"],
  "sink_patterns": ["危险函数匹配"],
  "source_patterns": ["输入源匹配"],
  "languages": ["适用语言"],
  "frameworks": ["适用框架"],
  "severity": "风险等级",
  "fix_suggestion": "修复建议"
}}"""

        try:
            messages = [
                ChatMessage(role="user", content=prompt)
            ]

            response = self.llm_client.chat_completion(
                messages=messages,
                temperature=0.2,
                response_format={"type": "json_object"}
            )

            return json.loads(response.content)

        except Exception as e:
            logger.warning(f"LLM rule generation failed: {e}")
            return {
                "detection_logic": pattern.description,
                "patterns": [pattern.code_signature],
                "languages": [],
                "frameworks": [],
            }

    def confirm_variant(
        self,
        variant_id: str,
        is_true_positive: bool,
        confirmed_by: str = "user",
    ) -> Dict[str, Any]:
        """确认变体结果

        Args:
            variant_id: 变体ID
            is_true_positive: 是否为真实漏洞
            confirmed_by: 确认者

        Returns:
            确认结果信息
        """
        # 解析 variant_id 获取相关的 pattern
        # variant_id 格式: VAR-{hash}
        result = {
            "variant_id": variant_id,
            "is_true_positive": is_true_positive,
            "confirmed_by": confirmed_by,
            "confirmed_at": datetime.now().isoformat(),
            "updated": False,
        }

        # 更新相关模式的统计数据
        for pattern in self.patterns.values():
            if is_true_positive:
                pattern.variants_found += 1
            else:
                pattern.false_positives += 1
            result["updated"] = True
            break  # 只更新第一个匹配的模式（实际应用中应该跟踪 variant 与 pattern 的关系）

        # 保存更新
        if result["updated"]:
            self._save_patterns()
            logger.info(f"Variant {variant_id} confirmed as {'true positive' if is_true_positive else 'false positive'} by {confirmed_by}")

        return result

    def get_pattern(self, pattern_id: str) -> Optional[VulnPattern]:
        """获取模式详情"""
        return self.patterns.get(pattern_id)

    def list_patterns(self) -> List[Dict[str, Any]]:
        """列出所有模式"""
        return [p.to_dict() for p in self.patterns.values()]

    def list_rules(self) -> List[Dict[str, Any]]:
        """列出所有生成的规则"""
        return [r.to_dict() for r in self.generated_rules.values()]

    def get_rule(self, rule_id: str) -> Optional[GeneratedRule]:
        """获取规则详情"""
        return self.generated_rules.get(rule_id)

    def approve_rule(self, rule_id: str) -> bool:
        """批准规则"""
        if rule_id in self.generated_rules:
            self.generated_rules[rule_id].approved = True
            self._save_patterns()
            return True
        return False

    def delete_rule(self, rule_id: str) -> bool:
        """删除规则"""
        if rule_id in self.generated_rules:
            del self.generated_rules[rule_id]
            self._save_patterns()
            return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        total_variants = sum(p.variants_found for p in self.patterns.values())
        total_fps = sum(p.false_positives for p in self.patterns.values())

        return {
            "total_patterns": len(self.patterns),
            "total_rules": len(self.generated_rules),
            "approved_rules": len([r for r in self.generated_rules.values() if r.approved]),
            "total_variants_found": total_variants,
            "total_false_positives": total_fps,
            "patterns_by_type": self._count_by_type(),
        }

    def _count_by_type(self) -> Dict[str, int]:
        """按类型统计模式"""
        counts = {}
        for p in self.patterns.values():
            t = p.pattern_type.value
            counts[t] = counts.get(t, 0) + 1
        return counts

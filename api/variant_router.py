"""
Variant Analysis API Router (Experimental)
Provides API endpoints for vulnerability variant analysis and pattern management.

WARNING: 当前为实验性实现，使用内存存储，服务重启后数据丢失。
不应在生产环境中依赖此模块的数据持久性。
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/variant", tags=["variant-experimental"])

# In-memory storage - 实验性实现，重启后数据丢失
# TODO: 迁移到 SQLite 持久化存储
_patterns_store: Dict[str, Dict[str, Any]] = {}
_variants_store: Dict[str, Dict[str, Any]] = {}
_rules_store: Dict[str, Dict[str, Any]] = {}

_EXPERIMENTAL_WARNING = (
    "This endpoint is experimental. Data is stored in-memory and will be lost on restart."
)


# ============ Pydantic Models ============

class FindingData(BaseModel):
    """Vulnerability finding data."""
    issue_type: str = Field(default="rce", description="Type of vulnerability")
    severity: str = Field(default="high", description="Severity level")
    summary: str = Field(default="", description="Summary description")


class ConfirmVulnerabilityRequest(BaseModel):
    """Request to confirm a vulnerability and create a pattern."""
    finding_id: str = Field(..., description="Finding ID")
    finding: FindingData = Field(..., description="Finding data")
    code_context: str = Field(..., description="Related code context")


class SearchVariantsRequest(BaseModel):
    """Request to search for vulnerability variants."""
    pattern_id: str = Field(..., description="Pattern ID to search for variants")
    top_k: int = Field(default=20, description="Maximum results to return")
    similarity_threshold: float = Field(default=0.75, description="Minimum similarity threshold")
    use_llm_verification: bool = Field(default=True, description="Use LLM to verify variants")


class ConfirmVariantRequest(BaseModel):
    """Request to confirm a variant."""
    variant_id: str = Field(..., description="Variant ID")
    is_true_positive: bool = Field(..., description="Whether variant is a true positive")
    confirmed_by: str = Field(default="user", description="Who confirmed")


class GenerateRuleRequest(BaseModel):
    """Request to generate a detection rule."""
    pattern_id: str = Field(..., description="Pattern ID to generate rule from")
    rule_type: str = Field(default="semantic", description="Type of rule to generate")


# ============ Helper Functions ============

def _generate_id() -> str:
    """Generate a unique ID."""
    return str(uuid.uuid4())[:8]


def _extract_pattern_from_code(code: str, issue_type: str) -> Dict[str, Any]:
    """
    Extract a vulnerability pattern from code.
    In production, this would use more sophisticated analysis.
    """
    # Simple pattern extraction based on common vulnerability patterns
    patterns = {
        "rce": ["exec", "eval", "system", "subprocess", "os.popen"],
        "sqli": ["execute", "raw", "query", "cursor", "SELECT", "INSERT", "UPDATE", "DELETE"],
        "xss": ["innerHTML", "document.write", "outerHTML", "insertAdjacentHTML"],
        "ssrf": ["requests.get", "urllib", "httplib", "curl", "file_get_contents"],
        "path_traversal": ["open(", "read(", "write(", "os.path", "pathlib"],
        "deserialization": ["pickle", "yaml.load", "unserialize", "Marshal", "json.loads"],
    }

    # Find matching patterns in code
    matched_patterns = []
    keywords = patterns.get(issue_type, [])
    for keyword in keywords:
        if keyword.lower() in code.lower():
            matched_patterns.append(keyword)

    # Extract potential sink functions
    sinks = []
    lines = code.split('\n')
    for i, line in enumerate(lines):
        for pattern in matched_patterns:
            if pattern.lower() in line.lower():
                sinks.append({
                    "line": i + 1,
                    "pattern": pattern,
                    "code": line.strip()
                })

    return {
        "keywords": matched_patterns,
        "sinks": sinks,
        "code_signature": code[:200] if len(code) > 200 else code,
    }


def _calculate_similarity(code1: str, code2: str) -> float:
    """
    Calculate similarity between two code snippets.
    In production, use embedding-based similarity.
    """
    # Simple token-based similarity
    tokens1 = set(code1.lower().split())
    tokens2 = set(code2.lower().split())

    if not tokens1 or not tokens2:
        return 0.0

    intersection = tokens1.intersection(tokens2)
    union = tokens1.union(tokens2)

    return len(intersection) / len(union) if union else 0.0


def _generate_mock_variants(pattern: Dict[str, Any], config: SearchVariantsRequest) -> List[Dict[str, Any]]:
    """
    Generate mock variants for demonstration.
    In production, this would search the indexed codebase.
    """
    variants = []
    issue_type = pattern.get("issue_type", "rce")

    # Mock variant templates based on issue type
    variant_templates = {
        "rce": [
            {
                "function_name": "run_command",
                "file_path": "utils/shell.py",
                "line_start": 42,
                "line_end": 48,
                "code_snippet": "def run_command(cmd):\n    import os\n    return os.system(cmd)",
                "similarity_score": 0.85,
            },
            {
                "function_name": "execute_script",
                "file_path": "handlers/admin.py",
                "line_start": 156,
                "line_end": 162,
                "code_snippet": "def execute_script(script_path):\n    import subprocess\n    subprocess.run(script_path, shell=True)",
                "similarity_score": 0.78,
            },
        ],
        "sqli": [
            {
                "function_name": "get_user_by_id",
                "file_path": "models/user.py",
                "line_start": 23,
                "line_end": 28,
                "code_snippet": "def get_user_by_id(user_id):\n    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n    return db.execute(query)",
                "similarity_score": 0.92,
            },
            {
                "function_name": "search_products",
                "file_path": "api/products.py",
                "line_start": 67,
                "line_end": 73,
                "code_snippet": "def search_products(name):\n    sql = \"SELECT * FROM products WHERE name LIKE '%\" + name + \"%'\"\n    return cursor.execute(sql)",
                "similarity_score": 0.81,
            },
        ],
    }

    templates = variant_templates.get(issue_type, variant_templates["rce"])

    for template in templates:
        if template["similarity_score"] >= config.similarity_threshold:
            variant = {
                "id": f"V-{_generate_id()}",
                "pattern_id": pattern["id"],
                **template,
                "llm_verified": config.use_llm_verification,
                "llm_confidence": 0.85 if config.use_llm_verification else None,
                "llm_explanation": f"This code follows a similar vulnerable pattern: user input flows into {issue_type.upper()} sink without proper sanitization." if config.use_llm_verification else None,
                "status": "pending",
                "created_at": datetime.now().isoformat(),
            }
            variants.append(variant)

    return variants[:config.top_k]


def _generate_rule_content(pattern: Dict[str, Any], rule_type: str) -> Dict[str, Any]:
    """Generate rule content based on pattern and type."""
    issue_type = pattern.get("issue_type", "rce")
    pattern_data = pattern.get("pattern_data", {})
    keywords = pattern_data.get("keywords", [])

    if rule_type == "semantic":
        return {
            "type": "semantic",
            "description": f"Detect {issue_type.upper()} vulnerability patterns",
            "query": f"Find code where user input flows to {', '.join(keywords) if keywords else issue_type} without sanitization",
            "confidence_threshold": 0.75,
        }
    elif rule_type == "regex":
        patterns_str = "|".join(keywords) if keywords else issue_type
        return {
            "type": "regex",
            "patterns": [
                f"({patterns_str})\\s*\\(",
                f"\\$_[A-Z]+\\[.*\\].*({patterns_str})",
            ],
            "exclude_patterns": [
                "# nosec",
                "# safe:",
            ],
        }
    else:  # ast
        return {
            "type": "ast",
            "node_types": ["Call", "FunctionDef"],
            "target_functions": keywords if keywords else [issue_type],
            "taint_sources": ["request", "input", "user_input", "$_GET", "$_POST"],
            "require_sanitization": True,
        }


# ============ API Endpoints ============

@router.get("/patterns")
async def list_patterns():
    """List all confirmed vulnerability patterns."""
    patterns_list = []
    for pattern_id, pattern in _patterns_store.items():
        patterns_list.append({
            "id": pattern_id,
            "name": pattern.get("name", "Unnamed Pattern"),
            "issue_type": pattern.get("issue_type", "unknown"),
            "severity": pattern.get("severity", "medium"),
            "variants_found": pattern.get("variants_found", 0),
            "created_at": pattern.get("created_at", ""),
        })

    return {"success": True, "patterns": patterns_list}


@router.get("/stats")
async def get_stats():
    """Get variant analysis statistics."""
    total_variants = sum(p.get("variants_found", 0) for p in _patterns_store.values())

    return {
        "success": True,
        "stats": {
            "total_patterns": len(_patterns_store),
            "total_variants_found": total_variants,
            "confirmed_variants": len([v for v in _variants_store.values() if v.get("status") == "confirmed"]),
            "false_positives": len([v for v in _variants_store.values() if v.get("status") == "false_positive"]),
            "rules_generated": len(_rules_store),
        }
    }


@router.post("/confirm")
async def confirm_vulnerability(request: ConfirmVulnerabilityRequest):
    """Confirm a vulnerability and create a pattern for variant search."""
    if not request.code_context.strip():
        raise HTTPException(status_code=400, detail="Code context cannot be empty")

    # Extract pattern from code
    pattern_data = _extract_pattern_from_code(
        request.code_context,
        request.finding.issue_type
    )

    # Create pattern
    pattern_id = f"P-{_generate_id()}"
    pattern = {
        "id": pattern_id,
        "name": f"{request.finding.issue_type.upper()} Pattern",
        "issue_type": request.finding.issue_type,
        "severity": request.finding.severity,
        "summary": request.finding.summary,
        "code_context": request.code_context,
        "pattern_data": pattern_data,
        "variants_found": 0,
        "created_at": datetime.now().isoformat(),
        "finding_id": request.finding_id,
    }

    _patterns_store[pattern_id] = pattern

    return {
        "success": True,
        "pattern": pattern,
        "message": f"Pattern {pattern_id} created successfully"
    }


@router.post("/search")
async def search_variants(request: SearchVariantsRequest):
    """Search for vulnerability variants based on a pattern."""
    if request.pattern_id not in _patterns_store:
        raise HTTPException(status_code=404, detail="Pattern not found")

    pattern = _patterns_store[request.pattern_id]

    # Generate variants (mock for now)
    variants = _generate_mock_variants(pattern, request)

    # Store variants
    for variant in variants:
        _variants_store[variant["id"]] = variant

    # Update pattern stats
    pattern["variants_found"] = len(variants)

    return {
        "success": True,
        "variants": variants,
        "count": len(variants)
    }


@router.post("/confirm-variant")
async def confirm_variant(request: ConfirmVariantRequest):
    """Confirm or reject a variant."""
    if request.variant_id not in _variants_store:
        raise HTTPException(status_code=404, detail="Variant not found")

    variant = _variants_store[request.variant_id]
    variant["status"] = "confirmed" if request.is_true_positive else "false_positive"
    variant["confirmed_by"] = request.confirmed_by
    variant["confirmed_at"] = datetime.now().isoformat()

    return {
        "success": True,
        "variant": variant,
        "message": f"Variant marked as {'confirmed' if request.is_true_positive else 'false positive'}"
    }


@router.post("/generate-rule")
async def generate_rule(request: GenerateRuleRequest):
    """Generate a detection rule from a pattern."""
    if request.pattern_id not in _patterns_store:
        raise HTTPException(status_code=404, detail="Pattern not found")

    pattern = _patterns_store[request.pattern_id]

    # Generate rule content
    rule_content = _generate_rule_content(pattern, request.rule_type)

    # Create rule
    rule_id = f"R-{_generate_id()}"
    rule = {
        "id": rule_id,
        "name": f"{pattern.get('issue_type', 'unknown').upper()} Detection Rule",
        "pattern_id": request.pattern_id,
        "rule_type": request.rule_type,
        "rule_content": rule_content,
        "detection_logic": f"Detects {pattern.get('issue_type', 'vulnerability')} patterns based on confirmed vulnerability {request.pattern_id}",
        "languages": ["python", "php", "javascript"],
        "frameworks": [],
        "approved": False,
        "created_at": datetime.now().isoformat(),
    }

    _rules_store[rule_id] = rule

    return {
        "success": True,
        "rule": rule,
        "message": f"Rule {rule_id} generated successfully"
    }


@router.post("/rules/{rule_id}/approve")
async def approve_rule(rule_id: str):
    """Approve a generated rule."""
    if rule_id not in _rules_store:
        raise HTTPException(status_code=404, detail="Rule not found")

    rule = _rules_store[rule_id]
    rule["approved"] = True
    rule["approved_at"] = datetime.now().isoformat()

    return {
        "success": True,
        "rule": rule,
        "message": "Rule approved"
    }


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str):
    """Delete a rule."""
    if rule_id not in _rules_store:
        raise HTTPException(status_code=404, detail="Rule not found")

    del _rules_store[rule_id]

    return {
        "success": True,
        "message": f"Rule {rule_id} deleted"
    }


@router.delete("/patterns/{pattern_id}")
async def delete_pattern(pattern_id: str):
    """Delete a pattern and its associated variants."""
    if pattern_id not in _patterns_store:
        raise HTTPException(status_code=404, detail="Pattern not found")

    # Delete associated variants
    variants_to_delete = [
        vid for vid, v in _variants_store.items()
        if v.get("pattern_id") == pattern_id
    ]
    for vid in variants_to_delete:
        del _variants_store[vid]

    # Delete pattern
    del _patterns_store[pattern_id]

    return {
        "success": True,
        "message": f"Pattern {pattern_id} and {len(variants_to_delete)} variants deleted"
    }

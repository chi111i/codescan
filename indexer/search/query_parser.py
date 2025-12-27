"""Query parser for hybrid search

Parses search queries with modifier syntax:
- `path:*.py` - Include files matching pattern
- `-path:tests` - Exclude files matching pattern
- `lang:python` - Filter by language
- `type:function` - Filter by artifact type
- `severity:high` - Filter by security severity
- `keyword:exec` - Explicit keyword search

Example:
    query = "SQL injection path:*.py -path:tests lang:python"
    parser = QueryParser()
    parsed = parser.parse(query)
    # parsed.text == "SQL injection"
    # parsed.filters == {"path": ["*.py"], "lang": ["python"]}
    # parsed.exclusions == {"path": ["tests"]}
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum


class ModifierType(Enum):
    PATH = "path"
    LANG = "lang"
    TYPE = "type"
    SEVERITY = "severity"
    KEYWORD = "keyword"
    FILE = "file"
    SYMBOL = "symbol"


@dataclass
class ParsedQuery:
    """Result of parsing a search query"""
    text: str
    filters: Dict[str, List[str]] = field(default_factory=dict)
    exclusions: Dict[str, List[str]] = field(default_factory=dict)
    keywords: List[str] = field(default_factory=list)
    is_empty: bool = False

    def has_filter(self, key: str) -> bool:
        return key in self.filters and len(self.filters[key]) > 0

    def has_exclusion(self, key: str) -> bool:
        return key in self.exclusions and len(self.exclusions[key]) > 0

    def get_filter(self, key: str) -> List[str]:
        return self.filters.get(key, [])

    def get_exclusion(self, key: str) -> List[str]:
        return self.exclusions.get(key, [])

    def to_metadata_filter(self) -> Optional[Dict]:
        """Convert filters to vector store metadata filter format"""
        if not self.filters:
            return None

        result = {}

        if self.has_filter("path"):
            patterns = self.get_filter("path")
            if len(patterns) == 1:
                result["file_path"] = patterns[0]
            else:
                result["file_path"] = patterns

        if self.has_filter("lang"):
            langs = self.get_filter("lang")
            if len(langs) == 1:
                result["language"] = langs[0]
            else:
                result["language"] = langs

        if self.has_filter("type"):
            types = self.get_filter("type")
            if len(types) == 1:
                result["artifact_type"] = types[0]
            else:
                result["artifact_type"] = types

        return result if result else None


class QueryParser:
    """Parse search queries with modifier syntax

    Supports modifiers:
    - path: / -path: - file path patterns
    - lang: - language filter
    - type: - artifact type (function, class, method, etc)
    - severity: - security severity
    - keyword: - explicit keyword
    - file: - exact file match
    - symbol: - symbol name match
    """

    MODIFIER_PATTERN = re.compile(
        r'(-?)(\w+):([^\s]+|"[^"]*")',
        re.UNICODE
    )

    VALID_MODIFIERS: Set[str] = {
        "path", "lang", "language", "type", "severity",
        "keyword", "file", "symbol", "ext"
    }

    MODIFIER_ALIASES = {
        "language": "lang",
        "ext": "path",
    }

    def __init__(self, default_keywords: List[str] = None):
        self.default_keywords = default_keywords or []

    def parse(self, query: str) -> ParsedQuery:
        """Parse a search query into structured components

        Args:
            query: Raw search query string

        Returns:
            ParsedQuery with extracted filters, exclusions, and text
        """
        if not query or not query.strip():
            return ParsedQuery(text="", is_empty=True)

        query = query.strip()
        filters: Dict[str, List[str]] = {}
        exclusions: Dict[str, List[str]] = {}
        keywords: List[str] = []

        remaining_text = query

        for match in self.MODIFIER_PATTERN.finditer(query):
            is_exclusion = match.group(1) == "-"
            modifier = match.group(2).lower()
            value = match.group(3).strip('"')

            if modifier not in self.VALID_MODIFIERS:
                continue

            modifier = self.MODIFIER_ALIASES.get(modifier, modifier)
            remaining_text = remaining_text.replace(match.group(0), "", 1)

            if modifier == "keyword":
                keywords.append(value)
            elif is_exclusion:
                if modifier not in exclusions:
                    exclusions[modifier] = []
                exclusions[modifier].append(value)
            else:
                if modifier not in filters:
                    filters[modifier] = []
                filters[modifier].append(value)

        text = " ".join(remaining_text.split())

        extracted_keywords = self._extract_keywords(text)
        keywords.extend(extracted_keywords)
        keywords = list(set(keywords))

        return ParsedQuery(
            text=text,
            filters=filters,
            exclusions=exclusions,
            keywords=keywords,
            is_empty=not text and not filters
        )

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract potential security keywords from text"""
        if not text:
            return []

        words = re.findall(r'\b\w+\b', text.lower())

        security_keywords = {
            "sql", "injection", "xss", "rce", "ssrf", "csrf",
            "auth", "authentication", "authorization", "login",
            "password", "token", "session", "cookie",
            "exec", "eval", "system", "shell", "command",
            "file", "read", "write", "upload", "download",
            "serialize", "deserialize", "pickle", "yaml",
            "admin", "delete", "update", "create",
            "payment", "money", "transfer", "balance",
            "privilege", "permission", "role", "access",
        }

        found = [w for w in words if w in security_keywords]
        return found

    def normalize_path_pattern(self, pattern: str) -> str:
        """Normalize path pattern for matching

        - Convert glob patterns to regex
        - Handle both forward and backslashes
        """
        pattern = pattern.replace("\\", "/")

        if pattern.startswith("**/"):
            pass
        elif "*" not in pattern and "/" not in pattern:
            pattern = f"**/{pattern}"

        return pattern

    def build_file_filter(self, parsed: ParsedQuery) -> Optional[callable]:
        """Build a filter function for file paths

        Args:
            parsed: Parsed query

        Returns:
            Filter function or None if no path filters
        """
        include_patterns = parsed.get_filter("path")
        exclude_patterns = parsed.get_exclusion("path")

        if not include_patterns and not exclude_patterns:
            return None

        import fnmatch

        include_patterns = [self.normalize_path_pattern(p) for p in include_patterns]
        exclude_patterns = [self.normalize_path_pattern(p) for p in exclude_patterns]

        def filter_func(file_path: str) -> bool:
            normalized = file_path.replace("\\", "/")

            for pattern in exclude_patterns:
                if fnmatch.fnmatch(normalized, pattern):
                    return False
                if pattern in normalized:
                    return False

            if not include_patterns:
                return True

            for pattern in include_patterns:
                if fnmatch.fnmatch(normalized, pattern):
                    return True

            return False

        return filter_func


def parse_query(query: str) -> ParsedQuery:
    """Convenience function for parsing queries"""
    return QueryParser().parse(query)

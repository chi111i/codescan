# CodeScan overview
- Purpose: LLM-driven code security audit tool to find logic and permission vulnerabilities, using vector search, taint analysis, and LLM-driven reasoning.
- Stack: Python backend (FastAPI APIs, asyncio), frontend Vue 3, uses Qdrant for vector store; CLI entry via start.py/cli.
- Structure: api (FastAPI endpoints/router), agent (LLM agent logic), analyzer/indexer/rules for scanning, frontend for UI, utils/helpers, tests under repo root.
- Key flows: start services via start.py, CLI via __main__.py; WebSocket streaming under api/agent_router.py; LLM client in llm_client/.
- Notes: defaults use Chinese-language prompts/messages; history compression and streaming enabled by config in UnifiedAgentConfig.
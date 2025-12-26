# Style and conventions
- Python backend uses async FastAPI routes; keep async/await correctness.
- Dataclasses and Pydantic schemas used; prefer json-safe serialization via `serialization.to_jsonable`/`safe_json_dumps`.
- Logging with `logger` in modules; avoid non-ASCII unless existing Chinese log messages (already present).
- Agent config in `UnifiedAgentConfig` with history compression, streaming; preserve context-window limits when modifying conversation management.
- Frontend stack: Vue 3, Pinia; follow existing components/layout if editing.
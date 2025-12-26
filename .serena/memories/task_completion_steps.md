# Task completion checklist
- Run relevant tests (pytest from repo root) when code changes allow; verify CLI/API where applicable.
- For backend changes, consider starting API via `python start.py api` or running targeted modules if feasible.
- Ensure serialization uses `to_jsonable`/`safe_json_dumps` for outputs; avoid breaking WebSocket streaming contracts.
- Update documentation or comments if behavior changes; keep ASCII unless existing Chinese context requires.
- Review conversation/history limits in agent logic to avoid context bloat or stale state after clear/restore operations.
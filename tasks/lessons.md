# Lessons

- Validate against the library's own model (e.g. `mcp_types` `SERVER_RESULTS`), never a hand-rolled copy of one of its rules.
- FastMCP's in-memory `Client` skips wire-model validation; MCP catalog changes need a real-transport or wire-model check.
- Build and run container targets end to end before calling a deployment task done.
- Verify dependency refreshes on the oldest supported Python before committing; asyncio timeout exception types differ before Python 3.11.

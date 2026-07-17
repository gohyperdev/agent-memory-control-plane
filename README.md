# AMCP — Agent Memory Control Plane

AMCP manages configuration, guidance, memory, and session state for coding agents across hosts.

The current implementation slice is macOS-first and Codex-first:

- `amcp-agent` is a separate local process that owns native provider-state access.
- `amcp-controller` is the central collector with SQLite/FTS5 storage and scoped search.
- The Agent and Controller communicate over an authenticated JSONL protocol on a Unix socket.
- Native provider state remains authoritative; AMCP stores normalized, redacted observations and evidence.

## Run the first vertical slice

```bash
cargo test
cargo build --bins
cargo run -p amcp-controller -- run-once --json
cargo run -p amcp-controller -- search --db "$HOME/Library/Application Support/AMCP/controller.sqlite" "AGENTS"
```

Use `--codex-home` to point the Agent at a fixture or alternate Codex home. For a deterministic local run:

```bash
cargo run -p amcp-controller -- run-once \
  --codex-home fixtures/codex \
  --db /tmp/amcp-fixture.sqlite \
  --socket /tmp/amcp-fixture.sock \
  --query Project \
  --json
```

The first slice is read-only and does not read credentials or apply file changes. Session and memory files are currently collected as metadata-only evidence; configuration and instruction files are redacted before persistence.

See [PLAN-IMPLEMENTACJI.md](PLAN-IMPLEMENTACJI.md) for the full implementation roadmap.

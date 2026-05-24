# Dashboard

`gruff-rs dashboard` serves a local browser dashboard for repeated analysis.

## Start

```sh
cargo run -- dashboard --host 127.0.0.1 --port 8766 --project-root .
```

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Bind host. |
| `--port` | `8766` | Bind port. |
| `--project-root` | current directory | Initial project root. |

## Safety

The dashboard has no authentication and should stay bound to loopback unless the
network is trusted. Treat the bind address as the safety boundary.

## Polyglot Repos

`gruff-rs` defaults to port `8766`, while Go, PHP, and Python default to
`8765`, and TypeScript defaults to `8767`. Use `--port` when running multiple
dashboards at once.

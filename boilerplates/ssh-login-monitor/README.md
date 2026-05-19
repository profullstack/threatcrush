# ThreatCrush Module — SSH Login Monitor

A ThreatCrush security module that monitors SSH authentication logs for
suspicious login activity and emits `ThreatEvent`s for brute-force detection.

## What it does

- Tails `/var/log/auth.log` (configurable) for SSH events
- Detects failed login attempts and successful logins
- Emits `high`/`critical` severity events when brute-force patterns are detected
  (configurable threshold)
- Emits `info` events for successful SSH logins (useful for audit trails)
- Persists file offset via `ctx.setState` to avoid re-processing on restart

## Configuration

In `mod.toml`:

```toml
[module.config.defaults]
auth_log_path = "/var/log/auth.log"
failed_threshold = 5
poll_interval_seconds = 30
```

- `auth_log_path` — path to the sshd auth log
- `failed_threshold` — number of failed attempts from a single IP in one poll
  cycle before escalating to `high` severity
- `poll_interval_seconds` — how often to check for new log entries

## Install

```bash
git clone https://github.com/pxivory-max/threatcrush-ssh-monitor
cd threatcrush-ssh-monitor
pnpm install
pnpm build
```

## License

MIT

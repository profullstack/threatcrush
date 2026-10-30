#!/usr/bin/env python3
"""Run from a private, flock-protected cron entry every minute.

Uses the worker key from the existing app.env in memory. No credentials in
process arguments/logs. The application owns durable job claims and quota gates.
"""
import json
import time
import urllib.request
from pathlib import Path


def tick():
    env = Path('/home/anthony/www/threatcrush.com/app.env')
    key = next((line.split('=', 1)[1].strip().strip('"').strip("'") for line in env.read_text().splitlines() if line.startswith('GITHUB_MONITOR_WORKER_KEY=')), None)
    if not key:
        raise RuntimeError('Monitoring worker key is not configured')
    started = time.monotonic()
    for _ in range(10):
        request = urllib.request.Request('http://127.0.0.1:3270/api/github/monitoring/worker', method='POST', data=b'', headers={'Authorization': 'Bearer ' + key})
        with urllib.request.urlopen(request, timeout=840) as response:
            result = json.load(response)
        # Only these aggregate fields are logged, never response errors/tokens.
        print(json.dumps({k: result[k] for k in ('status', 'counts', 'truncated') if k in result}), flush=True)
        if result.get('status') == 'idle' or time.monotonic() - started > 50:
            break


if __name__ == '__main__':
    try:
        tick()
    except Exception:
        print('GitHub monitoring tick failed; queued work is retained', flush=True)
        raise SystemExit(1)

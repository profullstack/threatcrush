/**
 * SSH Login Monitor Module — ThreatCrush module.
 *
 * Tails /var/log/auth.log (configurable) for SSH login events, parses
 * failed and successful attempts, and emits ThreatEvents when suspicious
 * activity is detected (e.g., brute-force patterns, logins from new IPs).
 */

import { readFile, stat } from 'node:fs/promises';
import type {
  ThreatCrushModule,
  ModuleContext,
  ThreatEvent,
  EventSeverity,
} from '@threatcrush/sdk';

interface LoginAttempt {
  timestamp: string;
  user: string;
  ip: string;
  success: boolean;
  method?: string;
}

export default class SshLoginMonitorModule implements ThreatCrushModule {
  name = 'ssh-login-monitor';
  version = '0.1.0';
  description = 'Monitors SSH auth logs for failed/suspicious login attempts';

  private ctx!: ModuleContext;
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  async init(ctx: ModuleContext): Promise<void> {
    this.ctx = ctx;
    this.ctx.logger.info('[%s] initialized', this.name);
  }

  async start(): Promise<void> {
    const intervalSec =
      (this.ctx.config.poll_interval_seconds as number | undefined) ?? 30;
    this.ctx.logger.info(
      '[%s] starting auth log monitor (every %ds)',
      this.name,
      intervalSec,
    );
    this.running = true;
    void this.tick();
    this.timer = setInterval(() => void this.tick(), intervalSec * 1000);
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.ctx.logger.info('[%s] stopped', this.name);
  }

  private async tick(): Promise<void> {
    if (!this.running) return;

    const logPath =
      (this.ctx.config.auth_log_path as string | undefined) ??
      '/var/log/auth.log';

    let fileSize: number;
    try {
      const s = await stat(logPath);
      fileSize = s.size;
    } catch (err) {
      this.ctx.logger.error('[%s] cannot stat %s: %s', this.name, logPath, String(err));
      return;
    }

    const lastOffset = (this.ctx.getState('last_offset') as number) ?? 0;

    // If file was rotated (smaller than last offset), reset
    const readFrom = fileSize < lastOffset ? 0 : lastOffset;

    if (readFrom >= fileSize) return; // no new data

    let content: string;
    try {
      const buf = await readFile(logPath, { encoding: 'utf8' });
      content = buf.slice(readFrom);
    } catch (err) {
      this.ctx.logger.error('[%s] read error: %s', this.name, String(err));
      return;
    }

    const attempts = this.parseAuthLog(content);
    const failedByIp = new Map<string, number>();

    const threshold =
      (this.ctx.config.failed_threshold as number | undefined) ?? 5;

    for (const attempt of attempts) {
      if (!attempt.success) {
        const count = (failedByIp.get(attempt.ip) ?? 0) + 1;
        failedByIp.set(attempt.ip, count);
      }

      // Emit individual events for successful logins (potential compromise)
      if (attempt.success) {
        const event: ThreatEvent = {
          timestamp: new Date(),
          module: this.name,
          category: 'auth',
          severity: 'info',
          message: `SSH login success: ${attempt.user}@${attempt.ip}`,
          details: {
            user: attempt.user,
            ip: attempt.ip,
            method: attempt.method,
          },
        };
        this.ctx.emit(event);
      }
    }

    // Emit high-severity events for brute-force patterns
    for (const [ip, count] of failedByIp) {
      if (count >= threshold) {
        const severity: EventSeverity = count >= threshold * 2 ? 'critical' : 'high';
        const event: ThreatEvent = {
          timestamp: new Date(),
          module: this.name,
          category: 'auth',
          severity,
          message: `SSH brute-force detected: ${count} failed attempts from ${ip}`,
          details: {
            ip,
            failed_count: count,
            threshold,
          },
        };
        this.ctx.emit(event);
      }
    }

    this.ctx.setState('last_offset', fileSize);
    this.ctx.logger.info(
      '[%s] processed %d bytes, found %d attempts',
      this.name,
      fileSize - readFrom,
      attempts.length,
    );
  }

  private parseAuthLog(content: string): LoginAttempt[] {
    const attempts: LoginAttempt[] = [];

    for (const line of content.split('\n')) {
      // Failed password
      const failedMatch = line.match(
        /^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from ([\d.]+)/,
      );
      if (failedMatch) {
        attempts.push({
          timestamp: failedMatch[1],
          user: failedMatch[2],
          ip: failedMatch[3],
          success: false,
        });
        continue;
      }

      // Accepted login
      const acceptMatch = line.match(
        /^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted (\S+) for (\S+) from ([\d.]+)/,
      );
      if (acceptMatch) {
        attempts.push({
          timestamp: acceptMatch[1],
          user: acceptMatch[3],
          ip: acceptMatch[4],
          success: true,
          method: acceptMatch[2],
        });
        continue;
      }
    }

    return attempts;
  }
}

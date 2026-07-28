/**
 * spend-guard — detect and contain balance-drain attacks on metered
 * third-party services.
 *
 * Implements PRD 0001. Motivated by an SMS-pumping (IRSF) campaign against
 * qrypt.chat that cost ~$194 across three waves, the largest of which ran for
 * two days and went unnoticed for a month. Nothing in ThreatCrush could see it:
 * there was no port scan, no failed login and no malicious payload — the
 * attacker used a public signup form exactly as designed, and the loss landed
 * at a third party the server never talks to.
 *
 * Scope of this release is Detect and Report. Containment is limited to a
 * webhook circuit breaker the operator owns; provider key revocation is
 * deliberately not implemented yet (see README, "What this does not do").
 */

import type {
  Alert,
  ModuleContext,
  ThreatCrushModule,
  ThreatEvent,
} from '@threatcrush/sdk';
import {
  DEFAULT_THRESHOLDS,
  evaluateBurnRate,
  evaluateDay,
  learnBaseline,
  type Baseline,
  type Thresholds,
  type UsageSample,
  type Verdict,
} from './detectors.js';
import { AlchemyProvider, redactRpcUrl } from './providers/alchemy.js';
import { ElevenLabsQuota, ValueSerpQuota, type QuotaProvider } from './providers/quota-apis.js';
import {
  computeDrawdownPerHour,
  DeepSeekBalance,
  MoonshotBalance,
  type BalanceProvider,
} from './providers/balance-apis.js';
import { DEFAULT_QUOTA_THRESHOLDS, evaluateQuota } from './quota.js';
import { TwilioProvider } from './providers/twilio.js';
import { ProviderError, type SpendProvider } from './providers/types.js';

const STATE_BASELINE = 'baseline';
const STATE_QUARANTINE = 'quarantined_dates';
const STATE_ALERTED = 'alerted_keys';

const DEFAULTS = {
  pollIntervalSeconds: 900,
  lookbackDays: 14,
  /** Days of clean history required before any rule may fire. */
  warmupSamples: 7,
  burnRateWarnHours: 6,
};

export default class SpendGuardModule implements ThreatCrushModule {
  name = 'spend-guard';
  version = '0.4.0';
  description = 'Detects balance-drain attacks (SMS pumping, toll fraud, runaway API spend) on third-party providers';

  private ctx!: ModuleContext;
  private providers: SpendProvider[] = [];
  private quotaProviders: QuotaProvider[] = [];
  private balanceProviders: BalanceProvider[] = [];
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  async init(ctx: ModuleContext): Promise<void> {
    this.ctx = ctx;
    this.providers = buildProviders(ctx);
    this.quotaProviders = buildQuotaProviders(ctx);
    this.balanceProviders = buildBalanceProviders(ctx);

    if (this.providers.length === 0) {
      ctx.logger.warn(
        '[%s] no providers configured — set twilio_account_sid/twilio_auth_token to enable',
        this.name,
      );
    } else {
      ctx.logger.info(
        '[%s] initialized with %d provider(s): %s',
        this.name,
        this.providers.length,
        this.providers.map((p) => p.name).join(', '),
      );
    }
  }

  async start(): Promise<void> {
    const intervalSec =
      (this.ctx.config.poll_interval_seconds as number | undefined) ?? DEFAULTS.pollIntervalSeconds;

    this.running = true;
    this.ctx.logger.info('[%s] polling every %ds', this.name, intervalSec);

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

    for (const b of this.balanceProviders) {
      try {
        await this.pollPrepaidBalance(b);
      } catch (err) {
        this.ctx.logger.error('[%s] %s balance poll failed: %s', this.name, b.name, String(err));
      }
    }

    for (const q of this.quotaProviders) {
      try {
        await this.pollQuotaProvider(q);
      } catch (err) {
        this.ctx.logger.error('[%s] %s quota poll failed: %s', this.name, q.name, String(err));
      }
    }

    for (const provider of this.providers) {
      try {
        await this.pollProvider(provider);
      } catch (err) {
        // A provider outage must never take the daemon down, but it also must
        // not fail silently — an attacker who can break polling can drain
        // unobserved, so this is a real signal.
        const status = err instanceof ProviderError ? err.status : undefined;
        this.ctx.logger.error('[%s] %s poll failed: %s', this.name, provider.name, String(err));
        this.ctx.emit(
          this.event('system', 'medium', `spend-guard: ${provider.name} polling failed`, {
            provider: provider.name,
            error: String(err),
            status,
          }),
        );
      }
    }
  }

  private async pollProvider(provider: SpendProvider): Promise<void> {
    // Providers that expose no usage API (Alchemy) report quota state instead.
    // Handled first so an exhausted quota alerts even though there is no
    // usage series to score.
    if (provider instanceof AlchemyProvider) {
      await this.pollQuota(provider);
      return;
    }

    const lookbackDays =
      (this.ctx.config.lookback_days as number | undefined) ?? DEFAULTS.lookbackDays;
    const since = isoDaysAgo(lookbackDays);

    const usage = await provider.fetchUsage(since);
    if (usage.length === 0) {
      this.ctx.logger.debug('[%s] %s: no usage since %s', this.name, provider.name, since);
      return;
    }

    const quarantine = new Set(this.readState<string[]>(`${provider.name}:${STATE_QUARANTINE}`, []));
    const thresholds = this.readThresholds();

    // The most recent day is still accumulating, so judge it but learn only
    // from days that are complete and not already judged anomalous.
    const days = [...new Set(usage.map((s) => s.date))].sort();
    const latestDay = days[days.length - 1];
    const history = usage.filter((s) => s.date !== latestDay);

    const baseline = learnBaseline(history, quarantine);
    this.writeState(`${provider.name}:${STATE_BASELINE}`, baseline);

    if (baseline.samples < ((this.ctx.config.warmup_samples as number) ?? DEFAULTS.warmupSamples)) {
      this.ctx.logger.info(
        '[%s] %s: warming up (%d/%d clean days) — detection held off',
        this.name,
        provider.name,
        baseline.samples,
        DEFAULTS.warmupSamples,
      );
      return;
    }

    for (const day of days) {
      const verdict = evaluateDay(
        usage.filter((s) => s.date === day),
        baseline,
        thresholds,
      );
      if (verdict.hits.length === 0) continue;

      this.report(provider, day, verdict, baseline);

      if (verdict.contain) {
        quarantine.add(day);
      }
    }

    this.writeState(`${provider.name}:${STATE_QUARANTINE}`, [...quarantine]);
    await this.checkBalance(provider, usage);
  }

  /**
   * Quota-state monitoring for providers with no billing API.
   *
   * An exhausted quota is critical, not a warning: it means the spend already
   * happened AND every app on that key is now failing. Alerts fire on state
   * *change* so a month-long exhaustion does not page every poll.
   */
  private async pollQuota(provider: AlchemyProvider): Promise<void> {
    const probe = await provider.probeQuota();
    const stateKey = `${provider.name}:quota_state`;
    const previous = this.readState<string>(stateKey, 'unknown');

    this.writeState(stateKey, probe.state);
    if (probe.state === previous) return;

    if (probe.state === 'healthy') {
      if (previous !== 'unknown') {
        this.ctx.logger.info('[%s] %s quota recovered', this.name, provider.name);
      }
      return;
    }

    const severity = probe.state === 'exhausted' ? 'critical' : 'high';
    const headline =
      probe.state === 'exhausted'
        ? `spend-guard: ${provider.name} monthly capacity EXHAUSTED — every app on this key is failing`
        : `spend-guard: ${provider.name} quota probe returned ${probe.state}`;

    this.ctx.emit(
      this.event('system', severity, headline, {
        provider: provider.name,
        state: probe.state,
        previous,
        detail: probe.detail,
      }),
    );
    this.ctx.alert({ title: headline, severity, body: probe.detail });
  }

  /**
   * Credit/quota pace monitoring. Works with the ordinary API key the app
   * already deploys — no admin credential and no billing API required, which
   * is what makes coverage across a large estate practical.
   */
  private async pollQuotaProvider(provider: QuotaProvider): Promise<void> {
    const snap = await provider.fetchQuota();
    const verdict = evaluateQuota(snap, Date.now(), {
      ...DEFAULT_QUOTA_THRESHOLDS,
      paceFactor: (this.ctx.config.quota_pace_factor as number) ?? DEFAULT_QUOTA_THRESHOLDS.paceFactor,
    });

    if (verdict.severity === 'info') return;

    // Alert on severity change only, so a quota that sits at 80% all month
    // does not page on every poll.
    const stateKey = `quota:${provider.name}:severity`;
    if (this.readState<string>(stateKey, 'info') === verdict.severity) return;
    this.writeState(stateKey, verdict.severity);

    const headline = `spend-guard: ${verdict.message}`;
    this.ctx.emit(
      this.event('system', verdict.severity, headline, {
        provider: provider.name,
        used: snap.used,
        limit: snap.limit,
        unit: snap.unit,
        pace_ratio: Number(verdict.paceRatio.toFixed(2)),
        used_fraction: Number(verdict.usedFraction.toFixed(3)),
        will_exhaust: verdict.willExhaust,
        projected_exhaustion: verdict.projectedExhaustion,
      }),
    );
    this.ctx.alert({ title: headline, severity: verdict.severity });
  }

  /**
   * Prepaid balances have no limit and no reset date, so pace is undefined.
   * The signal comes from the slope between polls instead — which beats a
   * low-balance threshold, because a threshold only fires once the money has
   * already gone.
   */
  private async pollPrepaidBalance(provider: BalanceProvider): Promise<void> {
    const sample = await provider.fetchPrepaidBalance();
    const now = Date.now();
    const key = `balance:${provider.name}:last`;
    const previous = this.readState<{ balance: number; at: number } | null>(key, null);

    this.writeState(key, { balance: sample.balance, at: now });
    if (!previous) return; // first observation — nothing to compare against yet

    const perHour = computeDrawdownPerHour(previous, { balance: sample.balance, at: now });
    const hit = evaluateBurnRate(
      sample.balance,
      perHour,
      (this.ctx.config.burn_rate_warn_hours as number) ?? DEFAULTS.burnRateWarnHours,
      Boolean(this.ctx.config.auto_recharge_enabled),
    );
    if (!hit) return;

    const stateKey = `balance:${provider.name}:severity`;
    if (this.readState<string>(stateKey, '') === hit.severity) return;
    this.writeState(stateKey, hit.severity);

    const headline = `spend-guard: ${provider.name} ${hit.message} (${sample.currency})`;
    this.ctx.emit(
      this.event('system', hit.severity, headline, {
        provider: provider.name,
        balance: sample.balance,
        currency: sample.currency,
        spend_per_hour: Number(perHour.toFixed(4)),
        ...hit.details,
      }),
    );
    this.ctx.alert({ title: headline, severity: hit.severity });
  }

  private report(provider: SpendProvider, day: string, verdict: Verdict, baseline: Baseline): void {
    // Deduplicate on provider+day+signals so a 48h drain produces one alert per
    // escalation, not one per poll.
    const key = `${provider.name}:${day}:${verdict.hits.map((h) => h.detector).sort().join(',')}`;
    const alerted = new Set(this.readState<string[]>(`${provider.name}:${STATE_ALERTED}`, []));
    if (alerted.has(key)) return;

    const details = {
      provider: provider.name,
      date: day,
      spend: Number(verdict.spend.toFixed(4)),
      contain: verdict.contain,
      baseline_unit_cost: Number(baseline.unitCost.toFixed(6)),
      baseline_daily_count: baseline.dailyCount,
      signals: verdict.hits.map((h) => ({
        detector: h.detector,
        ratio: h.ratio,
        message: h.message,
      })),
    };

    const headline = verdict.contain
      ? `spend-guard: ${provider.name} balance-drain suspected on ${day} — ${verdict.hits.length} signals, ${verdict.spend.toFixed(2)} spent`
      : `spend-guard: ${provider.name} spend anomaly on ${day} — ${verdict.spend.toFixed(2)} spent`;

    this.ctx.emit(this.event('system', verdict.severity, headline, details));
    this.ctx.alert({
      title: headline,
      severity: verdict.severity,
      // Lead with money and evidence: the operator's first question is always
      // "how much, and is it still running".
      body: verdict.hits.map((h) => `• ${h.message}`).join('\n'),
    } satisfies Alert);

    alerted.add(key);
    this.writeState(`${provider.name}:${STATE_ALERTED}`, [...alerted].slice(-500));

    if (verdict.contain) void this.contain(provider, day, details);
  }

  private async checkBalance(provider: SpendProvider, usage: UsageSample[]): Promise<void> {
    const snapshot = await provider.fetchBalance();
    if (!snapshot) return;

    const today = new Date().toISOString().slice(0, 10);
    const spentToday = usage
      .filter((s) => s.date === today)
      .reduce((sum, s) => sum + Math.abs(s.cost), 0);

    const elapsedHours = Math.max(new Date().getUTCHours(), 1);
    const perHour = spentToday / elapsedHours;

    // The provider rarely reports auto-recharge state, so trust the operator's
    // assertion when the API stays silent.
    const autoRecharge =
      snapshot.autoRechargeEnabled ?? Boolean(this.ctx.config.auto_recharge_enabled);

    const hit = evaluateBurnRate(
      snapshot.balance,
      perHour,
      (this.ctx.config.burn_rate_warn_hours as number) ?? DEFAULTS.burnRateWarnHours,
      autoRecharge,
    );
    if (!hit) return;

    const headline = `spend-guard: ${provider.name} ${hit.message}`;
    this.ctx.emit(this.event('system', hit.severity, headline, { provider: provider.name, ...hit.details }));
    this.ctx.alert({ title: headline, severity: hit.severity });
  }

  /**
   * Containment. Intentionally minimal: POST to an operator-owned webhook so
   * the application can trip its own breaker. Nothing here mutates provider
   * state, because that needs write-scoped credentials whose blast radius is
   * still an open question in PRD 0001.
   */
  private async contain(
    provider: SpendProvider,
    day: string,
    details: Record<string, unknown>,
  ): Promise<void> {
    const webhook = this.ctx.config.circuit_breaker_webhook as string | undefined;
    if (!webhook) {
      this.ctx.logger.warn(
        '[%s] containment recommended for %s on %s but no circuit_breaker_webhook configured',
        this.name,
        provider.name,
        day,
      );
      return;
    }

    try {
      const res = await fetch(webhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: this.name, action: 'halt', ...details }),
      });
      this.ctx.logger.info('[%s] circuit breaker fired: HTTP %d', this.name, res.status);
    } catch (err) {
      this.ctx.logger.error('[%s] circuit breaker failed: %s', this.name, String(err));
    }
  }

  private readThresholds(): Thresholds {
    const cfg = this.ctx.config;
    return {
      unitCostFactor: (cfg.unit_cost_factor as number) ?? DEFAULT_THRESHOLDS.unitCostFactor,
      volumeFactor: (cfg.volume_factor as number) ?? DEFAULT_THRESHOLDS.volumeFactor,
      minDailySpend: (cfg.min_daily_spend as number) ?? DEFAULT_THRESHOLDS.minDailySpend,
      containSignals: (cfg.contain_signals as number) ?? DEFAULT_THRESHOLDS.containSignals,
    };
  }

  private event(
    category: ThreatEvent['category'],
    severity: ThreatEvent['severity'],
    message: string,
    details: Record<string, unknown>,
  ): ThreatEvent {
    return { timestamp: new Date(), module: this.name, category, severity, message, details };
  }

  private readState<T>(key: string, fallback: T): T {
    const value = this.ctx.getState(key);
    return (value as T) ?? fallback;
  }

  private writeState(key: string, value: unknown): void {
    this.ctx.setState(key, value);
  }
}

/** Build providers from config. Credentials are never logged. */
export function buildProviders(ctx: ModuleContext): SpendProvider[] {
  const providers: SpendProvider[] = [];
  const sid = ctx.config.twilio_account_sid as string | undefined;
  const token = ctx.config.twilio_auth_token as string | undefined;

  if (sid && token) {
    providers.push(new TwilioProvider({ accountSid: sid, authToken: token }));
  }

  // Alchemy is configured as a list of RPC URLs, because one key is commonly
  // shared across several apps — label each so alerts name the right service.
  const alchemy = ctx.config.alchemy_rpc_urls;
  if (Array.isArray(alchemy)) {
    for (const entry of alchemy) {
      const rpcUrl = typeof entry === 'string' ? entry : (entry as { url?: string })?.url;
      if (!rpcUrl) continue;
      const label = typeof entry === 'string' ? undefined : (entry as { label?: string })?.label;
      providers.push(new AlchemyProvider({ rpcUrl, label }));
      ctx.logger.info('[spend-guard] alchemy provider: %s', redactRpcUrl(rpcUrl));
    }
  }

  return providers;
}

/**
 * Build quota providers from config. Each entry is `{ provider, api_key,
 * label }` so one physical key shared by several apps can still be labelled.
 */
export function buildQuotaProviders(ctx: ModuleContext): QuotaProvider[] {
  const out: QuotaProvider[] = [];
  const entries = ctx.config.quota_providers;
  if (!Array.isArray(entries)) return out;

  for (const raw of entries) {
    const e = raw as { provider?: string; api_key?: string; label?: string };
    if (!e?.provider || !e?.api_key) continue;
    const label = e.label ?? e.provider;

    switch (e.provider.toLowerCase()) {
      case 'valueserp':
        out.push(new ValueSerpQuota(e.api_key, label));
        break;
      case 'elevenlabs':
        out.push(new ElevenLabsQuota(e.api_key, label));
        break;
      default:
        ctx.logger.warn('[spend-guard] unknown quota provider: %s', e.provider);
    }
  }
  return out;
}

/** Build prepaid-balance providers from config. */
export function buildBalanceProviders(ctx: ModuleContext): BalanceProvider[] {
  const out: BalanceProvider[] = [];
  const entries = ctx.config.balance_providers;
  if (!Array.isArray(entries)) return out;

  for (const raw of entries) {
    const e = raw as { provider?: string; api_key?: string; label?: string; host?: string };
    if (!e?.provider || !e?.api_key) continue;
    const label = e.label ?? e.provider;

    switch (e.provider.toLowerCase()) {
      case 'deepseek':
        out.push(new DeepSeekBalance(e.api_key, label));
        break;
      case 'moonshot':
      case 'kimi':
        out.push(new MoonshotBalance(e.api_key, label, e.host));
        break;
      default:
        ctx.logger.warn('[spend-guard] unknown balance provider: %s', e.provider);
    }
  }
  return out;
}

export function isoDaysAgo(days: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - days);
  return d.toISOString().slice(0, 10);
}

export * from './detectors.js';
export * from './providers/alchemy.js';
export * from './providers/quota-apis.js';
export * from './providers/balance-apis.js';
export * from './quota.js';
export * from './providers/twilio.js';
export * from './providers/types.js';

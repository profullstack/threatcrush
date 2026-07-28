import { describe, expect, it, vi } from 'vitest';
import {
  AlchemyProvider,
  classifyRpcResponse,
  redactRpcUrl,
} from '../providers/alchemy.js';

/**
 * The exhausted-quota body below is the verbatim response observed from a live
 * Alchemy key that had hit its monthly cap. Matching it exactly is the whole
 * point of this connector: Alchemy exposes no usage API, so this 429 is the
 * only free signal that the drain already happened and dependent apps are down.
 */
const EXHAUSTED_BODY = {
  jsonrpc: '2.0',
  id: 1,
  error: {
    code: 429,
    message:
      'Monthly capacity limit exceeded. Visit https://dashboard.alchemy.com/settings/billing to upgrade your scaling policy for continued service.',
  },
};

describe('classifyRpcResponse', () => {
  it('detects the real monthly-capacity response', () => {
    const probe = classifyRpcResponse(429, EXHAUSTED_BODY);
    expect(probe.state).toBe('exhausted');
    expect(probe.detail).toContain('Monthly capacity limit exceeded');
  });

  it('detects capacity exhaustion even when the HTTP status is 200', () => {
    // Alchemy sometimes returns the JSON-RPC error with a 200 envelope.
    expect(classifyRpcResponse(200, EXHAUSTED_BODY).state).toBe('exhausted');
  });

  it('treats a bare 429 as exhausted', () => {
    expect(classifyRpcResponse(429, null).state).toBe('exhausted');
  });

  it('distinguishes a rejected key from an exhausted quota', () => {
    // These need different responses: one is a billing event, the other is a
    // revoked/rotated credential.
    expect(classifyRpcResponse(401, null).state).toBe('forbidden');
    expect(classifyRpcResponse(403, null).state).toBe('forbidden');
  });

  it('reports healthy on a normal response', () => {
    expect(classifyRpcResponse(200, { jsonrpc: '2.0', id: 1, result: '0x1b4' }).state).toBe(
      'healthy',
    );
  });

  it('falls back to unknown rather than guessing', () => {
    expect(classifyRpcResponse(500, null).state).toBe('unknown');
    expect(classifyRpcResponse(503, {}).state).toBe('unknown');
  });
});

describe('redactRpcUrl', () => {
  it('strips the key so it never reaches a log or alert', () => {
    expect(redactRpcUrl('https://base-mainnet.g.alchemy.com/v2/SECRETKEY123')).toBe(
      'https://base-mainnet.g.alchemy.com/v2/<KEY>',
    );
    expect(redactRpcUrl('https://bitcoin-mainnet.g.alchemy.com/v2/abc?x=1')).toBe(
      'https://bitcoin-mainnet.g.alchemy.com/v2/<KEY>?x=1',
    );
  });
});

describe('AlchemyProvider', () => {
  const cfg = { rpcUrl: 'https://base-mainnet.g.alchemy.com/v2/KEY', label: 'b1dz' };

  it('labels events by app so a shared key can still be attributed', () => {
    expect(new AlchemyProvider(cfg).name).toBe('alchemy:b1dz');
    expect(new AlchemyProvider({ rpcUrl: cfg.rpcUrl }).name).toBe('alchemy');
  });

  it('probes with the cheapest possible RPC call', async () => {
    const fakeFetch = vi.fn(
      async () => new Response(JSON.stringify({ result: '0x1b4' }), { status: 200 }),
    );
    const provider = new AlchemyProvider(cfg, fakeFetch as unknown as typeof fetch);

    const probe = await provider.probeQuota();

    expect(probe.state).toBe('healthy');
    const body = JSON.parse((fakeFetch.mock.calls[0][1] as RequestInit).body as string);
    expect(body.method).toBe('eth_blockNumber');
  });

  it('surfaces an exhausted quota', async () => {
    const fakeFetch = vi.fn(
      async () => new Response(JSON.stringify(EXHAUSTED_BODY), { status: 429 }),
    );
    const provider = new AlchemyProvider(cfg, fakeFetch as unknown as typeof fetch);

    expect((await provider.probeQuota()).state).toBe('exhausted');
  });

  it('reports no usage series and no balance, rather than faking them', async () => {
    const provider = new AlchemyProvider(cfg, (async () => new Response('{}')) as unknown as typeof fetch);

    // Alchemy publishes no usage API and is subscription-billed. Empty and null
    // are the truthful answers; inventing numbers here would produce detectors
    // that appear to work but can never fire.
    expect(await provider.fetchUsage()).toEqual([]);
    expect(await provider.fetchBalance()).toBeNull();
  });

  it('wraps network failures in ProviderError', async () => {
    const fakeFetch = vi.fn(async () => {
      throw new Error('ECONNRESET');
    });
    const provider = new AlchemyProvider(cfg, fakeFetch as unknown as typeof fetch);

    await expect(provider.probeQuota()).rejects.toThrow(/Alchemy probe failed/);
  });
});

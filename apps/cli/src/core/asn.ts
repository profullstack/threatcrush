import { promises as dns } from 'node:dns';
import { isIP } from 'node:net';
import { ipToBytes } from '../daemon/firewall/protected.js';

/**
 * Who owns an address, and what kind of network it is: enough to tell a
 * person's home or mobile line from a rented server, a VPN or a cloud runner.
 *
 * Looked up on demand through Team Cymru's IP-to-ASN DNS service (no account,
 * no database to download): `<reversed ip>.origin.asn.cymru.com TXT` gives the
 * ASN, `AS<n>.asn.cymru.com TXT` its registered name. Only accepted SSH logins
 * are looked up, so the volume is tiny, and every answer is cached.
 */

export type NetworkKind = 'tor' | 'ci' | 'hosting' | 'vpn' | 'unknown';

export interface AsnInfo {
  asn: number;
  /** Registered AS name, e.g. "GOOGLE-CLOUD-PLATFORM - Google LLC, US". */
  name: string;
  country?: string;
  prefix?: string;
}

/** CI runner networks: GitHub Actions runs on Azure (Microsoft), plus GitHub's own. */
export const CI_ASNS = new Set([8075, 36459, 8068, 8069, 12076]);

/**
 * Hosting and cloud ASNs seen in SSH attacks (and the 2026-10-27 intrusion:
 * Google Cloud 396982, OVH 16276). Names are matched too (HOSTING_NAME), so
 * this list only needs the big ones whose names do not say "hosting".
 */
export const HOSTING_ASNS = new Set([
  15169, 396982, 19527, // Google, Google Cloud
  16509, 14618, // Amazon / AWS
  16276, // OVH
  24940, 213230, // Hetzner
  14061, // DigitalOcean
  63949, // Linode / Akamai
  20473, // Vultr (Choopa)
  12876, // Scaleway
  51167, // Contabo
  31898, // Oracle Cloud
  45102, // Alibaba
  132203, 45090, // Tencent
  36352, // ColoCrossing
  53667, // FranTech / BuyVM
  197540, // netcup
  9009, // M247
  60068, // Datacamp / CDN77
  212238, // Datacamp
  202425, // IP Volume
  210644, // Aeza
  49981, // WorldStream
  62240, // Clouvider
  136907, // Huawei Cloud
  8100, // QuadraNet
  46606, // Unified Layer
  29802, // HVC
  40021, // Contabo US / Nubes
  398324, 399629, // Censys and friends
]);

/** Commercial VPN and anonymizer operators (by ASN). */
export const VPN_ASNS = new Set([
  9009, // M247 (most commercial VPN exits)
  212238, 60068, // Datacamp (NordVPN, Proton, ...)
  209854, // Surfshark
  39351, // 31173 Services (Mullvad)
  136787, // TEFINCOM (NordVPN)
  147049, // PacketHub (NordVPN)
]);

const HOSTING_NAME = /hosting|server|datacenter|data center|data-center|cloud|colo|vps|dedicated|ovh|hetzner|digitalocean|linode|vultr|choopa|amazon|aws|google|microsoft|azure|oracle|alibaba|tencent|contabo|scaleway|leaseweb|ionos|kamatera|frantech|buyvm|racknerd|quadranet|psychz|m247|datacamp|cdn77|aeza|serverius|worldstream|ipvolume|clouvider|netcup|gcore|g-core|selectel|timeweb|hostinger|godaddy|incapsula|fastly/i;
const VPN_NAME = /\bvpn\b|proton|mullvad|nordvpn|surfshark|expressvpn|private internet access|tefincom|packethub|31173 services|anonymi[sz]|privacy|proxy/i;

/** What kind of network an ASN is. `tor` is decided by the exit list, not here. */
export function classifyAsn(info: AsnInfo | null): Exclude<NetworkKind, 'tor'> {
  if (!info) return 'unknown';
  if (CI_ASNS.has(info.asn)) return 'ci';
  if (VPN_ASNS.has(info.asn) || VPN_NAME.test(info.name)) return 'vpn';
  if (HOSTING_ASNS.has(info.asn) || HOSTING_NAME.test(info.name)) return 'hosting';
  return 'unknown';
}

/** The Cymru origin query name for an address. */
export function cymruOriginName(ip: string): string | null {
  const bytes = ipToBytes(ip);
  if (!bytes) return null;
  if (bytes.length === 4) return `${[...bytes].reverse().join('.')}.origin.asn.cymru.com`;
  const nibbles: string[] = [];
  for (const b of bytes) nibbles.push((b >> 4).toString(16), (b & 0xf).toString(16));
  return `${nibbles.reverse().join('.')}.origin6.asn.cymru.com`;
}

/** `"16276 | 198.244.192.0/18 | FR | ripencc | 2004-..."` → asn, prefix, country. */
export function parseCymruOrigin(txt: string): { asn: number; prefix?: string; country?: string } | null {
  const fields = txt.split('|').map((f) => f.trim());
  // A prefix announced by several ASNs lists them space-separated; the first will do.
  const asn = Number(fields[0]?.split(/\s+/)[0]);
  if (!Number.isInteger(asn) || asn <= 0) return null;
  return { asn, prefix: fields[1] || undefined, country: /^[A-Z]{2}$/.test(fields[2] ?? '') ? fields[2] : undefined };
}

/** `"16276 | FR | ripencc | 2004-01-26 | OVH, FR"` → the name. */
export function parseCymruName(txt: string): string {
  const fields = txt.split('|').map((f) => f.trim());
  return (fields[4] ?? '').slice(0, 120);
}

export type TxtResolver = (name: string) => Promise<string[][]>;

export class AsnLookup {
  private cache = new Map<string, { at: number; info: AsnInfo | null }>();

  constructor(
    private resolveTxt: TxtResolver = (name) => dns.resolveTxt(name),
    private ttlMs = 24 * 3_600_000,
    private now: () => number = Date.now,
  ) {}

  async lookup(ip: string): Promise<AsnInfo | null> {
    if (isIP(ip) === 0) return null;
    const hit = this.cache.get(ip);
    if (hit && this.now() - hit.at < this.ttlMs) return hit.info;
    let info: AsnInfo | null = null;
    try {
      const origin = cymruOriginName(ip);
      if (origin) {
        const rec = await withTimeout(this.resolveTxt(origin), 5000);
        const parsed = parseCymruOrigin(rec.map((r) => r.join('')).find(Boolean) ?? '');
        if (parsed) {
          let name = '';
          try {
            const names = await withTimeout(this.resolveTxt(`AS${parsed.asn}.asn.cymru.com`), 5000);
            name = parseCymruName(names.map((r) => r.join('')).find(Boolean) ?? '');
          } catch { /* the number alone still classifies the big ones */ }
          info = { asn: parsed.asn, name, country: parsed.country, prefix: parsed.prefix };
        }
      }
    } catch {
      info = null;
    }
    if (this.cache.size > 5000) this.cache.clear();
    this.cache.set(ip, { at: this.now(), info });
    return info;
  }
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout')), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}

/** "AS16276 OVH, FR (hosting)" for alert text. */
export function describeNetwork(info: AsnInfo | null, kind: NetworkKind): string {
  if (kind === 'tor') return info ? `Tor exit, AS${info.asn} ${info.name}`.trim() : 'Tor exit';
  if (!info) return `unknown network (${kind})`;
  return `AS${info.asn}${info.name ? ` ${info.name}` : ''} (${kind === 'unknown' ? 'ISP or unclassified' : kind})`;
}

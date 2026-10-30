import { sshdPeerIp } from '../../core/log-parser.js';

/** Small connection cache: only root-owned sshd records from the same boot/PID. */
export class JournalProvenance {
  private peers = new Map<string, { ip: string; at: number }>();
  fields(entry: Record<string, unknown>): { source_ip?: string; details: Record<string, string> } {
    const details: Record<string, string> = {};
    for (const [source, dest] of Object.entries({ _PID: 'pid', _BOOT_ID: 'boot_id', __CURSOR: 'journal_cursor', _AUDIT_SESSION: 'audit_session', _AUDIT_LOGINUID: 'login_uid' })) {
      if (typeof entry[source] === 'string') details[dest] = (entry[source] as string).slice(0, 200);
    }
    const trusted = entry._UID === '0' && ['sshd', 'sshd-session', 'sshd-auth'].includes(String(entry._COMM));
    if (!trusted || typeof entry.MESSAGE !== 'string') return { details };
    const at = Number(entry.__REALTIME_TIMESTAMP) / 1000;
    const key = typeof entry._BOOT_ID === 'string' && typeof entry._PID === 'string' ? `${entry._BOOT_ID}:${entry._PID}` : null;
    for (const [k, peer] of this.peers) if (!Number.isFinite(at) || at - peer.at > 120_000 || at < peer.at) this.peers.delete(k);
    const direct = sshdPeerIp(entry.MESSAGE);
    if (direct && key && Number.isFinite(at)) {
      this.peers.delete(key);
      this.peers.set(key, { ip: direct, at });
      if (this.peers.size > 512) this.peers.delete(this.peers.keys().next().value!);
    }
    const peer = key ? this.peers.get(key) : undefined;
    const source_ip = direct ?? (peer && Number.isFinite(at) && at >= peer.at && at - peer.at <= 120_000 ? peer.ip : undefined);
    if (source_ip) details.source_ip_basis = direct ? 'current sshd record' : 'same boot and sshd PID within 120 seconds';
    return { ...(source_ip ? { source_ip } : {}), details };
  }
}

type Res<T> = { ok: true; result: T } | { ok: false; error: string }

export interface CloudFinding {
  id: string
  source: 'scan' | 'pentest' | 'ai-scan'
  type: string
  severity: string
  message: string
  location: string | null
  status: string
  note: string | null
  first_seen_at: string
  last_seen_at: string
  times_seen: number
  status_source: string
  properties?: { name: string; kind: string; target: string } | null
  details?: Record<string, unknown>
}

export interface AvDetectionView {
  engine: string
  id: string
  name: string
  severity: string
  impact: 'malicious' | 'suspicious' | 'info'
  description: string
}
export interface AvFileView {
  path: string
  size: number
  sha256: string | null
  kind: string
  verdict: 'clean' | 'suspicious' | 'malicious' | 'error'
  detections: AvDetectionView[]
  note?: string
}
export interface AvStatus {
  rules: number
  clamav: { available: boolean; version: string | null; mode: string | null; signaturesDate: string | null }
  clamavHint: string
  quarantined: number
  watching: boolean
  quickTargets: string[]
}
export interface AvScanResult {
  summary: { scanned: number; malicious: number; suspicious: number; errors: number; skipped: number; engines: string[] }
  flagged: AvFileView[]
  clamavError: string | null
  cancelled: boolean
}
export interface AvQuarantineEntry {
  id: string
  originalPath: string
  sha256: string
  size: number
  detections: Array<{ name: string; id: string }>
  quarantinedAt: string
}
export type AvEvent =
  | { type: 'phase'; phase: string; detail?: string }
  | { type: 'progress'; scanned: number; path: string }
  | { type: 'hit'; result: AvFileView }
  | { type: 'watch'; result: AvFileView }

export type ConnectResult = {
  connected: boolean
  pid?: number
  version?: string
  socket?: string
  error?: string
}

declare global {
  interface Window {
    /** Exposed by src/preload/index.ts; absent when the renderer runs outside Electron. */
    api?: {
      connectDaemon(): Promise<ConnectResult>
      daemonStatus(): Promise<{ running: boolean; pid?: number; error?: string }>
      daemonRequest<T = unknown>(
        method: string,
        params?: Record<string, unknown>,
      ): Promise<{ ok: true; result: T } | { ok: false; error: string }>
      /** Pushed frames: { type: 'event' | 'module' | 'connected', data }. */
      onEvent(callback: (frame: unknown) => void): () => void
      av: {
        status(): Promise<Res<AvStatus>>
        pick(): Promise<Res<string[]>>
        scan(mode: 'quick' | 'full' | 'paths', paths?: string[], offline?: boolean): Promise<Res<AvScanResult>>
        cancel(): Promise<Res<void>>
        quarantine(path: string): Promise<Res<AvQuarantineEntry>>
        quarantineList(): Promise<Res<AvQuarantineEntry[]>>
        restore(id: string): Promise<Res<string>>
        remove(id: string): Promise<Res<void>>
        reveal(path: string): Promise<Res<void>>
        watch(on: boolean, offline?: boolean): Promise<Res<{ watching: boolean }>>
        onEvent(callback: (event: AvEvent) => void): () => void
      }
      cloud: {
        status(): Promise<Res<{ signedIn: boolean; email?: string; org_slug?: string; api: string }>>
        login(): Promise<Res<{ user_code: string; verification_url: string }>>
        waitForLogin(): Promise<Res<{ ok: true; email?: string } | { ok: false; error: string }>>
        cancelLogin(): Promise<Res<void>>
        logout(): Promise<Res<void>>
        orgs(): Promise<Res<Array<{ id: string; slug: string; name: string }>>>
        useOrg(id: string, slug: string): Promise<Res<void>>
        findings(q?: { status?: string; severity?: string; source?: string; offset?: number }): Promise<Res<{ findings: CloudFinding[]; total: number; counts: Record<string, number> }>>
        finding(id: string): Promise<Res<{ finding: CloudFinding }>>
        triage(ids: string[], status: string | null, note?: string): Promise<Res<{ updated: Array<{ id: string; status: string }> }>>
      }
    }
  }
}

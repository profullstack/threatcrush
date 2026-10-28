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

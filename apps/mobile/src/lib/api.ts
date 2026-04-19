import { config } from '../config';

interface ApiOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
}

class ThreatCrushAPI {
  private baseUrl: string;
  private licenseKey: string | null = null;

  constructor() {
    this.baseUrl = config.apiUrl;
  }

  setBaseUrl(url: string) {
    this.baseUrl = url.replace(/\/$/, '');
  }

  setLicenseKey(key: string | null) {
    this.licenseKey = key;
  }

  private async request<T>(path: string, opts: ApiOptions = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...opts.headers,
    };

    if (this.licenseKey) {
      headers['Authorization'] = `Bearer ${this.licenseKey}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method: opts.method || 'GET',
      headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });

    if (!res.ok) {
      throw new Error(`API ${res.status}: ${res.statusText}`);
    }

    return res.json() as Promise<T>;
  }

  async getEvents(limit = 50) {
    return this.request<ThreatEvent[]>(`/api/events?limit=${limit}`);
  }

  async getModules() {
    return this.request<Module[]>('/api/modules');
  }

  async toggleModule(id: string, enabled: boolean) {
    return this.request<Module>(`/api/modules/${id}`, {
      method: 'PATCH',
      body: { enabled },
    });
  }

  async getStats() {
    return this.request<Stats>('/api/stats');
  }

  async login(email: string) {
    return this.request<{ ok: boolean; message: string }>('/api/auth/login', {
      method: 'POST',
      body: { email },
    });
  }

  async verify(email: string, code: string) {
    return this.request<{ token: string }>('/api/auth/verify', {
      method: 'POST',
      body: { email, code },
    });
  }
}

export const api = new ThreatCrushAPI();

// Types
export interface ThreatEvent {
  id: string;
  timestamp: string;
  module: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  source?: string;
  blocked: boolean;
}

export interface Module {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  status: 'running' | 'stopped' | 'error';
  eventsToday: number;
}

export interface Stats {
  eventsToday: number;
  threatsBlocked: number;
  uptimeHours: number;
  modulesActive: number;
  modulesTotal: number;
}

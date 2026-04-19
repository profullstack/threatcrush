export type EventSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type EventCategory = 'auth' | 'web' | 'network' | 'system' | 'scan' | 'pentest';

export interface ThreatEvent {
  id?: number;
  timestamp: Date;
  module: string;
  category: EventCategory;
  severity: EventSeverity;
  message: string;
  source_ip?: string;
  details?: Record<string, unknown>;
}

export interface ParsedLogLine {
  timestamp: Date;
  raw: string;
  source: string;
  fields: Record<string, string | undefined>;
}

export interface NginxLogEntry extends ParsedLogLine {
  source: 'nginx';
  fields: {
    ip: string;
    method: string;
    path: string;
    status: string;
    size: string;
    user_agent: string;
    [key: string]: string;
  };
}

export interface AuthLogEntry extends ParsedLogLine {
  source: 'auth';
  fields: {
    process: string;
    message: string;
    ip?: string | undefined;
    user?: string | undefined;
    [key: string]: string | undefined;
  };
}

export interface SyslogEntry extends ParsedLogLine {
  source: 'syslog';
  fields: {
    facility: string;
    process: string;
    message: string;
    [key: string]: string;
  };
}

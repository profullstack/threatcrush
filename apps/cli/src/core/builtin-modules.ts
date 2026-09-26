/**
 * Modules compiled into threatcrushd. They are always there — nothing to
 * install — so offline views (`status` with the daemon down, `modules list`)
 * list them alongside whatever was installed from the store.
 */
export const BUILTIN_MODULES: ReadonlyArray<{ name: string; version: string; description: string }> = [
  { name: 'log-watcher', version: '0.1.0', description: 'Web and system log attacks (nginx, syslog)' },
  { name: 'ssh-guard', version: '0.1.0', description: 'SSH brute force (auth.log or the sshd journal)' },
  { name: 'user-journal', version: '0.1.0', description: 'Events from the systemd journal' },
  { name: 'network-monitor', version: '0.1.0', description: 'Inbound connections and port scans' },
  { name: 'dns-monitor', version: '0.1.0', description: 'DNS tunneling and DGA indicators' },
];

import React from 'react';
import { Text, View } from 'react-native';
import { theme } from '../../src/config';
import type { Remediation, Server } from '../../src/lib/api';
import { timeAgo } from '../../src/lib/utils';
import { ConnectServerHelp } from '../../src/components/ConnectServerHelp';
import { OrgScreen } from '../../src/components/OrgScreen';
import { Badge, Card, SectionTitle, styles } from '../../src/components/ui';
import { useWorkspaceStore } from '../../src/stores/workspace';

const SERVER_COLORS: Record<Server['status'], string> = {
  online: theme.primary,
  offline: theme.dim,
  unreachable: theme.red,
};

const REMEDIATION_COLORS: Record<Remediation['status'], string> = {
  pending: theme.yellow,
  executed: theme.primary,
  failed: theme.red,
  expired: theme.dim,
  reversed: theme.dim,
};

const ACTION_LABELS: Record<Remediation['action_type'], string> = {
  block: 'Block',
  unblock: 'Unblock',
  allowlist_add: 'Allowlist',
  allowlist_remove: 'Remove from allowlist',
};

function ServerCard({ server }: { server: Server }) {
  return (
    <Card>
      <View style={styles.rowBetween}>
        <Text style={styles.title}>{server.name}</Text>
        <Badge label={server.status} color={SERVER_COLORS[server.status] ?? theme.dim} />
      </View>
      <Text style={styles.dim}>{server.hostname || server.ip_address || 'No address'}</Text>
      <Text style={styles.dim}>
        Last heartbeat: {timeAgo(server.last_seen)}
        {server.threatcrushd_version ? ` · threatcrushd ${server.threatcrushd_version}` : ''}
      </Text>
    </Card>
  );
}

function RemediationRow({ action, serverName }: { action: Remediation; serverName: string }) {
  return (
    <Card>
      <View style={styles.rowBetween}>
        <Text style={styles.title}>
          {ACTION_LABELS[action.action_type] ?? action.action_type} {action.target_value}
        </Text>
        <Badge label={action.status} color={REMEDIATION_COLORS[action.status] ?? theme.dim} />
      </View>
      <Text style={styles.dim}>
        {serverName} · queued {timeAgo(action.created_at)}
        {action.expires_at ? ` · expires ${new Date(action.expires_at).toLocaleString()}` : ''}
      </Text>
    </Card>
  );
}

export default function ServersScreen() {
  const { servers, remediations } = useWorkspaceStore();
  const names = new Map(servers.map((s) => [s.id, s.name]));

  return (
    <OrgScreen title="SERVERS">
      {(org) =>
        servers.length === 0 ? (
          <ConnectServerHelp org={org} />
        ) : (
          <>
            {servers.map((s) => (
              <ServerCard key={s.id} server={s} />
            ))}
            <SectionTitle>Remediations</SectionTitle>
            {remediations.length === 0 ? (
              <Text style={styles.dim}>No blocks or allowlist changes have been queued from the dashboard.</Text>
            ) : (
              remediations.map((r) => (
                <RemediationRow key={r.id} action={r} serverName={names.get(r.server_id) ?? 'Unknown server'} />
              ))
            )}
          </>
        )
      }
    </OrgScreen>
  );
}

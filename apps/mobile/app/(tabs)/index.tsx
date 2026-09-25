import React from 'react';
import { Text, View } from 'react-native';
import { theme } from '../../src/config';
import type { Detection, Organization, Severity } from '../../src/lib/api';
import { SEVERITY_COLORS, timeAgo } from '../../src/lib/utils';
import { ConnectServerHelp } from '../../src/components/ConnectServerHelp';
import { OrgScreen } from '../../src/components/OrgScreen';
import { Badge, Body, Button, Card, EmptyState, SeverityBadge, styles } from '../../src/components/ui';
import { usePushStore } from '../../src/stores/push';
import { useWorkspaceStore } from '../../src/stores/workspace';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const STATUS_COLORS: Record<Detection['status'], string> = {
  new: theme.red,
  acknowledged: theme.yellow,
  resolved: theme.dim,
};

function PushPrompt({ org }: { org: Organization }) {
  const { status, dismissed, error, enable, dismiss } = usePushStore();
  if (status === 'error' && error) {
    return (
      <Card>
        <Text style={styles.title}>Alerts couldn't be turned on</Text>
        <Text style={styles.dim}>{error}</Text>
      </Card>
    );
  }
  if (status !== 'undetermined' || dismissed) return null;
  return (
    <Card>
      <Text style={styles.title}>Get alerts on this phone?</Text>
      <Body>
        ThreatCrush can notify you when a server in {org.name} records a new detection. Your phone will ask for
        permission next. Detections aren't uploaded from servers yet, so expect alerts once that ships.
      </Body>
      <View style={styles.row}>
        <View style={{ flex: 1 }}>
          <Button label="Turn on alerts" onPress={() => void enable(org.id)} />
        </View>
        <View style={{ flex: 1 }}>
          <Button label="Not now" variant="outline" onPress={dismiss} />
        </View>
      </View>
    </Card>
  );
}

function DetectionCard({ detection, serverName }: { detection: Detection; serverName: string }) {
  return (
    <Card>
      <View style={styles.rowBetween}>
        <View style={styles.row}>
          <SeverityBadge severity={detection.severity} />
          <Badge label={detection.status} color={STATUS_COLORS[detection.status] ?? theme.dim} />
        </View>
        <Text style={styles.dim}>{timeAgo(detection.detected_at)}</Text>
      </View>
      <Text style={styles.title}>{detection.title}</Text>
      {detection.description ? <Text style={styles.dim}>{detection.description}</Text> : null}
      <Text style={styles.dim}>
        {serverName}
        {detection.source_ip ? ` · from ${detection.source_ip}` : ''}
        {detection.rule_id ? ` · ${detection.rule_id}` : ''}
      </Text>
    </Card>
  );
}

function Threats({ org }: { org: Organization }) {
  const { servers, detections, detectionsTotal, loadingMore, loadMoreDetections } = useWorkspaceStore();

  if (servers.length === 0) return <ConnectServerHelp org={org} />;

  if (detections.length === 0) {
    return (
      <EmptyState title="No detections recorded">
        <Body>
          threatcrush.com has no detections for {org.name}'s {servers.length} server
          {servers.length === 1 ? '' : 's'}. The daemon currently raises alerts on the server itself (TUI, email,
          Discord, PagerDuty) and does not upload them here yet, so this list stays empty until that ships.
        </Body>
        <Body>Server status and scan results on the other tabs are live.</Body>
      </EmptyState>
    );
  }

  const counts = SEVERITIES.map((sev) => [sev, detections.filter((d) => d.severity === sev).length] as const);
  const names = new Map(servers.map((s) => [s.id, s.name]));

  return (
    <>
      <Card>
        <Text style={styles.dim}>Detections</Text>
        <Text style={styles.bigNumber}>{detectionsTotal}</Text>
        <View style={[styles.row, { flexWrap: 'wrap' }]}>
          {counts
            .filter(([, n]) => n > 0)
            .map(([sev, n]) => (
              <Text key={sev} style={{ color: SEVERITY_COLORS[sev], fontSize: 12 }}>
                {n} {sev}
              </Text>
            ))}
        </View>
        {detectionsTotal > detections.length ? (
          <Text style={styles.dim}>Severity counts cover the {detections.length} most recent.</Text>
        ) : null}
      </Card>
      {detections.map((d) => (
        <DetectionCard key={d.id} detection={d} serverName={names.get(d.server_id) ?? 'Unknown server'} />
      ))}
      {detections.length < detectionsTotal ? (
        <Button
          label={loadingMore ? 'Loading…' : `Load more (${detectionsTotal - detections.length} older)`}
          variant="outline"
          disabled={loadingMore}
          onPress={() => void loadMoreDetections()}
        />
      ) : null}
    </>
  );
}

export default function ThreatsScreen() {
  return (
    <OrgScreen title="THREATS">
      {(org) => (
        <>
          <PushPrompt org={org} />
          <Threats org={org} />
        </>
      )}
    </OrgScreen>
  );
}

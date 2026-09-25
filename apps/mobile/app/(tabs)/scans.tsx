import React from 'react';
import { Text, View } from 'react-native';
import { config, theme } from '../../src/config';
import type { PropertyRun, Severity } from '../../src/lib/api';
import { SEVERITY_COLORS, timeAgo } from '../../src/lib/utils';
import { OrgScreen } from '../../src/components/OrgScreen';
import { Badge, Body, Card, Code, EmptyState, LinkText, styles } from '../../src/components/ui';
import { useWorkspaceStore } from '../../src/stores/workspace';

const RUN_COLORS: Record<PropertyRun['status'], string> = {
  queued: theme.dim,
  running: theme.blue,
  succeeded: theme.primary,
  failed: theme.red,
  cancelled: theme.dim,
};

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function RunCard({ run }: { run: PropertyRun }) {
  const when = run.completed_at ?? run.started_at ?? run.queued_at;
  return (
    <Card>
      <View style={styles.rowBetween}>
        <View style={styles.row}>
          <Badge label={run.status} color={RUN_COLORS[run.status] ?? theme.dim} />
          <Text style={styles.dim}>{run.type}</Text>
        </View>
        <Text style={styles.dim}>{timeAgo(when)}</Text>
      </View>
      <Text style={styles.title}>{run.property?.name ?? 'Deleted property'}</Text>
      {run.property ? <Text style={styles.dim}>{run.property.target}</Text> : null}
      {run.status === 'succeeded' ? (
        <View style={[styles.row, { flexWrap: 'wrap' }]}>
          <Text style={styles.body}>
            {run.findings_count} finding{run.findings_count === 1 ? '' : 's'}
          </Text>
          {SEVERITIES.filter((s) => (run.severity_summary?.[s] ?? 0) > 0).map((s) => (
            <Text key={s} style={{ color: SEVERITY_COLORS[s], fontSize: 12 }}>
              {run.severity_summary?.[s]} {s}
            </Text>
          ))}
        </View>
      ) : null}
      {run.summary ? <Text style={styles.dim}>{run.summary}</Text> : null}
      {run.error ? <Text style={styles.errorText}>{run.error}</Text> : null}
    </Card>
  );
}

export default function ScansScreen() {
  const { runs, runsTotal } = useWorkspaceStore();

  return (
    <OrgScreen title="SCANS">
      {(org) =>
        runs.length === 0 ? (
          <EmptyState title="No scans yet">
            <Body>
              Scans and pentests run against the properties (sites, APIs, domains, repos) you add to {org.name}.
              A logged-in threatcrushd picks up queued runs and reports results here.
            </Body>
            <LinkText label="Add a property" url={`${config.apiUrl}/org/${org.slug}/properties/new`} />
            <Code>{'threatcrush properties add "Site" https://example.com'}</Code>
          </EmptyState>
        ) : (
          <>
            <Text style={styles.dim}>
              {runsTotal > runs.length
                ? `Latest ${runs.length} of ${runsTotal} runs`
                : `${runs.length} ${runs.length === 1 ? 'run' : 'runs'}`}
            </Text>
            {runs.map((r) => (
              <RunCard key={r.id} run={r} />
            ))}
          </>
        )
      }
    </OrgScreen>
  );
}

import React, { useCallback, useState } from 'react';
import { Text, View } from 'react-native';
import { useFocusEffect } from 'expo-router';
import { type AttackMapData, flag, severityColor, topCountries } from '@threatcrush/attack-map';
import { theme } from '../../src/config';
import { api, type Organization } from '../../src/lib/api';
import { timeAgo } from '../../src/lib/utils';
import { AttackMapCard } from '../../src/components/AttackMapCard';
import { ConnectServerHelp } from '../../src/components/ConnectServerHelp';
import { OrgScreen } from '../../src/components/OrgScreen';
import { Card, ErrorBanner, Loading, styles } from '../../src/components/ui';
import { useAuthStore } from '../../src/stores/auth';
import { useWorkspaceStore } from '../../src/stores/workspace';

const REFRESH_MS = 5000;

function LiveMap({ org }: { org: Organization }) {
  const servers = useWorkspaceStore((s) => s.servers);
  const [data, setData] = useState<AttackMapData | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Poll only while this tab is on screen.
  useFocusEffect(
    useCallback(() => {
      let stopped = false;
      const load = async () => {
        try {
          const next = await useAuthStore.getState().withSession((token) => api.attackMap(token, org.id));
          if (!stopped) {
            setData(next);
            setError(null);
          }
        } catch (err) {
          if (!stopped) setError(err instanceof Error ? err.message : 'Map unavailable');
        }
      };
      void load();
      const timer = setInterval(load, REFRESH_MS);
      return () => {
        stopped = true;
        clearInterval(timer);
      };
    }, [org.id]),
  );

  if (servers.length === 0) return <ConnectServerHelp org={org} />;
  if (!data) return error ? <ErrorBanner message={error} /> : <Loading />;

  const total = data.origins.reduce((n, o) => n + o.count, 0);
  const countries = topCountries(data.origins, 5);
  const latest = [...data.origins].sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : -1)).slice(0, 10);

  return (
    <>
      <Card>
        <View style={styles.rowBetween}>
          <View style={styles.row}>
            <View style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: theme.primary }} />
            <Text style={[styles.title, { color: theme.primary }]}>LIVE</Text>
          </View>
          <Text style={styles.dim}>
            {data.origins.length} sources · {total} events · last hour
          </Text>
        </View>
        <AttackMapCard data={data} />
        {data.origins.length === 0 ? <Text style={styles.dim}>All quiet: no attacks in the last hour.</Text> : null}
        {error ? <Text style={{ color: theme.red, fontSize: 12 }}>{error}</Text> : null}
      </Card>
      {countries.length > 0 ? (
        <Card>
          <Text style={styles.dim}>Top sources</Text>
          {countries.map((c) => (
            <View key={c.code ?? c.country} style={styles.rowBetween}>
              <Text style={{ color: theme.text }}>
                {flag(c.code)} {c.country}
              </Text>
              <Text style={{ color: theme.text, fontWeight: '700' }}>{c.count}</Text>
            </View>
          ))}
        </Card>
      ) : null}
      {latest.length > 0 ? (
        <Card>
          <Text style={styles.dim}>Latest</Text>
          {latest.map((o) => (
            <View key={o.ip} style={{ gap: 2 }}>
              <View style={styles.rowBetween}>
                <View style={styles.row}>
                  <View style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: severityColor(o.severity) }} />
                  <Text style={{ color: theme.text, fontFamily: 'monospace' }}>{o.ip}</Text>
                </View>
                <Text style={styles.dim}>{timeAgo(o.lastSeen)}</Text>
              </View>
              <Text style={styles.dim}>
                {flag(o.countryCode)} {[o.city, o.country].filter(Boolean).join(', ')}
                {o.category ? ` · ${o.category}` : ''}
              </Text>
            </View>
          ))}
        </Card>
      ) : null}
      <Text style={[styles.dim, { textAlign: 'right', fontSize: 10 }]}>IP Geolocation by DB-IP</Text>
    </>
  );
}

export default function MapScreen() {
  return <OrgScreen title="ATTACK MAP">{(org) => <LiveMap org={org} />}</OrgScreen>;
}

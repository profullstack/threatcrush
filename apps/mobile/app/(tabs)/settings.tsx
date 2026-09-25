import React from 'react';
import { Linking, ScrollView, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { config } from '../../src/config';
import { Body, Button, Card, SectionTitle, styles } from '../../src/components/ui';
import { useAuthStore } from '../../src/stores/auth';
import { usePushStore } from '../../src/stores/push';
import { useWorkspaceStore } from '../../src/stores/workspace';

const PUSH_LABELS = {
  unknown: 'Checking…',
  undetermined: 'Off',
  denied: 'Blocked in system settings',
  enabled: 'On for this device',
  unsupported: 'Not available in this build',
  error: 'Failed to register',
} as const;

function Row({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.rowBetween}>
      <Text style={styles.dim}>{label}</Text>
      <Text style={[styles.body, { flexShrink: 1, textAlign: 'right' }]} numberOfLines={1}>
        {value}
      </Text>
    </View>
  );
}

export default function SettingsScreen() {
  const email = useAuthStore((s) => s.session?.email ?? null);
  const signOut = useAuthStore((s) => s.signOut);
  const { orgs, currentOrgId } = useWorkspaceStore();
  const push = usePushStore();
  const org = orgs.find((o) => o.id === currentOrgId);

  const handleSignOut = async () => {
    await push.unregister();
    await signOut();
  };

  return (
    <SafeAreaView style={styles.screen} edges={['top']}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.heading}>SETTINGS</Text>

        <SectionTitle>Account</SectionTitle>
        <Card>
          <Row label="Signed in as" value={email ?? 'Unknown'} />
          <Row label="Organization" value={org ? `${org.name} (${org.user_role})` : 'None'} />
        </Card>

        <SectionTitle>Alerts</SectionTitle>
        <Card>
          <Row label="Push notifications" value={PUSH_LABELS[push.status]} />
          {push.error ? <Text style={styles.errorText}>{push.error}</Text> : null}
          <Body>
            Registered devices get a notification when a server in the org records a new detection. Servers
            don't upload detections yet, so no alerts are sent today.
          </Body>
          {org && (push.status === 'undetermined' || push.status === 'error') ? (
            <Button label="Turn on alerts" variant="outline" onPress={() => void push.enable(org.id)} />
          ) : null}
          {push.status === 'denied' || push.status === 'enabled' ? (
            <Button label="Open system settings" variant="outline" onPress={() => void Linking.openSettings()} />
          ) : null}
        </Card>

        <SectionTitle>About</SectionTitle>
        <Card>
          <Row label="Version" value={config.appVersion} />
          <Row label="API" value={config.apiUrl} />
        </Card>

        <View style={{ marginTop: 16 }}>
          <Button label="Sign out" variant="danger" onPress={() => void handleSignOut()} />
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

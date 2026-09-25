import React, { useEffect } from 'react';
import { Text } from 'react-native';
import { Redirect, Tabs } from 'expo-router';
import { theme } from '../../src/config';
import { useAuthStore } from '../../src/stores/auth';
import { usePushStore } from '../../src/stores/push';
import { useWorkspaceStore } from '../../src/stores/workspace';

const ICONS: Record<string, string> = { index: '◉', servers: '▤', scans: '◈', settings: '⚙' };

export default function TabsLayout() {
  const status = useAuthStore((s) => s.status);
  const userId = useAuthStore((s) => s.session?.userId ?? null);
  const load = useWorkspaceStore((s) => s.load);
  const reset = useWorkspaceStore((s) => s.reset);
  const currentOrgId = useWorkspaceStore((s) => s.currentOrgId);
  const syncPush = usePushStore((s) => s.sync);

  useEffect(() => {
    if (!userId) return;
    void load();
    return reset;
  }, [userId, load, reset]);

  // Registers the device for the org's alerts only if permission was already
  // granted; asking happens from the explanation card, never on launch.
  useEffect(() => {
    if (currentOrgId) void syncPush(currentOrgId);
  }, [currentOrgId, syncPush]);

  if (status === 'signedOut') return <Redirect href="/login" />;

  return (
    <Tabs
      screenOptions={({ route }) => ({
        headerShown: false,
        tabBarStyle: { backgroundColor: theme.bg, borderTopColor: theme.border },
        tabBarActiveTintColor: theme.primary,
        tabBarInactiveTintColor: theme.dim,
        tabBarIcon: ({ color }) => <Text style={{ color, fontSize: 18 }}>{ICONS[route.name] ?? '●'}</Text>,
      })}
    >
      <Tabs.Screen name="index" options={{ title: 'Threats' }} />
      <Tabs.Screen name="servers" options={{ title: 'Servers' }} />
      <Tabs.Screen name="scans" options={{ title: 'Scans' }} />
      <Tabs.Screen name="settings" options={{ title: 'Settings' }} />
    </Tabs>
  );
}

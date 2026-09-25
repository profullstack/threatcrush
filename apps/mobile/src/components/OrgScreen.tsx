import React, { useState } from 'react';
import { Pressable, RefreshControl, ScrollView, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { config, theme } from '../config';
import type { Organization } from '../lib/api';
import { useWorkspaceStore } from '../stores/workspace';
import { Body, Code, EmptyState, ErrorBanner, LinkText, Loading, styles } from './ui';

function OrgPicker({ orgs, current }: { orgs: Organization[]; current: Organization }) {
  const [open, setOpen] = useState(false);
  const selectOrg = useWorkspaceStore((s) => s.selectOrg);

  return (
    <View style={{ gap: 6 }}>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel="Switch organization"
        disabled={orgs.length < 2}
        onPress={() => setOpen((o) => !o)}
        style={styles.row}
      >
        <Text style={[styles.dim, { fontSize: 13 }]}>
          {current.name}
          {orgs.length > 1 ? (open ? '  ▴' : '  ▾') : ''}
        </Text>
      </Pressable>
      {open
        ? orgs.map((org) => (
            <Pressable
              key={org.id}
              onPress={() => {
                setOpen(false);
                void selectOrg(org.id);
              }}
              style={{ paddingVertical: 6 }}
            >
              <Text style={{ color: org.id === current.id ? theme.primary : theme.text }}>
                {org.name} <Text style={styles.dim}>({org.user_role})</Text>
              </Text>
            </Pressable>
          ))
        : null}
    </View>
  );
}

/**
 * Shared frame for the org-scoped tabs: header with org switcher, pull to
 * refresh, load/error states, and the "no organization" empty state. Children
 * render only once an org is selected and its data has loaded.
 */
export function OrgScreen({
  title,
  children,
}: {
  title: string;
  children: (org: Organization) => React.ReactNode;
}) {
  const { orgs, currentOrgId, status, error, refresh } = useWorkspaceStore();
  const current = orgs.find((o) => o.id === currentOrgId) ?? null;

  let body: React.ReactNode;
  if (status === 'idle' || (status === 'loading' && !current)) {
    body = <Loading />;
  } else if (status === 'error' && error) {
    body = <ErrorBanner message={error} onRetry={() => void refresh()} />;
  } else if (!current) {
    body = (
      <EmptyState title="You're not in an organization yet">
        <Body>
          Servers, detections and scans belong to an organization. Create one on the web dashboard or
          from the CLI, then pull down to refresh.
        </Body>
        <LinkText label="Open threatcrush.com/dashboard" url={`${config.apiUrl}/dashboard`} />
        <Code>threatcrush orgs create "My Company"</Code>
      </EmptyState>
    );
  } else if (status === 'loading') {
    body = <Loading />;
  } else {
    body = children(current);
  }

  return (
    <SafeAreaView style={styles.screen} edges={['top']}>
      <ScrollView
        contentContainerStyle={styles.content}
        refreshControl={
          <RefreshControl
            refreshing={status === 'loading' && !!current}
            onRefresh={() => void refresh()}
            tintColor={theme.primary}
          />
        }
      >
        <View style={{ gap: 2 }}>
          <Text style={styles.heading}>{title}</Text>
          {current ? <OrgPicker orgs={orgs} current={current} /> : null}
        </View>
        {body}
      </ScrollView>
    </SafeAreaView>
  );
}

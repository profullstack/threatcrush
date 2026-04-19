import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import type { Stats } from '../lib/api';
import { formatNumber, formatUptime } from '../lib/utils';

interface StatsBarProps {
  stats: Stats;
}

function StatItem({ label, value, color = '#e0e0e0' }: { label: string; value: string; color?: string }) {
  return (
    <View style={styles.item}>
      <Text style={[styles.value, { color }]}>{value}</Text>
      <Text style={styles.label}>{label}</Text>
    </View>
  );
}

export function StatsBar({ stats }: StatsBarProps) {
  return (
    <View style={styles.card}>
      <StatItem label="Events" value={formatNumber(stats.eventsToday)} />
      <StatItem label="Blocked" value={formatNumber(stats.threatsBlocked)} color="#00ff41" />
      <StatItem label="Uptime" value={formatUptime(stats.uptimeHours)} />
      <StatItem label="Modules" value={`${stats.modulesActive}/${stats.modulesTotal}`} />
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    flexDirection: 'row',
    backgroundColor: '#111111',
    borderWidth: 1,
    borderColor: '#222222',
    borderRadius: 12,
    padding: 16,
  },
  item: {
    flex: 1,
    alignItems: 'center',
  },
  value: {
    fontSize: 18,
    fontWeight: '700',
  },
  label: {
    color: '#666666',
    fontSize: 12,
    marginTop: 4,
  },
});

import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import type { ThreatEvent } from '../lib/api';
import { ThreatBadge } from './ThreatBadge';
import { timeAgo } from '../lib/utils';

interface EventCardProps {
  event: ThreatEvent;
}

export function EventCard({ event }: EventCardProps) {
  return (
    <View style={styles.card}>
      <View style={styles.headerRow}>
        <View style={styles.metaRow}>
          <ThreatBadge severity={event.severity} />
          <Text style={styles.module}>{event.module}</Text>
        </View>
        <Text style={styles.dim}>{timeAgo(event.timestamp)}</Text>
      </View>
      <Text style={styles.message}>{event.message}</Text>
      {event.source ? <Text style={styles.dim}>Source: {event.source}</Text> : null}
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: '#111111',
    borderBottomWidth: 1,
    borderBottomColor: '#222222',
    paddingHorizontal: 16,
    paddingVertical: 12,
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 4,
  },
  metaRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  module: {
    color: '#666666',
    fontSize: 12,
  },
  message: {
    color: '#e0e0e0',
    fontSize: 14,
  },
  dim: {
    color: '#666666',
    fontSize: 12,
    marginTop: 4,
  },
});

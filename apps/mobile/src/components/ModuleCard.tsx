import React from 'react';
import { View, Text, Pressable, StyleSheet } from 'react-native';
import type { Module } from '../lib/api';

interface ModuleCardProps {
  module: Module;
  onToggle: () => void;
}

export function ModuleCard({ module: mod, onToggle }: ModuleCardProps) {
  const statusColor = mod.status === 'running' ? '#00ff41' : mod.status === 'error' ? '#ff4444' : '#666666';

  return (
    <Pressable onPress={onToggle} style={styles.card}>
      <View style={styles.headerRow}>
        <View style={styles.nameRow}>
          <View style={[styles.dot, { backgroundColor: statusColor }]} />
          <Text style={styles.name}>{mod.name}</Text>
        </View>
        <View style={[styles.pill, { backgroundColor: mod.enabled ? '#00ff4122' : '#66666622' }]}>
          <Text style={[styles.pillText, { color: mod.enabled ? '#00ff41' : '#666666' }]}>
            {mod.enabled ? 'ON' : 'OFF'}
          </Text>
        </View>
      </View>
      <Text style={styles.description}>{mod.description}</Text>
      {mod.enabled ? <Text style={styles.dim}>{mod.eventsToday} events today</Text> : null}
    </Pressable>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: '#111111',
    borderWidth: 1,
    borderColor: '#222222',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 8,
  },
  nameRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  name: {
    color: '#e0e0e0',
    fontSize: 16,
    fontWeight: '700',
  },
  pill: {
    borderRadius: 999,
    paddingHorizontal: 12,
    paddingVertical: 4,
  },
  pillText: {
    fontSize: 12,
    fontWeight: '600',
  },
  description: {
    color: '#666666',
    fontSize: 14,
    marginBottom: 4,
  },
  dim: {
    color: '#666666',
    fontSize: 12,
  },
});

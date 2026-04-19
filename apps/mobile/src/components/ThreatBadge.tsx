import React from 'react';
import { View, Text } from 'react-native';
import type { Severity } from '../config';
import { getSeverityColor } from '../lib/utils';
import { s } from '../lib/styles';

interface ThreatBadgeProps {
  severity: Severity;
}

export function ThreatBadge({ severity }: ThreatBadgeProps) {
  const color = getSeverityColor(severity);
  const label = severity.toUpperCase();

  return (
    <View
      style={[s.rounded, { backgroundColor: color + '22', borderColor: color, borderWidth: 1, paddingHorizontal: 8, paddingVertical: 2 }]}
    >
      <Text style={{ color, fontSize: 10, fontWeight: '700' }}>{label}</Text>
    </View>
  );
}

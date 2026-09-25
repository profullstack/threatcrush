import React from 'react';
import { ActivityIndicator, Linking, Pressable, StyleSheet, Text, View, type ViewStyle } from 'react-native';
import { theme } from '../config';
import type { Severity } from '../lib/api';
import { SEVERITY_COLORS } from '../lib/utils';

export function Card({ children, style }: { children: React.ReactNode; style?: ViewStyle }) {
  return <View style={[styles.card, style]}>{children}</View>;
}

export function Badge({ label, color }: { label: string; color: string }) {
  return (
    <View style={[styles.badge, { backgroundColor: `${color}22`, borderColor: color }]}>
      <Text style={[styles.badgeText, { color }]}>{label.toUpperCase()}</Text>
    </View>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge label={severity} color={SEVERITY_COLORS[severity] ?? theme.dim} />;
}

export function Button({
  label,
  onPress,
  variant = 'primary',
  disabled,
}: {
  label: string;
  onPress: () => void;
  variant?: 'primary' | 'outline' | 'danger';
  disabled?: boolean;
}) {
  const color = variant === 'danger' ? theme.red : theme.primary;
  return (
    <Pressable
      accessibilityRole="button"
      onPress={onPress}
      disabled={disabled}
      style={({ pressed }) => [
        styles.button,
        variant === 'primary'
          ? { backgroundColor: color }
          : { borderColor: color, borderWidth: 1 },
        (pressed || disabled) && { opacity: 0.6 },
      ]}
    >
      <Text style={[styles.buttonText, { color: variant === 'primary' ? theme.bg : color }]}>{label}</Text>
    </Pressable>
  );
}

export function LinkText({ label, url }: { label: string; url: string }) {
  return (
    <Text style={styles.link} onPress={() => Linking.openURL(url)} accessibilityRole="link">
      {label}
    </Text>
  );
}

export function Code({ children }: { children: string }) {
  return (
    <Text selectable style={styles.code}>
      {children}
    </Text>
  );
}

export function EmptyState({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <Card style={styles.empty}>
      <Text style={styles.emptyTitle}>{title}</Text>
      {children}
    </Card>
  );
}

export function Body({ children }: { children: React.ReactNode }) {
  return <Text style={styles.body}>{children}</Text>;
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <Card style={styles.error}>
      <Text style={styles.errorText}>{message}</Text>
      {onRetry ? <Button label="Retry" variant="danger" onPress={onRetry} /> : null}
    </Card>
  );
}

export function Loading() {
  return (
    <View style={styles.loading}>
      <ActivityIndicator color={theme.primary} />
    </View>
  );
}

export function SectionTitle({ children }: { children: React.ReactNode }) {
  return <Text style={styles.section}>{children}</Text>;
}

export const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: theme.bg },
  content: { padding: 16, gap: 12, paddingBottom: 32 },
  card: {
    backgroundColor: theme.card,
    borderColor: theme.border,
    borderWidth: 1,
    borderRadius: 12,
    padding: 14,
    gap: 6,
  },
  row: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  rowBetween: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', gap: 8 },
  title: { color: theme.text, fontSize: 15, fontWeight: '600', flexShrink: 1 },
  dim: { color: theme.dim, fontSize: 12 },
  body: { color: theme.text, fontSize: 14, lineHeight: 20 },
  badge: { borderWidth: 1, borderRadius: 6, paddingHorizontal: 6, paddingVertical: 1 },
  badgeText: { fontSize: 10, fontWeight: '700', letterSpacing: 0.5 },
  button: { borderRadius: 10, paddingVertical: 12, paddingHorizontal: 16, alignItems: 'center' },
  buttonText: { fontSize: 15, fontWeight: '700' },
  link: { color: theme.primary, fontSize: 14, textDecorationLine: 'underline' },
  code: {
    color: theme.primary,
    fontFamily: 'monospace',
    fontSize: 13,
    backgroundColor: theme.bg,
    borderRadius: 6,
    padding: 8,
  },
  empty: { gap: 10, paddingVertical: 20 },
  emptyTitle: { color: theme.text, fontSize: 16, fontWeight: '700' },
  error: { borderColor: theme.red, gap: 10 },
  errorText: { color: theme.red, fontSize: 14 },
  loading: { padding: 32, alignItems: 'center' },
  section: {
    color: theme.dim,
    fontSize: 12,
    fontWeight: '700',
    letterSpacing: 1,
    textTransform: 'uppercase',
    marginTop: 8,
  },
  heading: { color: theme.primary, fontSize: 22, fontWeight: '800', fontFamily: 'monospace' },
  bigNumber: { color: theme.text, fontSize: 28, fontWeight: '800' },
});

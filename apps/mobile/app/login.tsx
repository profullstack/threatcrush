import React, { useState } from 'react';
import { KeyboardAvoidingView, Platform, ScrollView, Text, TextInput, View } from 'react-native';
import { Redirect } from 'expo-router';
import { SafeAreaView } from 'react-native-safe-area-context';
import { config, theme } from '../src/config';
import { ApiError } from '../src/lib/api';
import { Body, Button, LinkText, styles } from '../src/components/ui';
import { useAuthStore } from '../src/stores/auth';

const inputStyle = {
  backgroundColor: theme.card,
  borderColor: theme.border,
  borderWidth: 1,
  borderRadius: 10,
  color: theme.text,
  paddingHorizontal: 14,
  paddingVertical: 12,
  fontSize: 16,
} as const;

export default function LoginScreen() {
  const status = useAuthStore((s) => s.status);
  const signIn = useAuthStore((s) => s.signIn);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (status === 'signedIn') return <Redirect href="/" />;

  const submit = async () => {
    if (!email.trim() || !password) {
      setError('Enter your email and password.');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await signIn(email, password);
    } catch (err) {
      if (err instanceof ApiError && err.body.needs_email_verification) {
        setError('Confirm your email first: open the link we sent you, then sign in again.');
      } else {
        setError(err instanceof Error ? err.message : 'Sign-in failed.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <SafeAreaView style={styles.screen}>
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
        <ScrollView contentContainerStyle={[styles.content, { flexGrow: 1, justifyContent: 'center' }]}>
          <View style={{ gap: 4, marginBottom: 16 }}>
            <Text style={[styles.heading, { fontSize: 32 }]}>THREATCRUSH</Text>
            <Body>Sign in with your threatcrush.com account to see your servers, detections and scans.</Body>
          </View>

          <TextInput
            value={email}
            onChangeText={setEmail}
            placeholder="you@example.com"
            placeholderTextColor={theme.dim}
            keyboardType="email-address"
            autoCapitalize="none"
            autoComplete="email"
            textContentType="username"
            style={inputStyle}
          />
          <TextInput
            value={password}
            onChangeText={setPassword}
            placeholder="Password"
            placeholderTextColor={theme.dim}
            secureTextEntry
            autoComplete="password"
            textContentType="password"
            onSubmitEditing={() => void submit()}
            style={inputStyle}
          />

          {error ? <Text style={styles.errorText}>{error}</Text> : null}

          <Button label={submitting ? 'Signing in…' : 'Sign in'} onPress={() => void submit()} disabled={submitting} />

          <View style={{ gap: 8, marginTop: 12 }}>
            <Text style={styles.dim}>No account? Accounts are created on the web.</Text>
            <LinkText label="Create an account" url={`${config.apiUrl}/auth/signup`} />
            <LinkText label="Forgot password" url={`${config.apiUrl}/auth/login`} />
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

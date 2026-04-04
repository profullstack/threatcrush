import React, { useState } from 'react';
import { View, Text, TextInput, Pressable, ScrollView, Alert } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useAuthStore } from '../../src/stores/auth';
import { generateKeyPair } from '../../src/lib/crypto';
import { config } from '../../src/config';

function SettingsSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View className="mb-6">
      <Text className="text-txt font-bold text-sm mb-3 uppercase tracking-wider">{title}</Text>
      <View className="border border-border rounded-lg p-4" style={{ backgroundColor: '#111111' }}>
        {children}
      </View>
    </View>
  );
}

export default function SettingsScreen() {
  const { email, licenseKey, daemonUrl, e2eEnabled, publicKey, setDaemonUrl, setE2eEnabled, setPublicKey, logout } =
    useAuthStore();
  const [urlInput, setUrlInput] = useState(daemonUrl);
  const [keyInput, setKeyInput] = useState(licenseKey || '');

  const handleSaveUrl = () => {
    setDaemonUrl(urlInput);
  };

  const handleGenerateKeys = () => {
    const keys = generateKeyPair();
    setPublicKey(keys.publicKey);
    setE2eEnabled(true);
  };

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: '#0a0a0a' }}>
      <ScrollView className="flex-1 px-4">
        {/* Header */}
        <View className="py-4">
          <Text style={{ color: '#00ff41', fontSize: 20, fontWeight: '800', fontFamily: 'monospace' }}>
            SETTINGS
          </Text>
          <Text className="text-dim text-xs mt-1">Configuration & connectivity</Text>
        </View>

        {/* Daemon connection */}
        <SettingsSection title="Daemon Connection">
          <Text className="text-dim text-xs mb-2">Daemon URL</Text>
          <TextInput
            value={urlInput}
            onChangeText={setUrlInput}
            placeholder="https://threatcrush.com"
            placeholderTextColor="#666666"
            autoCapitalize="none"
            className="border border-border rounded px-3 py-2 text-txt mb-3"
            style={{ backgroundColor: '#0a0a0a', color: '#e0e0e0' }}
          />
          <Pressable
            onPress={handleSaveUrl}
            className="rounded py-2 items-center"
            style={{ backgroundColor: '#00ff4122', borderWidth: 1, borderColor: '#00ff41' }}
          >
            <Text style={{ color: '#00ff41', fontWeight: '600', fontSize: 13 }}>Save</Text>
          </Pressable>
        </SettingsSection>

        {/* Pairing */}
        <SettingsSection title="Device Pairing">
          <View className="items-center py-6">
            <View
              className="border border-border rounded-lg items-center justify-center mb-3"
              style={{ width: 160, height: 160, backgroundColor: '#0a0a0a' }}
            >
              <Text className="text-dim text-xs">QR Scanner</Text>
              <Text className="text-dim text-xs">Placeholder</Text>
            </View>
            <Text className="text-dim text-xs text-center">
              Scan QR code from your ThreatCrush daemon to pair
            </Text>
          </View>
        </SettingsSection>

        {/* License */}
        <SettingsSection title="License">
          <Text className="text-dim text-xs mb-2">License Key</Text>
          <TextInput
            value={keyInput}
            onChangeText={setKeyInput}
            placeholder="TC-XXXX-XXXX-XXXX"
            placeholderTextColor="#666666"
            autoCapitalize="none"
            className="border border-border rounded px-3 py-2 text-txt"
            style={{ backgroundColor: '#0a0a0a', color: '#e0e0e0' }}
          />
          {email && (
            <Text className="text-dim text-xs mt-2">Signed in as: {email}</Text>
          )}
        </SettingsSection>

        {/* E2E Encryption */}
        <SettingsSection title="E2E Encryption">
          <View className="flex-row items-center justify-between mb-3">
            <Text className="text-txt text-sm">Status</Text>
            <Text style={{ color: e2eEnabled ? '#00ff41' : '#ff4444', fontWeight: '600', fontSize: 13 }}>
              {e2eEnabled ? 'ENABLED' : 'DISABLED'}
            </Text>
          </View>
          {publicKey && (
            <View className="mb-3">
              <Text className="text-dim text-xs mb-1">Public Key</Text>
              <Text className="text-dim text-xs" numberOfLines={1} ellipsizeMode="middle">
                {publicKey}
              </Text>
            </View>
          )}
          {!e2eEnabled && (
            <Pressable
              onPress={handleGenerateKeys}
              className="rounded py-2 items-center"
              style={{ backgroundColor: '#00ff4122', borderWidth: 1, borderColor: '#00ff41' }}
            >
              <Text style={{ color: '#00ff41', fontWeight: '600', fontSize: 13 }}>Generate Keys</Text>
            </Pressable>
          )}
        </SettingsSection>

        {/* App info */}
        <SettingsSection title="About">
          <View className="flex-row justify-between mb-1">
            <Text className="text-dim text-sm">Version</Text>
            <Text className="text-txt text-sm">{config.appVersion}</Text>
          </View>
          <View className="flex-row justify-between">
            <Text className="text-dim text-sm">API</Text>
            <Text className="text-txt text-sm" numberOfLines={1}>{daemonUrl}</Text>
          </View>
        </SettingsSection>

        {/* Logout */}
        {email && (
          <Pressable
            onPress={logout}
            className="rounded-lg py-3 items-center mb-8"
            style={{ borderWidth: 1, borderColor: '#ff4444' }}
          >
            <Text style={{ color: '#ff4444', fontWeight: '600' }}>Sign Out</Text>
          </Pressable>
        )}

        <View className="h-8" />
      </ScrollView>
    </SafeAreaView>
  );
}

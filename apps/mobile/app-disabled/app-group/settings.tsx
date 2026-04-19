import React, { useState } from 'react';
import { View, Text, TextInput, Pressable, ScrollView, Alert } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useAuthStore } from '../../src/stores/auth';
import { generateKeyPair } from '../../src/lib/crypto';
import { config } from '../../src/config';

function SettingsSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View >
      <Text >{title}</Text>
      <View  style={{ backgroundColor: '#111111' }}>
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
      <ScrollView >
        {/* Header */}
        <View >
          <Text style={{ color: '#00ff41', fontSize: 20, fontWeight: '800', fontFamily: 'monospace' }}>
            SETTINGS
          </Text>
          <Text >Configuration & connectivity</Text>
        </View>

        {/* Daemon connection */}
        <SettingsSection title="Daemon Connection">
          <Text >Daemon URL</Text>
          <TextInput
            value={urlInput}
            onChangeText={setUrlInput}
            placeholder="https://threatcrush.com"
            placeholderTextColor="#666666"
            autoCapitalize="none"
            
            style={{ backgroundColor: '#0a0a0a', color: '#e0e0e0' }}
          />
          <Pressable
            onPress={handleSaveUrl}
            
            style={{ backgroundColor: '#00ff4122', borderWidth: 1, borderColor: '#00ff41' }}
          >
            <Text style={{ color: '#00ff41', fontWeight: '600', fontSize: 13 }}>Save</Text>
          </Pressable>
        </SettingsSection>

        {/* Pairing */}
        <SettingsSection title="Device Pairing">
          <View >
            <View
              
              style={{ width: 160, height: 160, backgroundColor: '#0a0a0a' }}
            >
              <Text >QR Scanner</Text>
              <Text >Placeholder</Text>
            </View>
            <Text >
              Scan QR code from your ThreatCrush daemon to pair
            </Text>
          </View>
        </SettingsSection>

        {/* License */}
        <SettingsSection title="License">
          <Text >License Key</Text>
          <TextInput
            value={keyInput}
            onChangeText={setKeyInput}
            placeholder="TC-XXXX-XXXX-XXXX"
            placeholderTextColor="#666666"
            autoCapitalize="none"
            
            style={{ backgroundColor: '#0a0a0a', color: '#e0e0e0' }}
          />
          {email && (
            <Text >Signed in as: {email}</Text>
          )}
        </SettingsSection>

        {/* E2E Encryption */}
        <SettingsSection title="E2E Encryption">
          <View >
            <Text >Status</Text>
            <Text style={{ color: e2eEnabled ? '#00ff41' : '#ff4444', fontWeight: '600', fontSize: 13 }}>
              {e2eEnabled ? 'ENABLED' : 'DISABLED'}
            </Text>
          </View>
          {publicKey && (
            <View >
              <Text >Public Key</Text>
              <Text  numberOfLines={1} ellipsizeMode="middle">
                {publicKey}
              </Text>
            </View>
          )}
          {!e2eEnabled && (
            <Pressable
              onPress={handleGenerateKeys}
              
              style={{ backgroundColor: '#00ff4122', borderWidth: 1, borderColor: '#00ff41' }}
            >
              <Text style={{ color: '#00ff41', fontWeight: '600', fontSize: 13 }}>Generate Keys</Text>
            </Pressable>
          )}
        </SettingsSection>

        {/* App info */}
        <SettingsSection title="About">
          <View >
            <Text >Version</Text>
            <Text >{config.appVersion}</Text>
          </View>
          <View >
            <Text >API</Text>
            <Text  numberOfLines={1}>{daemonUrl}</Text>
          </View>
        </SettingsSection>

        {/* Logout */}
        {email && (
          <Pressable
            onPress={logout}
            
            style={{ borderWidth: 1, borderColor: '#ff4444' }}
          >
            <Text style={{ color: '#ff4444', fontWeight: '600' }}>Sign Out</Text>
          </Pressable>
        )}

        <View  />
      </ScrollView>
    </SafeAreaView>
  );
}

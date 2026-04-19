import React, { useState } from 'react';
import { View, Text, TextInput, Pressable, KeyboardAvoidingView, Platform } from 'react-native';
import { router } from 'expo-router';
import { useAuthStore } from '../../src/stores/auth';

export default function LoginScreen() {
  const [email, setEmail] = useState('');
  const [licenseKey, setLicenseKey] = useState('');
  const [error, setError] = useState('');
  const login = useAuthStore((s) => s.login);

  const handleLogin = async () => {
    if (!email.trim()) {
      setError('Email is required');
      return;
    }
    try {
      await login(email.trim(), licenseKey.trim());
      router.replace('/(app)');
    } catch (e) {
      setError('Login failed. Check your credentials.');
    }
  };

  const handleSkip = () => {
    router.replace('/(app)');
  };

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      
      style={{ backgroundColor: '#0a0a0a' }}
    >
      <View >
        <Text style={{ color: '#00ff41', fontSize: 36, fontWeight: '800', fontFamily: 'monospace' }}>
          THREATCRUSH
        </Text>
        <Text >Personal threat intelligence</Text>
      </View>

      <View >
        <View>
          <Text >Email</Text>
          <TextInput
            value={email}
            onChangeText={setEmail}
            placeholder="you@example.com"
            placeholderTextColor="#666666"
            keyboardType="email-address"
            autoCapitalize="none"
            
            style={{ backgroundColor: '#111111', color: '#e0e0e0' }}
          />
        </View>

        <View>
          <Text >License Key</Text>
          <TextInput
            value={licenseKey}
            onChangeText={setLicenseKey}
            placeholder="TC-XXXX-XXXX-XXXX"
            placeholderTextColor="#666666"
            autoCapitalize="none"
            
            style={{ backgroundColor: '#111111', color: '#e0e0e0' }}
          />
        </View>

        {error ? <Text style={{ color: '#ff4444' }} >{error}</Text> : null}

        <Pressable
          onPress={handleLogin}
          
          style={{ backgroundColor: '#00ff41' }}
        >
          <Text style={{ color: '#0a0a0a', fontWeight: '700', fontSize: 16 }}>Sign In</Text>
        </Pressable>

        <Pressable onPress={handleSkip} >
          <Text >Skip → use demo mode</Text>
        </Pressable>
      </View>

      <Text >
        Don't have an account? Enter your email to join the waitlist.
      </Text>
    </KeyboardAvoidingView>
  );
}

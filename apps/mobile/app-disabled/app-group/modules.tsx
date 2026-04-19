import React from 'react';
import { View, Text, ScrollView, Pressable } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useEventsStore } from '../../src/stores/events';
import { ModuleCard } from '../../src/components/ModuleCard';

const AVAILABLE_MODULES = [
  { id: 'ad-block', name: 'Ad Blocker', description: 'Network-level ad and tracker blocking' },
  { id: 'tor-guard', name: 'Tor Guard', description: 'Block/monitor Tor exit node traffic' },
  { id: 'cert-watch', name: 'Cert Watcher', description: 'Monitor SSL certificate changes' },
];

export default function ModulesScreen() {
  const { modules, toggleModule } = useEventsStore();

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: '#0a0a0a' }}>
      <ScrollView >
        {/* Header */}
        <View >
          <Text style={{ color: '#00ff41', fontSize: 20, fontWeight: '800', fontFamily: 'monospace' }}>
            MODULES
          </Text>
          <Text >Manage security modules</Text>
        </View>

        {/* Installed modules */}
        <Text >Installed</Text>
        {modules.map((mod) => (
          <ModuleCard key={mod.id} module={mod} onToggle={() => toggleModule(mod.id)} />
        ))}

        {/* Available modules */}
        <Text >Available</Text>
        {AVAILABLE_MODULES.map((mod) => (
          <View
            key={mod.id}
            
            style={{ backgroundColor: '#111111' }}
          >
            <View >
              <Text >{mod.name}</Text>
              <Text >{mod.description}</Text>
            </View>
            <Pressable
              
              style={{ borderWidth: 1, borderColor: '#00ff41' }}
            >
              <Text style={{ color: '#00ff41', fontSize: 12, fontWeight: '600' }}>INSTALL</Text>
            </Pressable>
          </View>
        ))}

        <View  />
      </ScrollView>
    </SafeAreaView>
  );
}

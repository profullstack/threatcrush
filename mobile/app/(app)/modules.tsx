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
      <ScrollView className="flex-1 px-4">
        {/* Header */}
        <View className="py-4">
          <Text style={{ color: '#00ff41', fontSize: 20, fontWeight: '800', fontFamily: 'monospace' }}>
            MODULES
          </Text>
          <Text className="text-dim text-xs mt-1">Manage security modules</Text>
        </View>

        {/* Installed modules */}
        <Text className="text-txt font-bold text-sm mb-3 uppercase tracking-wider">Installed</Text>
        {modules.map((mod) => (
          <ModuleCard key={mod.id} module={mod} onToggle={() => toggleModule(mod.id)} />
        ))}

        {/* Available modules */}
        <Text className="text-txt font-bold text-sm mb-3 mt-4 uppercase tracking-wider">Available</Text>
        {AVAILABLE_MODULES.map((mod) => (
          <View
            key={mod.id}
            className="border border-border rounded-lg p-4 mb-3 flex-row items-center justify-between"
            style={{ backgroundColor: '#111111' }}
          >
            <View className="flex-1 mr-4">
              <Text className="text-txt font-bold text-base">{mod.name}</Text>
              <Text className="text-dim text-sm mt-1">{mod.description}</Text>
            </View>
            <Pressable
              className="rounded-lg px-4 py-2"
              style={{ borderWidth: 1, borderColor: '#00ff41' }}
            >
              <Text style={{ color: '#00ff41', fontSize: 12, fontWeight: '600' }}>INSTALL</Text>
            </Pressable>
          </View>
        ))}

        <View className="h-8" />
      </ScrollView>
    </SafeAreaView>
  );
}

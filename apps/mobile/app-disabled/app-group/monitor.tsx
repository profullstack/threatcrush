import React, { useCallback, useState } from 'react';
import { View, Text, FlatList, Pressable, RefreshControl } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useEventsStore } from '../../src/stores/events';
import { EventCard } from '../../src/components/EventCard';

export default function MonitorScreen() {
  const { events, modules, filterModule, setFilterModule, loadDemoData } = useEventsStore();
  const [refreshing, setRefreshing] = useState(false);

  const filteredEvents = filterModule
    ? events.filter((e) => e.module === filterModule)
    : events;

  const onRefresh = useCallback(() => {
    setRefreshing(true);
    loadDemoData();
    setTimeout(() => setRefreshing(false), 500);
  }, []);

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: '#0a0a0a' }}>
      {/* Header */}
      <View >
        <Text style={{ color: '#00ff41', fontSize: 20, fontWeight: '800', fontFamily: 'monospace' }}>
          LIVE MONITOR
        </Text>
        <Text >Real-time event stream</Text>
      </View>

      {/* Module filter */}
      <View >
        <View >
          <Pressable
            onPress={() => setFilterModule(null)}
            
            style={{
              backgroundColor: !filterModule ? '#00ff4122' : '#111111',
              borderWidth: 1,
              borderColor: !filterModule ? '#00ff41' : '#222222',
            }}
          >
            <Text style={{ color: !filterModule ? '#00ff41' : '#666666', fontSize: 12 }}>All</Text>
          </Pressable>
          {modules
            .filter((m) => m.enabled)
            .map((mod) => (
              <Pressable
                key={mod.id}
                onPress={() => setFilterModule(filterModule === mod.id ? null : mod.id)}
                
                style={{
                  backgroundColor: filterModule === mod.id ? '#00ff4122' : '#111111',
                  borderWidth: 1,
                  borderColor: filterModule === mod.id ? '#00ff41' : '#222222',
                }}
              >
                <Text style={{ color: filterModule === mod.id ? '#00ff41' : '#666666', fontSize: 12 }}>
                  {mod.name}
                </Text>
              </Pressable>
            ))}
        </View>
      </View>

      {/* Event list */}
      <FlatList
        data={filteredEvents}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => <EventCard event={item} />}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={onRefresh}
            tintColor="#00ff41"
            colors={['#00ff41']}
          />
        }
        ListEmptyComponent={
          <View >
            <Text >No events matching filter</Text>
          </View>
        }
      />
    </SafeAreaView>
  );
}

import React from 'react';
import { View, Text, ScrollView } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { useEventsStore } from '../../src/stores/events';
import { StatsBar } from '../../src/components/StatsBar';
import { EventCard } from '../../src/components/EventCard';

export default function DashboardScreen() {
  const { events, modules, stats } = useEventsStore();
  const recentEvents = events.slice(0, 5);

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: '#0a0a0a' }}>
      <ScrollView >
        {/* Header */}
        <View >
          <Text style={{ color: '#00ff41', fontSize: 24, fontWeight: '800', fontFamily: 'monospace' }}>
            THREATCRUSH
          </Text>
          <Text >THREAT INTELLIGENCE DASHBOARD</Text>
        </View>

        {/* Big threat counter */}
        <View
          
          style={{ backgroundColor: '#111111' }}
        >
          <Text >Threats Blocked</Text>
          <Text
            style={{
              color: '#00ff41',
              fontSize: 64,
              fontWeight: '800',
              fontFamily: 'monospace',
              textShadowColor: '#00ff4140',
              textShadowOffset: { width: 0, height: 0 },
              textShadowRadius: 20,
            }}
          >
            {stats.threatsBlocked}
          </Text>
          <Text >today</Text>
        </View>

        {/* Stats */}
        <View >
          <StatsBar stats={stats} />
        </View>

        {/* Module status grid */}
        <View >
          <Text >Module Status</Text>
          <View >
            {modules.map((mod) => (
              <View
                key={mod.id}
                
                style={{ backgroundColor: '#111111' }}
              >
                <View
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: 3,
                    backgroundColor: mod.status === 'running' ? '#00ff41' : '#ff4444',
                  }}
                />
                <Text >{mod.name}</Text>
              </View>
            ))}
          </View>
        </View>

        {/* Recent events */}
        <View >
          <Text >Recent Events</Text>
          <View >
            {recentEvents.map((event) => (
              <EventCard key={event.id} event={event} />
            ))}
          </View>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

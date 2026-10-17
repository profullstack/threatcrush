import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Animated, Easing, Image, Text, View } from 'react-native';
import {
  type AttackMapData,
  type AttackOrigin,
  MAP_ASPECT,
  MAP_COLORS,
  SEVERITY_RANK,
  project,
  severityColor,
  targetServer,
} from '@threatcrush/attack-map';
import { theme } from '../config';

const LAND = require('../../assets/attack-map-land.png');
const MAX_ARCS = 14;

/**
 * The attack map without a native drawing module: the land is a PNG drawn by
 * the shared renderer, and the arcs, comets and dots are plain animated views.
 */
export function AttackMapCard({ data }: { data: AttackMapData }) {
  const [width, setWidth] = useState(0);
  const height = width / MAP_ASPECT;

  const flights = useMemo(() => {
    const now = Date.now();
    return data.origins
      .filter((o) => now - Date.parse(o.lastSeen) < 15 * 60_000)
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.count - a.count)
      .slice(0, MAX_ARCS)
      .flatMap((o) => {
        const s = targetServer(o, data.servers);
        return s ? [{ origin: o, from: project(o.lat, o.lon), to: project(s.lat, s.lon) }] : [];
      });
  }, [data]);

  return (
    <View
      onLayout={(e) => setWidth(e.nativeEvent.layout.width)}
      style={{ width: '100%', height: height || undefined, aspectRatio: MAP_ASPECT, backgroundColor: MAP_COLORS.ocean, overflow: 'hidden', borderRadius: 8 }}
      accessibilityRole="image"
      accessibilityLabel={`Attack map: ${data.origins.length} sources`}
    >
      <Image source={LAND} style={{ position: 'absolute', width: '100%', height: '100%' }} resizeMode="stretch" />
      {width > 0 &&
        flights.map((f, i) => (
          <Flight key={f.origin.ip} origin={f.origin} from={f.from} to={f.to} width={width} height={height} delay={i * 230} />
        ))}
      {width > 0 &&
        data.origins.map((o) => {
          const p = project(o.lat, o.lon);
          const r = 2 + Math.min(4, Math.log2(1 + o.count) * 0.6);
          return (
            <View
              key={`dot-${o.ip}`}
              style={{
                position: 'absolute',
                left: p.x * width - r,
                top: p.y * height - r,
                width: r * 2,
                height: r * 2,
                borderRadius: r,
                backgroundColor: severityColor(o.severity),
                shadowColor: severityColor(o.severity),
                shadowOpacity: 0.9,
                shadowRadius: 6,
              }}
            />
          );
        })}
      {width > 0 && data.servers.map((s) => <ServerPin key={s.id} x={project(s.lat, s.lon).x * width} y={project(s.lat, s.lon).y * height} name={s.name} />)}
    </View>
  );
}

function Flight({
  origin,
  from,
  to,
  width,
  height,
  delay,
}: {
  origin: AttackOrigin;
  from: { x: number; y: number };
  to: { x: number; y: number };
  width: number;
  height: number;
  delay: number;
}) {
  const t = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    const loop = Animated.loop(
      Animated.sequence([
        Animated.delay(delay),
        Animated.timing(t, { toValue: 1, duration: 2200, easing: Easing.inOut(Easing.quad), useNativeDriver: true }),
        Animated.timing(t, { toValue: 0, duration: 0, useNativeDriver: true }),
      ]),
    );
    loop.start();
    return () => loop.stop();
  }, [t, delay]);

  // Straight across the map, the short way (an arc that wraps would streak).
  const x1 = from.x * width;
  const y1 = from.y * height;
  let x2 = to.x * width;
  if (Math.abs(x2 - x1) > width / 2) x2 += x2 > x1 ? -width : width;
  const y2 = to.y * height;
  const len = Math.hypot(x2 - x1, y2 - y1);
  const angle = Math.atan2(y2 - y1, x2 - x1);
  const color = severityColor(origin.severity);

  return (
    <>
      <View
        style={{
          position: 'absolute',
          left: (x1 + x2) / 2 - len / 2,
          top: (y1 + y2) / 2 - 0.5,
          width: len,
          height: 1,
          backgroundColor: color,
          opacity: 0.25,
          transform: [{ rotate: `${angle}rad` }],
        }}
      />
      <Animated.View
        style={{
          position: 'absolute',
          left: x1 - 3,
          top: y1 - 3,
          width: 6,
          height: 6,
          borderRadius: 3,
          backgroundColor: '#fff',
          shadowColor: color,
          shadowOpacity: 1,
          shadowRadius: 6,
          opacity: t.interpolate({ inputRange: [0, 0.1, 0.9, 1], outputRange: [0, 1, 1, 0] }),
          transform: [
            { translateX: t.interpolate({ inputRange: [0, 1], outputRange: [0, x2 - x1] }) },
            { translateY: t.interpolate({ inputRange: [0, 1], outputRange: [0, y2 - y1] }) },
          ],
        }}
      />
    </>
  );
}

function ServerPin({ x, y, name }: { x: number; y: number; name: string }) {
  const ring = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    const loop = Animated.loop(Animated.timing(ring, { toValue: 1, duration: 2000, useNativeDriver: true }));
    loop.start();
    return () => loop.stop();
  }, [ring]);
  return (
    <>
      <Animated.View
        style={{
          position: 'absolute',
          left: x - 14,
          top: y - 14,
          width: 28,
          height: 28,
          borderRadius: 14,
          borderWidth: 1.5,
          borderColor: MAP_COLORS.server,
          opacity: ring.interpolate({ inputRange: [0, 1], outputRange: [0.9, 0] }),
          transform: [{ scale: ring.interpolate({ inputRange: [0, 1], outputRange: [0.3, 1.4] }) }],
        }}
      />
      <View
        style={{
          position: 'absolute',
          left: x - 4,
          top: y - 4,
          width: 8,
          height: 8,
          backgroundColor: MAP_COLORS.server,
          transform: [{ rotate: '45deg' }],
        }}
      />
      <Text style={{ position: 'absolute', left: x + 8, top: y - 7, color: theme.primary, fontSize: 10, fontWeight: '700' }}>{name}</Text>
    </>
  );
}

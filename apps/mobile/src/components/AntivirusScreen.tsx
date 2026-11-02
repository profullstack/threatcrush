import React, { useState } from 'react';
import { Linking, Platform, ScrollView, Text, View } from 'react-native';
import * as FileSystem from 'expo-file-system';
import type { AvFileResult } from '@threatcrush/av';
import { config, theme } from '../config';
import { MAX_MOBILE_BYTES, nameFromUri, scanBase64, withReputation } from '../lib/av';
import { Body, Button, Card, SectionTitle, styles } from './ui';

/**
 * CrushAV on the phone. Android can grant access to a folder (Downloads,
 * WhatsApp media…) through the Storage Access Framework and every file in it
 * is scanned on the device. iOS gives no app a way to look at other apps'
 * files, so iPhone users scan picked files in the browser scanner instead.
 */

const SAF = FileSystem.StorageAccessFramework;

async function listFolder(uri: string, depth: number, out: string[]): Promise<void> {
  let children: string[];
  try {
    children = await SAF.readDirectoryAsync(uri);
  } catch {
    out.push(uri); // not a directory
    return;
  }
  for (const c of children) {
    if (out.length >= 2000) return;
    if (depth > 0) await listFolder(c, depth - 1, out);
    else out.push(c);
  }
}

export function AntivirusScreen() {
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState('');
  const [results, setResults] = useState<AvFileResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const scanFolder = async () => {
    setError(null);
    const perm = await SAF.requestDirectoryPermissionsAsync();
    if (!perm.granted) return;
    setBusy(true);
    setResults(null);
    try {
      const files: string[] = [];
      setProgress('Listing files…');
      await listFolder(perm.directoryUri, 2, files);
      const scanned: AvFileResult[] = [];
      for (let i = 0; i < files.length; i++) {
        const uri = files[i];
        const name = nameFromUri(uri);
        setProgress(`${i + 1} / ${files.length}  ${name}`);
        try {
          const info = await FileSystem.getInfoAsync(uri);
          const size = info.exists && 'size' in info ? (info.size ?? 0) : 0;
          if (size === 0 || size > MAX_MOBILE_BYTES) continue;
          const b64 = await FileSystem.readAsStringAsync(uri, { encoding: FileSystem.EncodingType.Base64 });
          scanned.push(await scanBase64(name, b64));
        } catch {
          scanned.push({ path: name, size: 0, sha256: null, kind: 'unknown', verdict: 'error', detections: [] });
        }
      }
      setProgress('Checking fingerprints against known malware…');
      setResults(await withReputation(scanned));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
      setProgress('');
    }
  };

  const flagged = (results ?? []).filter((r) => r.verdict === 'malicious' || r.verdict === 'suspicious');

  return (
    <ScrollView style={{ flex: 1, backgroundColor: theme.bg }} contentContainerStyle={{ padding: 16, paddingTop: 56, gap: 12 }}>
      <Text style={styles.title}>Virus scan</Text>
      <Body>
        CrushAV is free and open source. Files are scanned on this phone; only their fingerprints are checked online.
      </Body>

      {Platform.OS === 'android' ? (
        <Card>
          <SectionTitle>Scan a folder</SectionTitle>
          <Body>Pick Download (or any folder) and CrushAV checks every file in it and two levels below.</Body>
          <View style={{ marginTop: 12 }}>
            <Button label={busy ? 'Scanning…' : 'Choose a folder to scan'} onPress={() => void scanFolder()} disabled={busy} />
          </View>
          {progress ? <Text style={{ color: theme.dim, marginTop: 8 }} numberOfLines={1}>{progress}</Text> : null}
        </Card>
      ) : (
        <Card>
          <SectionTitle>iPhone and iPad</SectionTitle>
          <Body>
            iOS doesn&apos;t let any app look inside other apps, so there is nothing to sweep. To check a file you downloaded or
            were sent, open the scanner in Safari and pick it from Files.
          </Body>
        </Card>
      )}

      <Card>
        <SectionTitle>Scan files in the browser</SectionTitle>
        <Body>Works on any phone: choose files from your Downloads or Files app.</Body>
        <View style={{ marginTop: 12 }}>
          <Button label="Open the web scanner" variant="outline" onPress={() => void Linking.openURL(`${config.apiUrl}/antivirus#scan`)} />
        </View>
      </Card>

      {error ? <Text style={{ color: theme.red }}>{error}</Text> : null}

      {results ? (
        <Card>
          <SectionTitle>
            {`${results.length} files scanned · ${flagged.length ? `${flagged.length} flagged` : 'nothing found'}`}
          </SectionTitle>
          {flagged.map((r) => (
            <View key={r.path} style={{ marginTop: 10, borderLeftWidth: 3, borderLeftColor: r.verdict === 'malicious' ? theme.red : theme.yellow, paddingLeft: 8 }}>
              <Text style={{ color: theme.text, fontWeight: '600' }}>{r.path}</Text>
              {r.detections
                .filter((d) => d.impact !== 'info')
                .map((d) => (
                  <Text key={d.id} style={{ color: theme.dim, marginTop: 2 }}>
                    {d.name}: {d.description}
                  </Text>
                ))}
            </View>
          ))}
          {flagged.length ? (
            <Text style={{ color: theme.text, marginTop: 12 }}>
              Don&apos;t open flagged files. Delete them in your Files app; if you installed an app from one, uninstall it in
              Settings → Apps.
            </Text>
          ) : null}
        </Card>
      ) : null}
    </ScrollView>
  );
}

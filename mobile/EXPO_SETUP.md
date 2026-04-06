# ThreatCrush Mobile — Expo / EAS Setup

This mobile app is prepared to live under a separate Expo project identity.

## Current config

- `slug`: `threatcrush-mobile`
- `owner`: read from `EXPO_OWNER`
- `extra.eas.projectId`: read from `EXPO_PROJECT_ID`

## What still needs to happen

### 1) Log in to Expo / EAS

```bash
cd mobile
eas login
```

### 2) Create or link the separate Expo project

Use a separate Expo project from any old/default one.

Suggested identity:
- Expo slug: `threatcrush-mobile`
- Display name: `ThreatCrush`

Then either:

```bash
cd mobile
eas init
```

or link to an already-created Expo project.

### 3) Capture the resulting project identity

After linking, record:
- `EXPO_OWNER`
- `EXPO_PROJECT_ID`

These can be used locally and in GitHub Actions.

Example:

```bash
export EXPO_OWNER=your-expo-account
export EXPO_PROJECT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### 4) Add GitHub Actions secret

Required for `.github/workflows/mobile-release.yml`:
- `EXPO_TOKEN`

## Useful commands

### Preview/internal build

```bash
cd mobile
EXPO_OWNER=... EXPO_PROJECT_ID=... eas build --platform all --profile preview
```

### Production build

```bash
cd mobile
EXPO_OWNER=... EXPO_PROJECT_ID=... eas build --platform all --profile production
```

### Optional store submission

```bash
cd mobile
EXPO_OWNER=... EXPO_PROJECT_ID=... eas build --platform all --profile production --auto-submit
```

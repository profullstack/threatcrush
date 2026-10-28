import { app, safeStorage } from 'electron'
import { existsSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { Session, SessionStore } from './cloud'

/**
 * The desktop app's threatcrush.com session, in userData. Encrypted with the
 * OS keychain (safeStorage) when it is available; otherwise not stored at all,
 * so the app asks to sign in again next launch rather than leaving a token in
 * plain text.
 */
export function fileSessionStore(): SessionStore {
  const file = join(app.getPath('userData'), 'cloud-session.bin')
  let memory: Session | null = null
  return {
    load() {
      if (memory) return memory
      try {
        if (!existsSync(file) || !safeStorage.isEncryptionAvailable()) return null
        memory = JSON.parse(safeStorage.decryptString(readFileSync(file))) as Session
        return memory
      } catch {
        return null
      }
    },
    save(s) {
      memory = s
      try {
        if (!s) {
          rmSync(file, { force: true })
          return
        }
        if (safeStorage.isEncryptionAvailable()) writeFileSync(file, safeStorage.encryptString(JSON.stringify(s)), { mode: 0o600 })
      } catch {}
    },
  }
}

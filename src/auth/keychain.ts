import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';

const SECURITY = '/usr/bin/security';
const TIMEOUT_MS = 10000;
const ITEM_NOT_FOUND = 44;
const KEY_HEX = /^[0-9a-f]{64}$/;

export const KEYCHAIN_SERVICE = 'msteams-mcp-session-key';
export const KEYCHAIN_ACCOUNT = 'msteams-mcp';

let cachedKey: Buffer | null = null;

export function isKeychainSupported(): boolean {
  return process.platform === 'darwin';
}

function keychainError(detail: string): Error {
  return new Error(
    `Could not use the macOS Keychain for the session key (${detail}). ` +
    'Unlock the login keychain (it is locked in SSH sessions) and try again.'
  );
}

function readStoredKey(): Buffer | null {
  const res = spawnSync(SECURITY, ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-a', KEYCHAIN_ACCOUNT, '-w'], {
    encoding: 'utf8',
    timeout: TIMEOUT_MS,
  });
  if (res.error) throw keychainError(res.error.message);
  if (res.status === ITEM_NOT_FOUND) return null;
  if (res.status !== 0) throw keychainError(String(res.stderr || `exit ${res.status}`).trim());
  const hex = String(res.stdout).trim();
  if (!KEY_HEX.test(hex)) throw keychainError(`item "${KEYCHAIN_SERVICE}" does not hold a 32-byte hex key`);
  return Buffer.from(hex, 'hex');
}

/** The key goes through stdin of `security -i` so it never appears in the process list. */
function addKey(): void {
  const hex = randomBytes(32).toString('hex');
  const res = spawnSync(SECURITY, ['-i'], {
    input: `add-generic-password -s ${KEYCHAIN_SERVICE} -a ${KEYCHAIN_ACCOUNT} -w ${hex}\n`,
    encoding: 'utf8',
    timeout: TIMEOUT_MS,
  });
  if (res.error) throw keychainError(res.error.message);
}

/** Re-reads after adding: without -U the first stored key wins over concurrent creators. */
export function getOrCreateKeychainKey(): Buffer {
  if (cachedKey) return cachedKey;
  let key = readStoredKey();
  if (!key) {
    addKey();
    key = readStoredKey();
    if (!key) throw keychainError(`item "${KEYCHAIN_SERVICE}" was not created`);
  }
  cachedKey = key;
  return key;
}

export function resetKeychainCacheForTesting(): void {
  cachedKey = null;
}

/** Credential encryption: v2 = random key in the macOS Keychain, v1 = legacy hostname:username-derived key. */

import * as crypto from 'crypto';
import * as os from 'os';
import { isKeychainSupported, getOrCreateKeychainKey } from './keychain.js';

/** Algorithm for encryption. */
const ALGORITHM = 'aes-256-gcm';

/** Salt for the legacy key derivation. */
const SALT = 'teams-mcp-credential-salt-v1';

const LEGACY_VERSION = 1;
const KEYCHAIN_VERSION = 2;

function deriveLegacyKey(): Buffer {
  const machineId = `${os.hostname()}:${os.userInfo().username}`;
  return crypto.scryptSync(machineId, SALT, 32);
}

function keyFor(version: number): Buffer {
  if (version === KEYCHAIN_VERSION) return getOrCreateKeychainKey();
  if (version === LEGACY_VERSION) return deriveLegacyKey();
  throw new Error(`Unsupported encryption version: ${version}`);
}

function currentVersion(): number {
  return isKeychainSupported() ? KEYCHAIN_VERSION : LEGACY_VERSION;
}

/** Encrypted data format. */
export interface EncryptedData {
  /** Initialisation vector (hex). */
  iv: string;
  /** Encrypted content (hex). */
  content: string;
  /** Authentication tag (hex). */
  tag: string;
  /** Version marker for format compatibility. */
  version: number;
}

/**
 * Encrypts a string value.
 */
export function encrypt(plaintext: string): EncryptedData {
  const version = currentVersion();
  const key = keyFor(version);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString('hex'),
    content: encrypted,
    tag: tag.toString('hex'),
    version,
  };
}

/**
 * Decrypts encrypted data.
 *
 * @throws Error if decryption fails (wrong machine, corrupted data, etc.)
 */
export function decrypt(data: EncryptedData): string {
  const key = keyFor(data.version);
  const iv = Buffer.from(data.iv, 'hex');
  const tag = Buffer.from(data.tag, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(data.content, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/** True when the data should be re-encrypted with the current key. */
export function needsMigration(data: EncryptedData): boolean {
  return data.version !== currentVersion();
}

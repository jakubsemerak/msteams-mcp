/**
 * Unit tests for encryption utilities.
 */

import * as nodeCrypto from 'crypto';
import * as os from 'os';
import { describe, it, expect, vi, beforeEach } from 'vitest';

const KEYCHAIN_KEY = Buffer.alloc(32, 7);
const keychain = {
  isKeychainSupported: vi.fn(() => true),
  getOrCreateKeychainKey: vi.fn(() => KEYCHAIN_KEY),
};
vi.mock('./keychain.js', () => keychain);

const { encrypt, decrypt, needsMigration } = await import('./crypto.js');
type EncryptedData = ReturnType<typeof encrypt>;

function legacyKey(): Buffer {
  return nodeCrypto.scryptSync(`${os.hostname()}:${os.userInfo().username}`, 'teams-mcp-credential-salt-v1', 32);
}

function encryptWith(key: Buffer, plaintext: string, version: number): EncryptedData {
  const iv = nodeCrypto.randomBytes(16);
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
  const content = cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
  return { iv: iv.toString('hex'), content, tag: cipher.getAuthTag().toString('hex'), version };
}

function decryptWith(key: Buffer, data: EncryptedData): string {
  const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', key, Buffer.from(data.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(data.tag, 'hex'));
  return decipher.update(data.content, 'hex', 'utf8') + decipher.final('utf8');
}

beforeEach(() => {
  vi.clearAllMocks();
  keychain.isKeychainSupported.mockReturnValue(true);
  keychain.getOrCreateKeychainKey.mockReturnValue(KEYCHAIN_KEY);
});

describe('encrypt/decrypt round-trip', () => {
  it('encrypts and decrypts a simple string', () => {
    const plaintext = 'hello world';
    const encrypted = encrypt(plaintext);
    const decrypted = decrypt(encrypted);
    expect(decrypted).toBe(plaintext);
  });

  it('encrypts and decrypts JSON data', () => {
    const data = JSON.stringify({ token: 'abc123', expiry: 1705850000 });
    const encrypted = encrypt(data);
    const decrypted = decrypt(encrypted);
    expect(decrypted).toBe(data);
  });

  it('encrypts and decrypts empty string', () => {
    const encrypted = encrypt('');
    const decrypted = decrypt(encrypted);
    expect(decrypted).toBe('');
  });

  it('encrypts and decrypts unicode content', () => {
    const text = 'Hello 🌍 — "quotes" & <tags>';
    const encrypted = encrypt(text);
    const decrypted = decrypt(encrypted);
    expect(decrypted).toBe(text);
  });

  it('produces different ciphertext for same plaintext (unique IV)', () => {
    const plaintext = 'same input';
    const encrypted1 = encrypt(plaintext);
    const encrypted2 = encrypt(plaintext);
    // IVs should differ, so ciphertext differs
    expect(encrypted1.iv).not.toBe(encrypted2.iv);
    expect(encrypted1.content).not.toBe(encrypted2.content);
  });
});

describe('Keychain key (macOS)', () => {
  it('encrypts with the Keychain key, not the hostname-derived one', () => {
    const encrypted = encrypt('secret');

    expect(encrypted.version).toBe(2);
    expect(decryptWith(KEYCHAIN_KEY, encrypted)).toBe('secret');
    expect(() => decryptWith(legacyKey(), encrypted)).toThrow();
  });

  it('still decrypts files written with the legacy hostname-derived key', () => {
    const legacy = encryptWith(legacyKey(), 'old session', 1);

    expect(decrypt(legacy)).toBe('old session');
  });

  it('flags legacy files for re-encryption', () => {
    expect(needsMigration(encryptWith(legacyKey(), 'x', 1))).toBe(true);
    expect(needsMigration(encrypt('x'))).toBe(false);
  });

  it('propagates Keychain failures instead of falling back to the legacy key', () => {
    keychain.getOrCreateKeychainKey.mockImplementation(() => { throw new Error('Keychain locked'); });

    expect(() => encrypt('secret')).toThrow('Keychain locked');
  });
});

describe('platforms without a supported Keychain', () => {
  it('keeps the legacy key and format', () => {
    keychain.isKeychainSupported.mockReturnValue(false);

    const encrypted = encrypt('secret');

    expect(encrypted.version).toBe(1);
    expect(decryptWith(legacyKey(), encrypted)).toBe('secret');
    expect(needsMigration(encrypted)).toBe(false);
    expect(keychain.getOrCreateKeychainKey).not.toHaveBeenCalled();
  });
});

describe('decrypt error handling', () => {
  it('throws on tampered ciphertext', () => {
    const encrypted = encrypt('secret');
    const tampered: EncryptedData = {
      ...encrypted,
      content: encrypted.content.slice(0, -2) + 'xx',
    };
    expect(() => decrypt(tampered)).toThrow();
  });

  it('throws on tampered auth tag', () => {
    const encrypted = encrypt('secret');
    const tampered: EncryptedData = {
      ...encrypted,
      tag: 'a'.repeat(encrypted.tag.length),
    };
    expect(() => decrypt(tampered)).toThrow();
  });

  it('rejects unknown format versions', () => {
    expect(() => decrypt({ ...encrypt('x'), version: 3 })).toThrow(/version/);
  });
});

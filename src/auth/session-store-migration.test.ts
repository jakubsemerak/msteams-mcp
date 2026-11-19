import * as fs from 'fs';
import * as nodeCrypto from 'crypto';
import * as path from 'path';
import { describe, it, expect, vi, afterAll } from 'vitest';

const realOs = await vi.importActual<typeof import('os')>('os');
const home = fs.mkdtempSync(path.join(realOs.tmpdir(), 'teams-mcp-migration-'));
vi.mock('os', async () => ({ ...await vi.importActual<typeof import('os')>('os'), homedir: () => home }));

const KEYCHAIN_KEY = Buffer.alloc(32, 9);
vi.mock('./keychain.js', () => ({
  isKeychainSupported: () => true,
  getOrCreateKeychainKey: () => KEYCHAIN_KEY,
}));

const { readTokenCache, TOKEN_CACHE_PATH, ensureConfigDir } = await import('./session-store.js');

afterAll(() => fs.rmSync(home, { recursive: true, force: true }));

describe('legacy session file migration', () => {
  it('re-encrypts a legacy file with the Keychain key on first read', () => {
    const cache = { substrateToken: 'eyJ.tok', substrateTokenExpiry: 1, extractedAt: 2 };
    const legacyKey = nodeCrypto.scryptSync(`${realOs.hostname()}:${realOs.userInfo().username}`, 'teams-mcp-credential-salt-v1', 32);
    const iv = nodeCrypto.randomBytes(16);
    const cipher = nodeCrypto.createCipheriv('aes-256-gcm', legacyKey, iv);
    const content = cipher.update(JSON.stringify(cache), 'utf8', 'hex') + cipher.final('hex');
    ensureConfigDir();
    fs.writeFileSync(TOKEN_CACHE_PATH, JSON.stringify({ iv: iv.toString('hex'), content, tag: cipher.getAuthTag().toString('hex'), version: 1 }), { mode: 0o600 });

    expect(TOKEN_CACHE_PATH.startsWith(home)).toBe(true);
    expect(readTokenCache()).toEqual(cache);

    const rewritten = JSON.parse(fs.readFileSync(TOKEN_CACHE_PATH, 'utf8'));
    expect(rewritten.version).toBe(2);
    expect(fs.statSync(TOKEN_CACHE_PATH).mode & 0o777).toBe(0o600);
    expect(readTokenCache()).toEqual(cache);
  });
});

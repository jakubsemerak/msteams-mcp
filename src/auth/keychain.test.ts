import { describe, it, expect, vi, beforeEach } from 'vitest';

const spawnSync = vi.fn();
vi.mock('node:child_process', () => ({ spawnSync: (...args: unknown[]) => spawnSync(...args) }));

const { getOrCreateKeychainKey, resetKeychainCacheForTesting, KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT } = await import('./keychain.js');

const STORED = 'ab'.repeat(32);

function result(status: number, stdout = '', stderr = '') {
  return { status, stdout, stderr, error: undefined };
}

beforeEach(() => {
  spawnSync.mockReset();
  resetKeychainCacheForTesting();
});

describe('getOrCreateKeychainKey', () => {
  it('returns the stored 32-byte key without creating one', () => {
    spawnSync.mockReturnValueOnce(result(0, `${STORED}\n`));

    const key = getOrCreateKeychainKey();

    expect(key).toEqual(Buffer.from(STORED, 'hex'));
    expect(spawnSync).toHaveBeenCalledTimes(1);
    expect(spawnSync.mock.calls[0][0]).toBe('/usr/bin/security');
    expect(spawnSync.mock.calls[0][1]).toEqual(['find-generic-password', '-s', KEYCHAIN_SERVICE, '-a', KEYCHAIN_ACCOUNT, '-w']);
  });

  it('caches the key for the life of the process', () => {
    spawnSync.mockReturnValueOnce(result(0, STORED));

    getOrCreateKeychainKey();
    getOrCreateKeychainKey();

    expect(spawnSync).toHaveBeenCalledTimes(1);
  });

  it('creates a random key via stdin, never argv, then re-reads the stored one', () => {
    spawnSync
      .mockReturnValueOnce(result(44, '', 'could not be found'))
      .mockReturnValueOnce(result(0))
      .mockReturnValueOnce(result(0, STORED));

    const key = getOrCreateKeychainKey();

    const [cmd, args, opts] = spawnSync.mock.calls[1];
    expect(cmd).toBe('/usr/bin/security');
    expect(args).toEqual(['-i']);
    expect(opts.input).toMatch(new RegExp(`^add-generic-password -s ${KEYCHAIN_SERVICE} -a ${KEYCHAIN_ACCOUNT} -w [0-9a-f]{64}\\n$`));
    expect(opts.input).not.toContain(' -U');
    expect(JSON.stringify(args)).not.toMatch(/[0-9a-f]{64}/);
    expect(key).toEqual(Buffer.from(STORED, 'hex'));
  });

  it('fails with guidance when the Keychain cannot be read', () => {
    spawnSync.mockReturnValueOnce(result(36, '', 'User interaction is not allowed.'));

    expect(() => getOrCreateKeychainKey()).toThrow(/Keychain/);
  });

  it('rejects a stored value that is not a 32-byte hex key', () => {
    spawnSync.mockReturnValueOnce(result(0, 'not-a-key'));

    expect(() => getOrCreateKeychainKey()).toThrow(/Keychain/);
  });

  it('fails when the key is still missing after creating it', () => {
    spawnSync
      .mockReturnValueOnce(result(44))
      .mockReturnValueOnce(result(0))
      .mockReturnValueOnce(result(44));

    expect(() => getOrCreateKeychainKey()).toThrow(/Keychain/);
  });
});

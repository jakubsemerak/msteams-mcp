import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deflateSync } from 'node:zlib';
import { httpRequest } from '../utils/http.js';
import { requireIc3TokenAsync, getRegionConfig } from '../utils/auth-guards.js';
import { invalidateAccessToken } from '../auth/token-extractor.js';
import { ok, err } from '../types/result.js';
import { ErrorCode, createError } from '../types/errors.js';
import { imageDimensions, inlineImageHtml, isAllowedAmsUrl, uploadInlineImage } from './ams-api.js';

vi.mock('../utils/http.js', () => ({ httpRequest: vi.fn() }));
vi.mock('../utils/auth-guards.js', () => ({ requireIc3TokenAsync: vi.fn(), getRegionConfig: vi.fn() }));
vi.mock('../auth/token-extractor.js', () => ({ invalidateAccessToken: vi.fn() }));

function png(width: number, height: number): Buffer {
  const chunk = (type: string, data: Buffer) => {
    const length = Buffer.alloc(4); length.writeUInt32BE(data.length);
    return Buffer.concat([length, Buffer.from(type), data, Buffer.alloc(4)]);
  };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4); ihdr[8] = 8; ihdr[9] = 2;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(Buffer.alloc(1))), chunk('IEND', Buffer.alloc(0))]);
}

function jpeg(width: number, height: number): Buffer {
  const app0 = Buffer.from([0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
  const sof = Buffer.from([0xff, 0xc0, 0x00, 0x11, 0x08, height >> 8, height & 0xff, width >> 8, width & 0xff, 0x03, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
  return Buffer.concat([Buffer.from([0xff, 0xd8]), app0, sof, Buffer.from([0xff, 0xd9])]);
}

function gif(width: number, height: number): Buffer {
  const header = Buffer.alloc(13);
  header.write('GIF89a', 0, 'ascii'); header.writeUInt16LE(width, 6); header.writeUInt16LE(height, 8);
  return header;
}

describe('imageDimensions', () => {
  it('reads PNG, JPEG and GIF sizes', () => {
    expect(imageDimensions(png(519, 250))).toEqual({ width: 519, height: 250 });
    expect(imageDimensions(jpeg(1024, 768))).toEqual({ width: 1024, height: 768 });
    expect(imageDimensions(gif(16, 32))).toEqual({ width: 16, height: 32 });
  });

  it('returns null for anything that is not a supported image', () => {
    expect(imageDimensions(Buffer.from('%PDF-1.7 not an image'))).toBeNull();
    expect(imageDimensions(Buffer.alloc(0))).toBeNull();
  });
});

describe('isAllowedAmsUrl', () => {
  it('accepts the Microsoft AMS hosts over https only', () => {
    expect(isAllowedAmsUrl('https://eu-api.asm.skype.com')).toBe(true);
    expect(isAllowedAmsUrl('https://eu-prod.asyncgw.teams.microsoft.com')).toBe(true);
    expect(isAllowedAmsUrl('http://eu-api.asm.skype.com')).toBe(false);
    expect(isAllowedAmsUrl('https://asm.skype.com.evil.example')).toBe(false);
    expect(isAllowedAmsUrl('not a url')).toBe(false);
  });
});

describe('inlineImageHtml', () => {
  it('builds the AMSImage tag Teams uses, scaled down to the inline height', () => {
    expect(inlineImageHtml({ id: '0-weu-d1-abc', viewUrl: 'https://eu-api.asm.skype.com/v1/objects/0-weu-d1-abc/views/imgo', width: 1000, height: 500 }))
      .toBe('<p><img src="https://eu-api.asm.skype.com/v1/objects/0-weu-d1-abc/views/imgo" itemtype="http://schema.skype.com/AMSImage" itemscope="" width="500" height="250" alt="image" id="x_0-weu-d1-abc" itemid="0-weu-d1-abc"></p>');
  });

  it('keeps small images at their own size and omits unknown dimensions', () => {
    expect(inlineImageHtml({ id: 'a', viewUrl: 'https://x.asm.skype.com/v1/objects/a/views/imgo', width: 96, height: 96 })).toContain('width="96" height="96"');
    expect(inlineImageHtml({ id: 'a', viewUrl: 'https://x.asm.skype.com/v1/objects/a/views/imgo' })).not.toContain('width=');
  });
});

describe('uploadInlineImage', () => {
  let dir: string;
  let imagePath: string;
  const region = { amsUrl: 'https://eu-api.asm.skype.com', amsV2Url: 'https://eu-prod.asyncgw.teams.microsoft.com' };

  beforeEach(async () => {
    vi.clearAllMocks();
    dir = await mkdtemp(join(tmpdir(), 'ams-test-'));
    imagePath = join(dir, 'shot.png');
    await writeFile(imagePath, png(300, 150));
    vi.mocked(getRegionConfig).mockReturnValue(region as ReturnType<typeof getRegionConfig>);
    vi.mocked(requireIc3TokenAsync).mockResolvedValue(ok('ic3-token'));
  });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it('creates the object with read access for the conversation, then uploads the bytes', async () => {
    vi.mocked(httpRequest)
      .mockResolvedValueOnce(ok({ status: 201, headers: new Headers(), data: { id: 'obj-1' } }))
      .mockResolvedValueOnce(ok({ status: 201, headers: new Headers(), data: '' }));

    const result = await uploadInlineImage(imagePath, '48:notes');

    expect(result).toEqual(ok({ id: 'obj-1', viewUrl: 'https://eu-api.asm.skype.com/v1/objects/obj-1/views/imgo', width: 300, height: 150 }));
    const [createUrl, createInit] = vi.mocked(httpRequest).mock.calls[0];
    expect(createUrl).toBe('https://eu-prod.asyncgw.teams.microsoft.com/v1/objects/');
    expect(JSON.parse(createInit!.body as string)).toEqual({ type: 'pish/image', permissions: { '48:notes': ['read'] }, sharingMode: 'Inline', filename: 'shot.png' });
    const createHeaders = createInit!.headers as Record<string, string>;
    expect(createHeaders.Authorization).toBe('Bearer ic3-token');
    expect(createHeaders['X-Ams-Post-Sharing-Mode']).toBe('Inline');
    const [putUrl, putInit] = vi.mocked(httpRequest).mock.calls[1];
    expect(putUrl).toBe('https://eu-prod.asyncgw.teams.microsoft.com/v1/objects/obj-1/content/imgpsh');
    expect(putInit!.method).toBe('PUT');
    expect(Buffer.from(putInit!.body as Uint8Array).subarray(0, 4).toString('hex')).toBe('89504e47');
  });

  it('discards a rejected IC3 token and retries once with a fresh one', async () => {
    vi.mocked(requireIc3TokenAsync).mockResolvedValueOnce(ok('stale-token')).mockResolvedValueOnce(ok('fresh-token'));
    vi.mocked(httpRequest)
      .mockResolvedValueOnce(err(createError(ErrorCode.AUTH_EXPIRED, 'HTTP 401: Unauthorized')))
      .mockResolvedValueOnce(ok({ status: 201, headers: new Headers(), data: { id: 'obj-2' } }))
      .mockResolvedValueOnce(ok({ status: 201, headers: new Headers(), data: '' }));

    const result = await uploadInlineImage(imagePath, '48:notes');

    expect(result.ok).toBe(true);
    expect(invalidateAccessToken).toHaveBeenCalledWith('stale-token');
    expect((vi.mocked(httpRequest).mock.calls[1][1]!.headers as Record<string, string>).Authorization).toBe('Bearer fresh-token');
  });

  it('reports a second rejection without the login-expired code, so no auto-login starts', async () => {
    vi.mocked(httpRequest).mockResolvedValue(err(createError(ErrorCode.AUTH_EXPIRED, 'HTTP 401: Unauthorized')));

    const result = await uploadInlineImage(imagePath, '48:notes');

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe(ErrorCode.API_ERROR);
    expect(httpRequest).toHaveBeenCalledTimes(2);
  });

  it('rejects a file that is not a PNG, JPEG or GIF before any network call', async () => {
    const textPath = join(dir, 'notes.txt');
    await writeFile(textPath, 'hello');

    const result = await uploadInlineImage(textPath, '48:notes');

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe(ErrorCode.INVALID_INPUT);
    expect(httpRequest).not.toHaveBeenCalled();
  });

  it('refuses to send the token when the session has no allowed AMS host', async () => {
    vi.mocked(getRegionConfig).mockReturnValue({ amsUrl: 'https://evil.example', amsV2Url: 'https://evil.example' } as ReturnType<typeof getRegionConfig>);

    const result = await uploadInlineImage(imagePath, '48:notes');

    expect(result.ok).toBe(false);
    expect(httpRequest).not.toHaveBeenCalled();
  });
});

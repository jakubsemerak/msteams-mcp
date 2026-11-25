/**
 * Inline image uploads through AMS (async media service), the store behind
 * images pasted into Teams messages.
 *
 * Teams web creates an AMS object on the AMS v2 gateway with read access for the
 * conversation, uploads the bytes, and embeds the object's view URL as an
 * AMSImage `<img>` with the object id in the message's `amsreferences`.
 * AMS accepts the IC3 token, which is refreshed on demand.
 */

import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { httpRequest } from '../utils/http.js';
import { requireIc3TokenAsync, getRegionConfig } from '../utils/auth-guards.js';
import { invalidateAccessToken } from '../auth/token-extractor.js';
import { escapeHtmlChars } from '../utils/parsers.js';
import { ErrorCode, createError, type McpError } from '../types/errors.js';
import { type Result, ok, err } from '../types/result.js';
import { AMS_CLIENT_HEADERS, INLINE_IMAGE_MAX_HEIGHT } from '../constants.js';

/** An uploaded inline image, ready to embed in a message. */
export interface InlineImage {
  id: string;
  viewUrl: string;
  width?: number;
  height?: number;
}

/** Pixel size of a PNG, JPEG or GIF, or null for anything else. Pure. */
export function imageDimensions(bytes: Uint8Array): { width: number; height: number } | null {
  const b = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (b.length >= 24 && b.readUInt32BE(0) === 0x89504e47 && b.toString('ascii', 12, 16) === 'IHDR') {
    return { width: b.readUInt32BE(16), height: b.readUInt32BE(20) };
  }
  if (b.length >= 10 && (b.toString('ascii', 0, 6) === 'GIF87a' || b.toString('ascii', 0, 6) === 'GIF89a')) {
    return { width: b.readUInt16LE(6), height: b.readUInt16LE(8) };
  }
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8) {
    let offset = 2;
    while (offset + 9 <= b.length && b[offset] === 0xff) {
      const marker = b[offset + 1];
      const length = b.readUInt16BE(offset + 2);
      const isFrame = marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
      if (isFrame) return { width: b.readUInt16BE(offset + 7), height: b.readUInt16BE(offset + 5) };
      offset += 2 + length;
    }
  }
  return null;
}

/** Whether a base URL is an AMS host the IC3 token may be sent to. Pure. */
export function isAllowedAmsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password &&
      (/^[a-z0-9-]+\.asm\.skype\.com$/.test(url.hostname) || /^[a-z0-9-]+\.asyncgw\.teams\.microsoft\.com$/.test(url.hostname));
  } catch {
    return false;
  }
}

/** The AMSImage tag Teams embeds for an inline image, scaled to the inline height. Pure. */
export function inlineImageHtml(image: InlineImage): string {
  let size = '';
  if (image.width && image.height) {
    const scale = Math.min(1, INLINE_IMAGE_MAX_HEIGHT / image.height);
    size = ` width="${Math.round(image.width * scale)}" height="${Math.round(image.height * scale)}"`;
  }
  const id = escapeHtmlChars(image.id);
  return `<p><img src="${escapeHtmlChars(image.viewUrl)}" itemtype="http://schema.skype.com/AMSImage" itemscope=""${size} alt="image" id="x_${id}" itemid="${id}"></p>`;
}

/**
 * Maps an AMS auth failure so it never reaches the server's auto-login: a 401
 * discards the token and asks for one retry, a 403 becomes ACCESS_DENIED.
 */
function amsAuthError(error: McpError, token: string): { retry: boolean; error?: McpError } | null {
  if (error.code === ErrorCode.AUTH_EXPIRED) {
    invalidateAccessToken(token);
    return { retry: true };
  }
  if (error.code === ErrorCode.AUTH_REQUIRED) {
    return { retry: false, error: createError(ErrorCode.ACCESS_DENIED, `The Teams image service refused the upload: ${error.message}`, { retryable: false }) };
  }
  return null;
}

/**
 * Uploads a local PNG, JPEG or GIF to AMS with read access for the conversation.
 * A rejected IC3 token is discarded and the upload retried once with a fresh one;
 * auth failures are never returned as AUTH_EXPIRED/AUTH_REQUIRED.
 */
export async function uploadInlineImage(filePath: string, conversationId: string): Promise<Result<InlineImage>> {
  let bytes: Buffer;
  try {
    bytes = await readFile(filePath);
  } catch (error) {
    return err(createError(ErrorCode.INVALID_INPUT, `Cannot read image ${filePath}: ${error instanceof Error ? error.message : String(error)}`));
  }
  const dimensions = imageDimensions(bytes);
  if (!dimensions) {
    return err(createError(ErrorCode.INVALID_INPUT, `${filePath} is not a PNG, JPEG or GIF image.`));
  }

  const region = getRegionConfig();
  const amsUrl = region?.amsUrl;
  const gatewayUrl = region?.amsV2Url;
  if (!amsUrl || !gatewayUrl || !isAllowedAmsUrl(amsUrl) || !isAllowedAmsUrl(gatewayUrl)) {
    return err(createError(ErrorCode.API_ERROR, 'The Teams session has no AMS image service URL. Run teams_login and try again.', { retryable: false }));
  }

  for (let attempt = 1; attempt <= 2; attempt++) {
    const tokenResult = await requireIc3TokenAsync();
    if (!tokenResult.ok) return tokenResult;
    const token = tokenResult.value;
    const headers = { ...AMS_CLIENT_HEADERS, Accept: 'application/json', Authorization: `Bearer ${token}` };

    const created = await httpRequest<{ id?: string }>(`${gatewayUrl}/v1/objects/`, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'pish/image', permissions: { [conversationId]: ['read'] }, sharingMode: 'Inline', filename: basename(filePath) }),
    });
    let failure = created.ok ? null : created.error;
    const id = created.ok ? created.value.data?.id : undefined;
    if (created.ok && !id) return err(createError(ErrorCode.API_ERROR, 'The Teams image service returned no object id.'));

    if (id) {
      const uploaded = await httpRequest(`${gatewayUrl}/v1/objects/${encodeURIComponent(id)}/content/imgpsh`, {
        method: 'PUT',
        headers: { ...headers, 'Content-Type': 'application/octet-stream' },
        body: new Uint8Array(bytes),
      });
      if (uploaded.ok) {
        return ok({ id, viewUrl: `${amsUrl}/v1/objects/${encodeURIComponent(id)}/views/imgo`, ...dimensions });
      }
      failure = uploaded.error;
    }

    const auth = amsAuthError(failure!, token);
    if (!auth) return err(failure!);
    if (auth.error) return err(auth.error);
  }
  return err(createError(ErrorCode.API_ERROR, 'The Teams image service rejected the IC3 token twice.', { retryable: true }));
}

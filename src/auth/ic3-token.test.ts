import { describe, expect, it } from 'vitest';
import { extractIc3Token, extractRegionConfig } from './token-extractor.js';
import type { SessionState } from './session-store.js';

function token(aud: string, seconds = 3600) {
  return `eyJhbGciOiJub25lIn0.${Buffer.from(JSON.stringify({ aud, exp: Date.now() / 1000 + seconds })).toString('base64url')}.signature`;
}
function state(localStorage: Array<{ name: string; value: string }>): SessionState {
  return { cookies: [], origins: [{ origin: 'https://teams.microsoft.com', localStorage }] };
}
function accessToken(secret: string, target: string) {
  return { name: secret, value: JSON.stringify({ credentialType: 'AccessToken', target, secret }) };
}

describe('IC3 token selection', () => {
  it('picks the token whose audience is IC3 and ignores other Teams tokens', () => {
    const ic3 = token('https://ic3.teams.office.com');
    const spaces = token('https://api.spaces.skype.com', 7200);
    expect(extractIc3Token(state([accessToken(spaces, 'https://api.spaces.skype.com/.default'), accessToken(ic3, 'https://ic3.teams.office.com/.default')]))?.token).toBe(ic3);
    expect(extractIc3Token(state([accessToken(spaces, 'https://api.spaces.skype.com/.default')]))).toBeNull();
  });

  it('ignores an expired IC3 token', () => {
    expect(extractIc3Token(state([accessToken(token('https://ic3.teams.office.com', -1), 'https://ic3.teams.office.com/.default')]))).toBeNull();
  });
});

describe('region config AMS URLs', () => {
  it('reads the AMS and AMS v2 base URLs from DISCOVER-REGION-GTM', () => {
    const gtm = { name: 'DISCOVER-REGION-GTM', value: JSON.stringify({ item: {
      chatServiceAfd: 'https://teams.cloud.microsoft/api/chatsvc/emea',
      middleTier: 'https://teams.cloud.microsoft/api/mt/part/emea-03',
      ams: 'https://eu-api.asm.skype.com',
      amsV2: 'https://eu-prod.asyncgw.teams.microsoft.com',
    } }) };
    const config = extractRegionConfig(state([gtm]));
    expect(config?.amsUrl).toBe('https://eu-api.asm.skype.com');
    expect(config?.amsV2Url).toBe('https://eu-prod.asyncgw.teams.microsoft.com');
  });
});

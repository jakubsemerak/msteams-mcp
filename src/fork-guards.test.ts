import * as fs from 'fs';
import * as path from 'path';
import { describe, it, expect } from 'vitest';

const root = path.resolve(import.meta.dirname, '..');

describe('hardened fork guards', () => {
  it('disables dependency install scripts via .npmrc', () => {
    const npmrc = fs.readFileSync(path.join(root, '.npmrc'), 'utf8');
    expect(npmrc).toMatch(/^ignore-scripts=true$/m);
  });

  it('keeps CLAUDE.md as a symlink to AGENTS.md', () => {
    expect(fs.readlinkSync(path.join(root, 'CLAUDE.md'))).toBe('AGENTS.md');
  });

  it('keeps the upstream sync audit rules in AGENTS.md', () => {
    expect(fs.readFileSync(path.join(root, 'AGENTS.md'), 'utf8')).toContain('### Security audit before every upstream sync');
  });
});

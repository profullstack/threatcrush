import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { scanText } from '../text';

// The eight lines that made up eight of the ten `high` findings on
// thecodearcher/limen, copied verbatim from its READMEs. Kept as a block
// because the point is the shape of a whole documentation file rather than one
// clever line.
const README = `
## Generate migrations

\`\`\`bash
limen generate migrations \\
  -d postgres \\
  -c "postgres://user:password@localhost:5432/mydb?sslmode=disable"
\`\`\`

\`\`\`bash
limen migrate -c "postgres://user:pass@localhost/db"
limen status -c "postgres://user:pass@localhost/db"
goose -dir ./migrations postgres "postgres://user:pass@localhost/db?sslmode=disable" up
limen apply -database "postgres://user:pass@localhost/db?sslmode=disable" \\
\`\`\`

- \`DATABASE_URL\` environment variable set (e.g. \`postgres://user:pass@localhost:5432/limen?sslmode=disable\`)
`;

describe('a README that documents its DSN', () => {
  it('is not eight high findings', () => {
    expect(scanText('cmd/limen/README.md', README)).toHaveLength(0);
  });

  it('still reports a real credential in the same file', () => {
    const leaked = `${README}\nDATABASE_URL=postgres://limen_app:Kd93mQpZx2@db.internal:5432/limen\n`;
    const findings = scanText('cmd/limen/README.md', leaked);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('secret-database-url');
    expect(findings[0]!.severity).toBe('high');
  });

  it('reads the file this repository ships without tripping on its own docs', () => {
    // Guards the reverse mistake: a placeholder pattern loose enough to exempt
    // the DSNs above must not exempt anything in this package's own sources.
    const own = readFileSync(new URL('../secret-rules.ts', import.meta.url), 'utf8');
    expect(own).toContain('user(?:name)?|admin|root');
  });
});

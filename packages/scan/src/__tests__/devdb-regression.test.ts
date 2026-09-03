import { describe, expect, it } from 'vitest';
import { scanText } from '../text';

// The four `high` findings on terrablue/devdb, copied verbatim from its
// `profiles.go`. devdb's whole job is building connection strings, so the
// templates it substitutes at run time are the repository's core data — a
// scanner that calls them leaked credentials has nothing left to say about it.
const PROFILES_GO = `
type profile struct {
	dsn        string // "postgres://{{.user}}:{{.pass}}@{{.host}}:{{.port}}/{{.name}}"
}

var profiles = map[string]profile{
	"postgres": {
		port: 5432,
		dsn:  "postgres://{{.user}}:{{.pass}}@{{.host}}:{{.port}}/{{.name}}",
	},
	"mongo": {
		port: 27017,
		dsn:  "mongodb://{{.user}}:{{.pass}}@{{.host}}:{{.port}}/{{.name}}",
	},
	"redis": {
		port: 6379,
		dsn:  "redis://:{{.pass}}@{{.host}}:{{.port}}",
	},
}
`;

describe('a DSN whose credential slot is a template', () => {
  it('is not four high findings', () => {
    expect(scanText('profiles.go', PROFILES_GO)).toHaveLength(0);
  });

  it('exempts the other interpolation syntaxes that sit in the same slot', () => {
    const dsns = [
      'mysql://${DB_USER}:${DB_PASS}@localhost:3306/app',
      'postgres://$PGUSER:$PGPASSWORD@localhost:5432/app',
      'postgres://%s:%s@%s:%d/%s',
      'amqp://{{ user }}:{{ password }}@broker:5672',
    ].join('\n');
    expect(scanText('dsn.go', dsns)).toHaveLength(0);
  });

  it('still reports a real credential beside a templated host', () => {
    const leaked = 'dsn := "postgres://devdb:Kd93mQpZx2@{{.host}}:{{.port}}/devdb"';
    const findings = scanText('profiles.go', leaked);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe('secret-database-url');
    expect(findings[0]!.severity).toBe('high');
  });

  it('still reports a real password behind a templated user', () => {
    // Only the password slot decides this. A templated *user* beside a literal
    // password is the case the exemption must not swallow.
    const leaked = 'dsn := "postgres://{{.user}}:Kd93mQpZx2@localhost:5432/devdb"';
    expect(scanText('profiles.go', leaked)).toHaveLength(1);
  });
});

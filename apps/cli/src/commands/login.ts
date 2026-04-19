import readline from 'node:readline';
import { Writable } from 'node:stream';
import chalk from 'chalk';
import { banner } from '../core/logger.js';
import {
  authHeaders,
  clearCliConfig,
  isLoggedIn,
  readCliConfig,
  updateCliConfig,
  CLI_CONFIG_PATH,
} from '../core/cli-config.js';

const API_URL = process.env.THREATCRUSH_API_URL || 'https://threatcrush.com';

function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, (answer) => {
    rl.close();
    resolve(answer.trim());
  }));
}

function promptPassword(question: string): Promise<string> {
  return new Promise((resolve) => {
    const muted = new Writable({
      write(_chunk, _enc, cb) { cb(); },
    });
    const rl = readline.createInterface({ input: process.stdin, output: muted, terminal: true });
    process.stdout.write(question);
    rl.question('', (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

export interface LoginOptions {
  email?: string;
  password?: string;
  silent?: boolean;
}

interface LoginSuccess {
  ok: true;
  email: string;
  userId: string;
  displayName?: string;
}
interface LoginFailure {
  ok: false;
  error: string;
}

export async function login(options: LoginOptions = {}): Promise<LoginSuccess | LoginFailure> {
  const email = options.email || (await prompt(chalk.green('  Email: ')));
  if (!email || !email.includes('@')) {
    return { ok: false, error: 'A valid email is required.' };
  }

  const password = options.password || (await promptPassword(chalk.green('  Password: ')));
  if (!password) {
    return { ok: false, error: 'Password is required.' };
  }

  let res: Response;
  try {
    res = await fetch(`${API_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
  } catch (err) {
    return { ok: false, error: `Network error: ${(err as Error).message}` };
  }

  const data = await res.json().catch(() => ({})) as {
    user?: { id?: string; email?: string };
    session?: { access_token?: string; refresh_token?: string; expires_at?: number };
    error?: string;
  };

  if (!res.ok || !data.session?.access_token || !data.user?.id) {
    return { ok: false, error: data.error || `Login failed (${res.status})` };
  }

  updateCliConfig({
    email: data.user.email || email,
    user_id: data.user.id,
    token: data.session.access_token,
    refresh_token: data.session.refresh_token,
    expires_at: data.session.expires_at,
  });

  return {
    ok: true,
    email: data.user.email || email,
    userId: data.user.id,
  };
}

export async function loginCommand(opts: { email?: string } = {}): Promise<void> {
  banner();

  if (isLoggedIn()) {
    const cfg = readCliConfig();
    console.log(chalk.green(`  ✓ Already logged in as ${chalk.white(cfg.email || cfg.user_id || 'unknown')}`));
    console.log(chalk.dim(`    Run ${chalk.white('threatcrush logout')} to sign out.\n`));
    return;
  }

  console.log(chalk.green('  Log in to threatcrush.com'));
  console.log(chalk.gray('  ' + '─'.repeat(40)));

  const result = await login({ email: opts.email });
  if (!result.ok) {
    console.log(chalk.red(`\n  ✗ ${result.error}\n`));
    console.log(chalk.dim(`  Forgot password? ${API_URL}/auth/forgot-password`));
    console.log(chalk.dim(`  No account yet?  ${API_URL}/auth/signup\n`));
    return;
  }

  console.log(chalk.green(`\n  ✓ Logged in as ${chalk.white(result.email)}`));
  console.log(chalk.dim(`    Credentials saved to ${CLI_CONFIG_PATH}\n`));

  // Pre-fetch current org for convenience.
  try {
    const res = await fetch(`${API_URL}/api/orgs`, { headers: authHeaders() });
    if (res.ok) {
      const data = await res.json() as { organizations?: Array<{ id: string; slug: string; name: string }> };
      const orgs = data.organizations || [];
      if (orgs.length > 0) {
        updateCliConfig({ current_org_id: orgs[0].id, current_org_slug: orgs[0].slug });
        console.log(chalk.dim(`  Current org: ${chalk.white(orgs[0].name)} (${orgs[0].slug})\n`));
      } else {
        console.log(chalk.dim(`  Tip: create an organization with ${chalk.white('threatcrush orgs create <name>')}\n`));
      }
    }
  } catch {
    // optional — skip silently
  }
}

export async function logoutCommand(): Promise<void> {
  banner();

  if (!isLoggedIn()) {
    console.log(chalk.dim('  Not logged in.\n'));
    return;
  }

  clearCliConfig(['token', 'refresh_token', 'expires_at', 'current_org_id', 'current_org_slug']);
  console.log(chalk.green('  ✓ Logged out.\n'));
  console.log(chalk.dim('  Re-authenticate with `threatcrush login`.\n'));
}

export async function whoamiCommand(): Promise<void> {
  banner();
  const cfg = readCliConfig();

  if (!cfg.token) {
    console.log(chalk.yellow('  Not logged in.'));
    console.log(chalk.dim(`  Log in with ${chalk.white('threatcrush login')}.\n`));
    return;
  }

  try {
    const res = await fetch(`${API_URL}/api/auth/me`, { headers: authHeaders() });
    if (res.status === 401) {
      console.log(chalk.yellow('  Session expired. Please log in again.\n'));
      clearCliConfig(['token', 'refresh_token', 'expires_at']);
      return;
    }
    const data = await res.json() as { profile?: Record<string, unknown>; error?: string };
    if (!res.ok || !data.profile) {
      console.log(chalk.red(`  ✗ ${data.error || 'Failed to fetch profile'}\n`));
      return;
    }

    const p = data.profile;
    console.log(chalk.green.bold('  Logged in as'));
    console.log(chalk.gray('  ' + '─'.repeat(50)));
    console.log(`  Email:         ${chalk.white(String(p.email || cfg.email || '—'))}`);
    if (p.display_name) console.log(`  Display name:  ${chalk.white(String(p.display_name))}`);
    if (p.phone) console.log(`  Phone:         ${chalk.white(String(p.phone))}`);
    if (cfg.current_org_slug) console.log(`  Current org:   ${chalk.white(cfg.current_org_slug)}`);
    console.log();
  } catch (err) {
    console.log(chalk.red(`  ✗ Could not reach ${API_URL}: ${(err as Error).message}\n`));
  }
}

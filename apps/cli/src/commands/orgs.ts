import chalk from "chalk";
import { homedir } from "node:os";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const API_URL = process.env.THREATCRUSH_API_URL || "https://threatcrush.com";
const CONFIG_PATH = join(homedir(), ".threatcrush", "config.json");

interface CliConfig {
  email?: string;
  token?: string;
  current_org_id?: string;
  current_org_slug?: string;
}

function readConfig(): CliConfig {
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, "utf-8"));
  } catch {
    return {};
  }
}

function writeConfig(config: CliConfig) {
  const dir = join(homedir(), ".threatcrush");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

function getAuthHeaders(): Record<string, string> {
  const config = readConfig();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.token) headers["Authorization"] = `Bearer ${config.token}`;
  return headers;
}

// ─── Organizations ───

export async function orgsCommand(options: { action?: string; name?: string }): Promise<void> {
  const { action, name } = options;

  if (action === "create") {
    if (!name) {
      console.log(chalk.red("  Usage: threatcrush orgs create <name>\n"));
      return;
    }
    await createOrganization(name);
    return;
  }

  if (action === "use") {
    if (!name) {
      console.log(chalk.red("  Usage: threatcrush orgs use <slug>\n"));
      return;
    }
    await useOrganization(name);
    return;
  }

  if (action === "list" || !action) {
    await listOrganizations();
    return;
  }

  console.log(chalk.red(`  Unknown action: ${action}`));
  console.log(chalk.dim("  Available: list, create, use\n"));
}

async function listOrganizations(): Promise<void> {
  console.log(chalk.green("  Your Organizations\n"));

  try {
    const res = await fetch(`${API_URL}/api/orgs`, { headers: getAuthHeaders() });
    if (!res.ok) {
      if (res.status === 401) {
        console.log(chalk.red("  Not authenticated. Run: threatcrush login\n"));
        return;
      }
      console.log(chalk.red(`  Failed to list organizations: ${res.statusText}\n`));
      return;
    }

    const data = await res.json() as { organizations?: Array<Record<string, unknown>> };
    const orgs = data.organizations || [];

    if (orgs.length === 0) {
      console.log(chalk.yellow("  No organizations found."));
      console.log(chalk.dim("  Create one: threatcrush orgs create <name>\n"));
      return;
    }

    const config = readConfig();
    for (const org of orgs) {
      const isCurrent = org.id === config.current_org_id;
      const role = org.user_role as string;
      const slug = org.slug as string;
      const name = org.name as string;

      console.log(`  ${isCurrent ? chalk.green("●") : chalk.gray("○")} ${chalk.bold(name)} ${chalk.gray(`(/${slug})`)}`);
      console.log(`    ${chalk.dim(`Role: ${role}`)}`);
      console.log();
    }

    console.log(chalk.dim("  Switch org: threatcrush orgs use <slug>"));
    console.log(chalk.dim("  Create org: threatcrush orgs create <name>\n"));
  } catch (err) {
    console.log(chalk.red(`  Failed to list organizations: ${err instanceof Error ? err.message : err}\n`));
  }
}

async function createOrganization(name: string): Promise<void> {
  console.log(chalk.green(`  Creating organization "${name}"...\n`));

  try {
    const res = await fetch(`${API_URL}/api/orgs`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ name }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      console.log(chalk.red(`  Failed: ${(err as Record<string, string>).error}\n`));
      return;
    }

    const data = await res.json() as { organization: Record<string, unknown> };
    const org = data.organization;

    console.log(chalk.green("  ✓ Organization created!"));
    console.log(chalk.dim(`  Name: ${org.name}`));
    console.log(chalk.dim(`  Slug: /${org.slug}\n`));

    // Auto-switch to new org
    const config = readConfig();
    config.current_org_id = org.id as string;
    config.current_org_slug = org.slug as string;
    writeConfig(config);

    console.log(chalk.dim("  Now using this organization.\n"));
  } catch (err) {
    console.log(chalk.red(`  Failed: ${err instanceof Error ? err.message : err}\n`));
  }
}

async function useOrganization(slug: string): Promise<void> {
  console.log(chalk.green(`  Switching to organization "${slug}"...\n`));

  try {
    const res = await fetch(`${API_URL}/api/orgs`, { headers: getAuthHeaders() });
    if (!res.ok) {
      console.log(chalk.red(`  Failed to list organizations: ${res.statusText}\n`));
      return;
    }

    const data = await res.json() as { organizations?: Array<Record<string, unknown>> };
    const orgs = data.organizations || [];
    const org = orgs.find((o) => o.slug === slug);

    if (!org) {
      console.log(chalk.red(`  Organization "/${slug}" not found.\n`));
      return;
    }

    const config = readConfig();
    config.current_org_id = org.id as string;
    config.current_org_slug = org.slug as string;
    writeConfig(config);

    console.log(chalk.green("  ✓ Now using:"));
    console.log(chalk.dim(`  Name: ${org.name}`));
    console.log(chalk.dim(`  Slug: /${org.slug}`));
    console.log(chalk.dim(`  Role: ${org.user_role}\n`));
  } catch (err) {
    console.log(chalk.red(`  Failed: ${err instanceof Error ? err.message : err}\n`));
  }
}

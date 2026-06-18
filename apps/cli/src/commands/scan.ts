import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import chalk from 'chalk';
import ora from 'ora';
import { banner, logger } from '../core/logger.js';
import type { RunResult, StructuredFinding } from '../core/run-result.js';
import { summarize } from '../core/run-result.js';

interface ScanFinding {
  file: string;
  line: number;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  snippet: string;
}

// Secret patterns
const SECRET_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  severity: 'medium' | 'high' | 'critical';
}> = [
  { name: 'AWS Access Key', pattern: /(?:AKIA[0-9A-Z]{16})/g, severity: 'critical' },
  { name: 'AWS Secret Key', pattern: /(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: 'critical' },
  { name: 'GitHub Token', pattern: /(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})/g, severity: 'critical' },
  { name: 'Generic API Key', pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*['"]([A-Za-z0-9\-_]{20,})['"]?/gi, severity: 'high' },
  { name: 'Generic Secret', pattern: /(?:secret|password|passwd|pwd)\s*[=:]\s*['"]([^'"]{8,})['"]?/gi, severity: 'high' },
  { name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*/g, severity: 'high' },
  { name: 'Slack Token', pattern: /xox[bpors]-[A-Za-z0-9-]{10,}/g, severity: 'critical' },
  { name: 'Stripe Key', pattern: /(?:sk_live_|pk_live_|sk_test_|pk_test_)[A-Za-z0-9]{20,}/g, severity: 'critical' },
  { name: 'Database URL', pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^\s'"]+/gi, severity: 'high' },
  { name: 'Bearer Token', pattern: /Bearer\s+[A-Za-z0-9\-_\.]{20,}/g, severity: 'medium' },
  { name: 'Hex Token (32+)', pattern: /(?:token|key|secret|auth)\s*[=:]\s*['"]?([0-9a-f]{32,})['"]?/gi, severity: 'medium' },
];

// File permission / misconfig checks
const MISCONFIG_FILES = [
  { pattern: '.env', message: '.env file found — may contain secrets' },
  { pattern: '.env.local', message: '.env.local file found — may contain secrets' },
  { pattern: '.env.production', message: '.env.production file found — may contain secrets' },
  { pattern: 'id_rsa', message: 'Private SSH key found' },
  { pattern: 'id_ed25519', message: 'Private SSH key found' },
  { pattern: '.pem', message: 'PEM certificate/key file found' },
  { pattern: '.p12', message: 'PKCS#12 keystore found' },
  { pattern: '.keystore', message: 'Keystore file found' },
];

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', '__pycache__',
  '.venv', 'vendor', '.terraform', 'coverage', '.cache',
]);

const SCAN_EXTENSIONS = new Set([
  '.ts', '.js', '.tsx', '.jsx', '.py', '.rb', '.go', '.java',
  '.php', '.rs', '.c', '.cpp', '.h', '.yml', '.yaml', '.json',
  '.toml', '.ini', '.cfg', '.conf', '.env', '.sh', '.bash',
  '.tf', '.hcl', '.xml', '.properties', '.gradle',
]);

export async function runScan(targetPath: string): Promise<RunResult> {
  const findings: ScanFinding[] = [];
  try {
    scanDirectory(targetPath, targetPath, findings, () => {});
    // Dependency CVE scan (PRD 06)
    const depFindings = await scanDependencies(targetPath);
    findings.push(...depFindings);
  } catch (err) {
    return {
      type: 'scan',
      target: targetPath,
      findings: [],
      severity_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      summary: `Scan failed: ${(err as Error).message}`,
      error: (err as Error).message,
    };
  }

  const structured: StructuredFinding[] = findings.map((f) => ({
    type: f.type,
    severity: f.severity,
    message: f.message,
    location: `${f.file}:${f.line}`,
    details: { file: f.file, line: f.line, snippet: f.snippet },
  }));
  const summary = summarize(structured);

  return {
    type: 'scan',
    target: targetPath,
    findings: structured,
    severity_summary: summary,
    summary: findings.length === 0
      ? 'No security issues found'
      : `${findings.length} issue(s): ${summary.critical}C ${summary.high}H ${summary.medium}M ${summary.low}L`,
  };
}

export async function scanCommand(targetPath: string): Promise<RunResult> {
  banner();
  logger.info(`Scanning ${chalk.white(targetPath)} for security issues...\n`);

  const spinner = ora({ text: 'Scanning files...', color: 'green' }).start();
  const findings: ScanFinding[] = [];
  let filesScanned = 0;

  try {
    scanDirectory(targetPath, targetPath, findings, () => {
      filesScanned++;
      spinner.text = `Scanning files... (${filesScanned} files)`;
    });
  } catch (err) {
    spinner.fail(`Scan failed: ${(err as Error).message}`);
    return {
      type: 'scan',
      target: targetPath,
      findings: [],
      severity_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      summary: `Scan failed: ${(err as Error).message}`,
      error: (err as Error).message,
    };
  }

  spinner.succeed(`Scanned ${filesScanned} files\n`);

  const structured: StructuredFinding[] = findings.map((f) => ({
    type: f.type,
    severity: f.severity,
    message: f.message,
    location: `${f.file}:${f.line}`,
    details: { file: f.file, line: f.line, snippet: f.snippet },
  }));
  const sevCounts = summarize(structured);

  // Print results
  if (findings.length === 0) {
    console.log(chalk.green.bold('  ✓ No security issues found!'));
    console.log();
    return {
      type: 'scan',
      target: targetPath,
      findings: [],
      severity_summary: sevCounts,
      summary: `No issues found across ${filesScanned} files`,
    };
  }

  // Group by severity
  const critical = findings.filter((f) => f.severity === 'critical');
  const high = findings.filter((f) => f.severity === 'high');
  const medium = findings.filter((f) => f.severity === 'medium');
  const low = findings.filter((f) => f.severity === 'low');

  console.log(chalk.white.bold('  Scan Results'));
  console.log(chalk.gray('  ' + '─'.repeat(70)));
  console.log(
    `  ${chalk.red.bold(critical.length + ' critical')}  ` +
    `${chalk.red(high.length + ' high')}  ` +
    `${chalk.yellow(medium.length + ' medium')}  ` +
    `${chalk.gray(low.length + ' low')}`,
  );
  console.log(chalk.gray('  ' + '─'.repeat(70)));
  console.log();

  const allFindings = [...critical, ...high, ...medium, ...low];
  for (const finding of allFindings) {
    const sev =
      finding.severity === 'critical' ? chalk.bgRed.white.bold(` ${finding.severity.toUpperCase()} `) :
      finding.severity === 'high' ? chalk.red(`[${finding.severity.toUpperCase()}]`) :
      finding.severity === 'medium' ? chalk.yellow(`[${finding.severity.toUpperCase()}]`) :
      chalk.gray(`[${finding.severity.toUpperCase()}]`);

    console.log(`  ${sev} ${chalk.white.bold(finding.type)}`);
    console.log(`    ${chalk.gray('File:')} ${chalk.cyan(finding.file)}:${chalk.yellow(String(finding.line))}`);
    console.log(`    ${chalk.gray('Info:')} ${finding.message}`);
    if (finding.snippet) {
      // Redact the actual secret value
      const redacted = finding.snippet.replace(
        /(['"]?)([A-Za-z0-9+/=\-_]{16,})(['"]?)/g,
        '$1' + chalk.red('*'.repeat(16)) + '$3',
      );
      console.log(`    ${chalk.gray('Code:')} ${redacted.trim()}`);
    }
    console.log();
  }

  console.log(chalk.gray('  ' + '─'.repeat(70)));
  console.log(`  ${chalk.white.bold(`${findings.length} issue(s) found`)} across ${filesScanned} files`);
  console.log();

  return {
    type: 'scan',
    target: targetPath,
    findings: structured,
    severity_summary: sevCounts,
    summary: `${findings.length} issue(s): ${sevCounts.critical}C ${sevCounts.high}H ${sevCounts.medium}M ${sevCounts.low}L`,
  };
}

function scanDirectory(
  basePath: string,
  currentPath: string,
  findings: ScanFinding[],
  onFile: () => void,
): void {
  let entries;
  try {
    entries = readdirSync(currentPath, { withFileTypes: true });
  } catch {
    return; // Permission denied or similar
  }

  for (const entry of entries) {
    const fullPath = join(currentPath, entry.name);

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      scanDirectory(basePath, fullPath, findings, onFile);
      continue;
    }

    if (!entry.isFile()) continue;

    // Check for misconfig files
    for (const mc of MISCONFIG_FILES) {
      if (entry.name === mc.pattern || entry.name.endsWith(mc.pattern)) {
        findings.push({
          file: relative(basePath, fullPath),
          line: 0,
          type: 'Sensitive File',
          severity: 'high',
          message: mc.message,
          snippet: '',
        });
      }
    }

    // Only scan text files with known extensions
    const ext = extname(entry.name).toLowerCase();
    if (!SCAN_EXTENSIONS.has(ext) && !entry.name.startsWith('.env')) continue;

    // Skip large files
    try {
      const stat = statSync(fullPath);
      if (stat.size > 1024 * 1024) continue; // Skip >1MB
    } catch {
      continue;
    }

    onFile();

    // Scan file content
    let content: string;
    try {
      content = readFileSync(fullPath, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Skip comments
      if (line.trim().startsWith('//') && !line.includes('password') && !line.includes('secret')) continue;

      for (const pattern of SECRET_PATTERNS) {
        pattern.pattern.lastIndex = 0;
        if (pattern.pattern.test(line)) {
          findings.push({
            file: relative(basePath, fullPath),
            line: i + 1,
            type: pattern.name,
            severity: pattern.severity,
            message: `Possible ${pattern.name} detected`,
            snippet: line.length > 120 ? line.slice(0, 120) + '...' : line,
          });
        }
      }
    }
  }
}

// ─── Dependency CVE Scanner (PRD 06) ───

interface OsvVulnerability {
  id: string;
  summary: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{ package: { name: string; ecosystem: string }; ranges?: Array<{ events: Array<{ introduced?: string; fixed?: string }> }> }>;
}

async function scanDependencies(targetPath: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];

  // Check for package-lock.json or package.json
  const lockfiles = [
    { file: 'package-lock.json', ecosystem: 'npm' },
    { file: 'pnpm-lock.yaml', ecosystem: 'npm' },
    { file: 'yarn.lock', ecosystem: 'npm' },
    { file: 'requirements.txt', ecosystem: 'PyPI' },
    { file: 'Pipfile.lock', ecosystem: 'PyPI' },
  ];

  for (const { file, ecosystem } of lockfiles) {
    const lockPath = join(targetPath, file);
    if (!existsSync(lockPath)) continue;

    try {
      const deps = parseDependencies(lockPath, file, ecosystem);
      for (const dep of deps.slice(0, 50)) { // Limit to 50 deps to avoid API flooding
        try {
          const vulns = await queryOsv(dep.name, dep.version, ecosystem);
          for (const vuln of vulns) {
            const cvssScore = vuln.severity?.find(s => s.type === 'CVSS_V3')?.score;
            const severity: ScanFinding['severity'] = cvssScore
              ? (parseFloat(cvssScore) >= 9 ? 'critical' : parseFloat(cvssScore) >= 7 ? 'high' : parseFloat(cvssScore) >= 4 ? 'medium' : 'low')
              : 'medium';

            findings.push({
              file: file,
              line: 0,
              type: 'Dependency CVE',
              severity,
              message: `${dep.name}@${dep.version}: ${vuln.summary || vuln.id}`,
              snippet: `${vuln.id}${cvssScore ? ` (CVSS: ${cvssScore})` : ''}`,
            });
          }
        } catch {
          // Skip individual dep query failures
        }
      }
    } catch {
      // Skip lockfile parse failures
    }
  }

  return findings;
}

function parseDependencies(lockPath: string, filename: string, ecosystem: string): Array<{ name: string; version: string }> {
  const deps: Array<{ name: string; version: string }> = [];

  if (filename === 'package-lock.json') {
    try {
      const lock = JSON.parse(readFileSync(lockPath, 'utf-8'));
      const packages = lock.packages || lock.dependencies || {};
      for (const [key, value] of Object.entries(packages)) {
        const name = key.replace(/^node_modules\//, '');
        const version = (value as any).version;
        if (name && version && !name.startsWith('.')) {
          deps.push({ name, version });
        }
      }
    } catch { /* skip */ }
  } else if (filename === 'requirements.txt') {
    try {
      const content = readFileSync(lockPath, 'utf-8');
      for (const line of content.split('\n')) {
        const match = line.match(/^([a-zA-Z0-9_.-]+)==([0-9.]+)/);
        if (match) deps.push({ name: match[1], version: match[2] });
      }
    } catch { /* skip */ }
  }

  return deps;
}

async function queryOsv(name: string, version: string, ecosystem: string): Promise<OsvVulnerability[]> {
  try {
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name, ecosystem }, version }),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return [];
    const data = await res.json() as { vulns?: OsvVulnerability[] };
    return data.vulns || [];
  } catch {
    return [];
  }
}

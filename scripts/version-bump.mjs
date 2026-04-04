#!/usr/bin/env node

/**
 * Version Bump Script for ThreatCrush Monorepo
 *
 * Usage:
 *   pnpm version:bump major|minor|patch
 *   node scripts/version-bump.mjs patch --from-hook
 *
 * This script:
 * 1. Bumps version in root package.json
 * 2. Bumps version in cli/package.json
 * 3. Bumps version in desktop/package.json
 * 4. Bumps version in mobile/package.json
 * 5. Creates a git commit with the version change
 * 6. Creates a git tag (v1.2.3)
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');

function bumpVersion(version, type) {
  const parts = version.split('.').map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error(`Invalid version format: ${version}`);
  }
  const [major, minor, patch] = parts;
  switch (type) {
    case 'major': return `${major + 1}.0.0`;
    case 'minor': return `${major}.${minor + 1}.0`;
    case 'patch': return `${major}.${minor}.${patch + 1}`;
    default: throw new Error(`Invalid bump type: ${type}`);
  }
}

function updatePackageJson(filePath, newVersion) {
  if (!existsSync(filePath)) {
    console.log(`  ⚠️  Skipping ${filePath} (not found)`);
    return false;
  }
  const content = readFileSync(filePath, 'utf-8');
  const pkg = JSON.parse(content);
  const oldVersion = pkg.version;
  pkg.version = newVersion;
  writeFileSync(filePath, JSON.stringify(pkg, null, 2) + '\n');
  console.log(`  ✅ ${filePath}: ${oldVersion} → ${newVersion}`);
  return true;
}

function exec(command, silent = false) {
  try {
    return execSync(command, {
      cwd: rootDir,
      stdio: silent ? 'pipe' : 'inherit',
      encoding: 'utf-8',
    });
  } catch (error) {
    if (!silent) console.error(`Command failed: ${command}`);
    throw error;
  }
}

function checkGitStatus() {
  const status = exec('git status --porcelain', true);
  if (status && status.trim()) {
    console.error('❌ Working directory is not clean. Commit or stash changes first.');
    console.error('\nUncommitted changes:');
    console.error(status);
    process.exit(1);
  }
}

function main() {
  const args = process.argv.slice(2);
  const fromHook = args.includes('--from-hook');
  const bumpType = args.find((a) => !a.startsWith('--'));

  if (!bumpType || !['major', 'minor', 'patch'].includes(bumpType)) {
    console.error('Usage: node scripts/version-bump.mjs <major|minor|patch>');
    console.error('\nExamples:');
    console.error('  pnpm version:bump patch  # 0.1.0 → 0.1.1');
    console.error('  pnpm version:bump minor  # 0.1.0 → 0.2.0');
    console.error('  pnpm version:bump major  # 0.1.0 → 1.0.0');
    process.exit(1);
  }

  if (!fromHook) {
    console.log('\n🔍 Checking git status...');
    checkGitStatus();
  }

  const rootPkgPath = join(rootDir, 'package.json');
  const rootPkg = JSON.parse(readFileSync(rootPkgPath, 'utf-8'));
  const currentVersion = rootPkg.version;
  const newVersion = bumpVersion(currentVersion, bumpType);

  console.log(`\n📦 Bumping version: ${currentVersion} → ${newVersion} (${bumpType})\n`);

  const packagesToUpdate = [
    'package.json',
    'cli/package.json',
    'desktop/package.json',
    'mobile/package.json',
    'extension/package.json',
  ];

  console.log('📝 Updating package.json files:');
  for (const pkg of packagesToUpdate) {
    updatePackageJson(join(rootDir, pkg), newVersion);
  }

  console.log('\n🔖 Creating git commit and tag...');

  try {
    exec(`git add ${packagesToUpdate.join(' ')}`);
    exec(`git commit --no-verify -m "chore(release): v${newVersion}"`);
    exec(`git tag -a v${newVersion} -m "Release v${newVersion}"`);

    console.log(`\n✅ Version bumped to v${newVersion}`);
    console.log('\n📋 Next steps:');
    console.log('  1. Review the changes: git log --oneline -3');
    console.log('  2. Push to remote: git push --follow-tags');
    console.log('  3. CI will build and create the release');
  } catch (error) {
    console.error('\n❌ Git operations failed. Rolling back...');
    exec('git checkout -- .', true);
    throw error;
  }
}

main();

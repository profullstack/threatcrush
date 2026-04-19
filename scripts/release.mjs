#!/usr/bin/env node

/**
 * Release Script for ThreatCrush Monorepo
 *
 * Usage:
 *   pnpm release patch     # 0.1.0 → 0.1.1
 *   pnpm release minor     # 0.1.0 → 0.2.0
 *   pnpm release major     # 0.1.0 → 1.0.0
 *
 * This script:
 * 1. Bumps version in all package.json files
 * 2. Creates a git commit with the version change
 * 3. Creates a git tag (v1.2.3)
 * 4. Pushes to remote with tags (triggers CI/CD release)
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');

/**
 * @param {string} version
 * @param {'major' | 'minor' | 'patch'} type
 * @returns {string}
 */
function bumpVersion(version, type) {
  const parts = version.split('.').map(Number);

  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error(`Invalid version format: ${version}`);
  }

  const [major, minor, patch] = parts;

  switch (type) {
    case 'major':
      return `${major + 1}.0.0`;
    case 'minor':
      return `${major}.${minor + 1}.0`;
    case 'patch':
      return `${major}.${minor}.${patch + 1}`;
    default:
      throw new Error(`Invalid bump type: ${type}. Use major, minor, or patch.`);
  }
}

/**
 * @param {string} filePath
 * @param {string} newVersion
 */
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

/**
 * @param {string} command
 * @param {boolean} silent
 */
function exec(command, silent = false) {
  try {
    return execSync(command, {
      cwd: rootDir,
      stdio: silent ? 'pipe' : 'inherit',
      encoding: 'utf-8',
    });
  } catch (error) {
    if (!silent) {
      console.error(`Command failed: ${command}`);
    }
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
  const bumpType = args[0];

  if (!bumpType || !['major', 'minor', 'patch'].includes(bumpType)) {
    console.error('Usage: pnpm release <major|minor|patch>');
    console.error('\nExamples:');
    console.error('  pnpm release patch  # 0.1.0 → 0.1.1');
    console.error('  pnpm release minor  # 0.1.0 → 0.2.0');
    console.error('  pnpm release major  # 0.1.0 → 1.0.0');
    process.exit(1);
  }

  console.log('\n🔍 Checking git status...');
  checkGitStatus();

  // Read current version from root package.json
  const rootPkgPath = join(rootDir, 'package.json');
  const rootPkg = JSON.parse(readFileSync(rootPkgPath, 'utf-8'));
  const currentVersion = rootPkg.version;
  const newVersion = bumpVersion(currentVersion, bumpType);

  console.log(`\n📦 Bumping version: ${currentVersion} → ${newVersion} (${bumpType})\n`);

  // Update all package.json files
  const packagesToUpdate = [
    'package.json',
    'apps/web/package.json',
    'apps/cli/package.json',
    'apps/desktop/package.json',
    'apps/mobile/package.json',
    'apps/extension/package.json',
    'apps/sdk/package.json',
  ];

  console.log('📝 Updating package.json files:');
  for (const pkg of packagesToUpdate) {
    updatePackageJson(join(rootDir, pkg), newVersion);
  }

  // Git operations
  console.log('\n🔖 Creating git commit and tag...');

  try {
    exec(`git add ${packagesToUpdate.join(' ')}`);
    exec(`git commit --no-verify -m "chore(release): v${newVersion}"`);
    exec(`git tag -a v${newVersion} -m "Release v${newVersion}"`);

    console.log('\n🚀 Pushing to remote...');
    exec('git push --follow-tags');

    console.log(`\n✅ Released v${newVersion}`);
    console.log('\n📋 What happens next:');
    console.log('  1. GitHub Actions will build desktop apps for all platforms');
    console.log('  2. A GitHub Release will be created automatically');
    console.log('  3. Package managers will be updated via the submit-packages workflow');
    console.log('  4. Download links will be available at:');
    console.log(`     https://github.com/profullstack/threatcrush/releases/tag/v${newVersion}`);
    console.log('\n💡 To manually submit to package managers:');
    console.log(`   pnpm submit-packages -v ${newVersion}`);
  } catch (error) {
    console.error('\n❌ Release failed. Rolling back...');
    exec('git checkout -- .', true);
    throw error;
  }
}

main();

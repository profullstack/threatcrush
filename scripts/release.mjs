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
 * 1. Bumps each package.json against its own current version
 * 2. Creates a git commit with the version change
 * 3. Creates a git tag (v1.2.3) taken from the CLI's new version
 * 4. Pushes to remote with tags (triggers CI/CD release)
 *
 * The packages here are NOT on one shared version line. The CLI and the scan
 * engine ship together at 0.11.x; the desktop app is at 0.5.x. So each
 * manifest is bumped from where it actually is, and the tag is taken from
 * `apps/cli` rather than from the root manifest.
 *
 * Reading the release version from the root manifest is what this script used
 * to do, and it was a live footgun: root has sat at 0.5.1 through v0.9.0,
 * v0.10.0 and v0.11.0, so `pnpm release patch` would have republished the
 * 0.11.0 CLI as 0.5.2 — moving npm's `latest` dist-tag *backwards* onto an
 * older build. `packages/scan` was also missing from the update list entirely,
 * so the engine never got bumped with the CLI that bundles it.
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
 * Bump one manifest against its own current version.
 *
 * @param {string} filePath
 * @param {'major' | 'minor' | 'patch'} type
 * @returns {string | null} the new version, or null when the file is absent
 */
function bumpPackageJson(filePath, type) {
  if (!existsSync(filePath)) {
    console.log(`  ⚠️  Skipping ${filePath} (not found)`);
    return null;
  }

  const content = readFileSync(filePath, 'utf-8');
  const pkg = JSON.parse(content);
  const oldVersion = pkg.version;
  const newVersion = bumpVersion(oldVersion, type);
  pkg.version = newVersion;

  writeFileSync(filePath, JSON.stringify(pkg, null, 2) + '\n');
  console.log(`  ✅ ${filePath}: ${oldVersion} → ${newVersion}`);
  return newVersion;
}

/**
 * Refuse to cut a tag that does not move forward.
 *
 * The backstop for the class of mistake described at the top of this file. A
 * tag is what triggers `npm publish`, and a publish cannot be taken back, so
 * the check belongs here rather than in a reviewer's head.
 *
 * @param {string} newVersion
 */
function assertTagMovesForward(newVersion) {
  const tags = exec('git tag --list "v*" --sort=-v:refname', true)
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  if (tags.includes(`v${newVersion}`)) {
    console.error(`❌ Tag v${newVersion} already exists.`);
    process.exit(1);
  }

  const latest = tags[0];
  if (!latest) return;

  const compare = (a, b) => {
    const left = a.replace(/^v/, '').split('.').map(Number);
    const right = b.replace(/^v/, '').split('.').map(Number);
    for (let i = 0; i < 3; i += 1) {
      if (left[i] !== right[i]) return left[i] - right[i];
    }
    return 0;
  };

  if (compare(newVersion, latest) <= 0) {
    console.error(`❌ v${newVersion} does not move forward from ${latest}.`);
    console.error('   Publishing it would move npm\'s `latest` tag backwards.');
    process.exit(1);
  }
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

  // The tag follows the CLI, because that is what `npm publish` ships and what
  // every previous v* tag has actually corresponded to.
  const TAG_SOURCE = 'apps/cli/package.json';

  const packagesToUpdate = [
    'package.json',
    'apps/web/package.json',
    'apps/cli/package.json',
    // Bundled into the CLI by tsup. Absent from this list until now, so the
    // engine silently kept its old version while the CLI that contains it
    // moved on.
    'packages/scan/package.json',
    'apps/desktop/package.json',
    'apps/mobile/package.json',
    'apps/extension/package.json',
    'apps/sdk/package.json',
  ];

  // Settle the tag before touching a single manifest. Refusing afterwards
  // leaves the tree half-bumped, which reads like a failed release rather than
  // a refused one and has to be cleaned up by hand.
  const tagSourcePath = join(rootDir, TAG_SOURCE);
  if (!existsSync(tagSourcePath)) {
    console.error(`\n❌ ${TAG_SOURCE} is missing — nothing to take a tag from.`);
    process.exit(1);
  }
  const currentVersion = JSON.parse(readFileSync(tagSourcePath, 'utf-8')).version;
  const newVersion = bumpVersion(currentVersion, bumpType);

  console.log(`\n🏷️  Release version (from ${TAG_SOURCE}): ${currentVersion} → v${newVersion}`);
  assertTagMovesForward(newVersion);

  console.log(`\n📦 Bumping every package by one ${bumpType}\n`);
  console.log('📝 Updating package.json files:');

  for (const pkg of packagesToUpdate) {
    bumpPackageJson(join(rootDir, pkg), bumpType);
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

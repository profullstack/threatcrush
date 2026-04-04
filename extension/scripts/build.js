#!/usr/bin/env node

/**
 * Build script for ThreatCrush browser extension
 *
 * Builds the extension for Chrome (MV3), Firefox (MV3), and Safari (MV3)
 * Usage: node scripts/build.js [chrome|firefox|safari|all]
 */

import { execSync } from 'node:child_process';
import {
  copyFileSync,
  mkdirSync,
  rmSync,
  existsSync,
  readFileSync,
  writeFileSync,
  readdirSync,
  createWriteStream,
} from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

// Build configuration
const BUILD_DIR = join(ROOT_DIR, 'dist');
const CHROME_DIR = join(BUILD_DIR, 'chrome');
const FIREFOX_DIR = join(BUILD_DIR, 'firefox');
const SAFARI_DIR = join(BUILD_DIR, 'safari');

/**
 * Clean build directories
 */
function clean() {
  console.log('🧹 Cleaning build directories...');

  if (existsSync(BUILD_DIR)) {
    rmSync(BUILD_DIR, { recursive: true });
  }

  mkdirSync(BUILD_DIR, { recursive: true });
  mkdirSync(CHROME_DIR, { recursive: true });
  mkdirSync(FIREFOX_DIR, { recursive: true });
  mkdirSync(SAFARI_DIR, { recursive: true });
}

/**
 * Run Vite build
 */
function buildVite() {
  console.log('📦 Building with Vite...');

  execSync('pnpm vite build', {
    cwd: ROOT_DIR,
    stdio: 'inherit',
  });
}

/**
 * Copy directory recursively (sync version)
 */
function copyDirectorySync(src, dest) {
  if (!existsSync(src)) {
    return;
  }

  if (!existsSync(dest)) {
    mkdirSync(dest, { recursive: true });
  }

  const entries = readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = join(src, entry.name);
    const destPath = join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirectorySync(srcPath, destPath);
    } else {
      copyFileSync(srcPath, destPath);
    }
  }
}

/**
 * Copy manifest and assets for Chrome
 */
function buildChrome() {
  console.log('🌐 Building Chrome extension (MV3)...');

  // Copy Chrome manifest as manifest.json
  const chromeManifest = readFileSync(join(ROOT_DIR, 'src/manifest.chrome.json'), 'utf-8');
  writeFileSync(join(CHROME_DIR, 'manifest.json'), chromeManifest);

  // Copy icons
  copyIcons(CHROME_DIR);

  // Copy background script
  const bgSrc = join(ROOT_DIR, 'src/background/index.js');
  if (existsSync(bgSrc)) {
    copyFileSync(bgSrc, join(CHROME_DIR, 'background.js'));
  }

  console.log('✅ Chrome build complete');
}

/**
 * Copy manifest and assets for Firefox
 */
function buildFirefox() {
  console.log('🦊 Building Firefox extension (MV3)...');

  // Copy built files from Chrome build
  const viteOutput = CHROME_DIR;
  if (existsSync(viteOutput)) {
    copyDirectorySync(viteOutput, FIREFOX_DIR);
  }

  // Copy Firefox manifest as manifest.json (overwrite Chrome manifest)
  const firefoxManifest = readFileSync(join(ROOT_DIR, 'src/manifest.firefox.json'), 'utf-8');
  writeFileSync(join(FIREFOX_DIR, 'manifest.json'), firefoxManifest);

  // Copy icons
  copyIcons(FIREFOX_DIR);

  // Copy background script
  const bgSrc = join(ROOT_DIR, 'src/background/index.js');
  if (existsSync(bgSrc)) {
    copyFileSync(bgSrc, join(FIREFOX_DIR, 'background.js'));
  }

  console.log('✅ Firefox build complete');
}

/**
 * Copy manifest and assets for Safari
 */
function buildSafari() {
  console.log('🧭 Building Safari extension (MV3)...');

  // Copy built files from Chrome build
  const viteOutput = CHROME_DIR;
  if (existsSync(viteOutput)) {
    copyDirectorySync(viteOutput, SAFARI_DIR);
  }

  // Copy Safari manifest as manifest.json (overwrite Chrome manifest)
  const safariManifest = readFileSync(join(ROOT_DIR, 'src/manifest.safari.json'), 'utf-8');
  writeFileSync(join(SAFARI_DIR, 'manifest.json'), safariManifest);

  // Copy icons
  copyIcons(SAFARI_DIR);

  // Copy background script
  const bgSrc = join(ROOT_DIR, 'src/background/index.js');
  if (existsSync(bgSrc)) {
    copyFileSync(bgSrc, join(SAFARI_DIR, 'background.js'));
  }

  console.log('✅ Safari build complete');
  console.log('');
  console.log('📝 Note: Safari requires additional steps:');
  console.log('   1. Use Xcode to create a Safari Web Extension project');
  console.log('   2. Copy the contents of dist/safari into the extension folder');
  console.log('   3. Build and sign with Xcode');
  console.log(
    '   See: https://developer.apple.com/documentation/safariservices/safari_web_extensions'
  );
}

/**
 * Copy icons to target directory
 */
function copyIcons(targetDir) {
  const iconsDir = join(ROOT_DIR, 'public/icons');
  const targetIconsDir = join(targetDir, 'icons');

  if (!existsSync(iconsDir)) {
    console.log('   ⚠️  No icons directory found, skipping icon copy');
    return;
  }

  if (!existsSync(targetIconsDir)) {
    mkdirSync(targetIconsDir, { recursive: true });
  }

  // Copy icon files if they exist (PNG or SVG)
  const iconSizes = ['16', '32', '48', '128'];
  for (const size of iconSizes) {
    const pngFile = join(iconsDir, `icon-${size}.png`);
    const svgFile = join(iconsDir, `icon-${size}.svg`);

    if (existsSync(pngFile)) {
      copyFileSync(pngFile, join(targetIconsDir, `icon-${size}.png`));
    }
    if (existsSync(svgFile)) {
      copyFileSync(svgFile, join(targetIconsDir, `icon-${size}.svg`));
    }
  }

  // Also copy the base icon.svg if it exists
  const baseIcon = join(iconsDir, 'icon.svg');
  if (existsSync(baseIcon)) {
    copyFileSync(baseIcon, join(targetIconsDir, 'icon.svg'));
  }
}

/**
 * Create ZIP packages for distribution
 */
async function createPackages(targets) {
  console.log('📦 Creating distribution packages...');

  let archiver;
  try {
    archiver = (await import('archiver')).default;
  } catch {
    console.log('⚠️  archiver not installed, skipping ZIP creation');
    console.log('   Run: pnpm add -D archiver');
    return;
  }

  if (targets.includes('chrome')) {
    await createZip(archiver, CHROME_DIR, join(BUILD_DIR, 'threatcrush-chrome.zip'));
  }

  if (targets.includes('firefox')) {
    await createZip(archiver, FIREFOX_DIR, join(BUILD_DIR, 'threatcrush-firefox.zip'));
  }

  if (targets.includes('safari')) {
    await createZip(archiver, SAFARI_DIR, join(BUILD_DIR, 'threatcrush-safari.zip'));
  }

  console.log('✅ Packages created');
}

/**
 * Create a ZIP file from a directory
 */
function createZip(archiver, sourceDir, outputPath) {
  return new Promise((resolve, reject) => {
    const output = createWriteStream(outputPath);
    const archive = archiver('zip', { zlib: { level: 9 } });

    output.on('close', () => {
      console.log(`   Created: ${outputPath} (${archive.pointer()} bytes)`);
      resolve();
    });

    archive.on('error', reject);

    archive.pipe(output);
    archive.directory(sourceDir, false);
    archive.finalize();
  });
}

/**
 * Main build function
 */
async function main() {
  const target = process.argv[2] || 'all';

  console.log('🚀 ThreatCrush Extension Build');
  console.log(`   Target: ${target}`);
  console.log('');

  try {
    clean();
    buildVite();

    const targets = [];

    switch (target) {
      case 'chrome':
        buildChrome();
        targets.push('chrome');
        break;
      case 'firefox':
        buildFirefox();
        targets.push('firefox');
        break;
      case 'safari':
        buildSafari();
        targets.push('safari');
        break;
      case 'all':
      default:
        buildChrome();
        buildFirefox();
        buildSafari();
        targets.push('chrome', 'firefox', 'safari');
        break;
    }

    await createPackages(targets);

    console.log('');
    console.log('🎉 Build complete!');
    console.log('');
    console.log('Output:');
    if (targets.includes('chrome')) {
      console.log(`   Chrome:  ${CHROME_DIR}`);
    }
    if (targets.includes('firefox')) {
      console.log(`   Firefox: ${FIREFOX_DIR}`);
    }
    if (targets.includes('safari')) {
      console.log(`   Safari:  ${SAFARI_DIR}`);
    }
    console.log('');
    console.log('To load in Chrome:');
    console.log('   1. Go to chrome://extensions');
    console.log('   2. Enable "Developer mode"');
    console.log('   3. Click "Load unpacked"');
    console.log(`   4. Select: ${CHROME_DIR}`);
    console.log('');
    console.log('To load in Firefox:');
    console.log('   1. Go to about:debugging');
    console.log('   2. Click "This Firefox"');
    console.log('   3. Click "Load Temporary Add-on"');
    console.log(`   4. Select: ${FIREFOX_DIR}/manifest.json`);
    console.log('');
    console.log('To load in Safari:');
    console.log('   1. Open Xcode and create a Safari Web Extension project');
    console.log('   2. Copy dist/safari contents to the extension folder');
    console.log('   3. Build and run from Xcode');
    console.log('   4. Enable in Safari > Preferences > Extensions');
  } catch (error) {
    console.error('❌ Build failed:', error.message);
    process.exit(1);
  }
}

main();

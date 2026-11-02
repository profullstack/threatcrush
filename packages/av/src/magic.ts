import type { FileKind } from './types';

const starts = (b: Uint8Array, sig: number[], at = 0) =>
  b.length >= at + sig.length && sig.every((v, i) => b[at + i] === v);

/** Identify a file from its first bytes. The name is never consulted. */
export function sniffKind(b: Uint8Array): FileKind {
  if (starts(b, [0x4d, 0x5a])) return 'pe';
  if (starts(b, [0x7f, 0x45, 0x4c, 0x46])) return 'elf';
  if (
    starts(b, [0xfe, 0xed, 0xfa, 0xce]) || starts(b, [0xfe, 0xed, 0xfa, 0xcf]) ||
    starts(b, [0xce, 0xfa, 0xed, 0xfe]) || starts(b, [0xcf, 0xfa, 0xed, 0xfe])
  ) return 'macho';
  // 0xCAFEBABE is both a Mach-O fat binary and a Java class; a fat binary has a
  // small architecture count where a class file has its version number.
  if (starts(b, [0xca, 0xfe, 0xba, 0xbe]) && b.length >= 8 && b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7] > 0 && b[7] < 20) return 'macho';
  if (starts(b, [0x50, 0x4b, 0x03, 0x04]) || starts(b, [0x50, 0x4b, 0x05, 0x06])) return 'zip';
  if (starts(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return 'ole';
  if (starts(b, [0x25, 0x50, 0x44, 0x46, 0x2d])) return 'pdf';
  if (starts(b, [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])) return 'lnk';
  if (starts(b, [0x7b, 0x5c, 0x72, 0x74, 0x66])) return 'rtf';
  if (starts(b, [0x64, 0x65, 0x78, 0x0a])) return 'dex';
  if (starts(b, [0x23, 0x21])) return 'script';
  if (
    starts(b, [0xff, 0xd8, 0xff]) || starts(b, [0x89, 0x50, 0x4e, 0x47]) || starts(b, [0x47, 0x49, 0x46, 0x38]) ||
    (starts(b, [0x52, 0x49, 0x46, 0x46]) && starts(b, [0x57, 0x45, 0x42, 0x50], 8)) || starts(b, [0x42, 0x4d])
  ) return 'image';
  if (
    starts(b, [0x66, 0x74, 0x79, 0x70], 4) || starts(b, [0x49, 0x44, 0x33]) || starts(b, [0x1a, 0x45, 0xdf, 0xa3]) ||
    starts(b, [0x4f, 0x67, 0x67, 0x53]) || starts(b, [0x66, 0x4c, 0x61, 0x43])
  ) return 'media';
  if (
    starts(b, [0x1f, 0x8b]) || starts(b, [0x52, 0x61, 0x72, 0x21]) || starts(b, [0x37, 0x7a, 0xbc, 0xaf]) ||
    starts(b, [0xfd, 0x37, 0x7a, 0x58, 0x5a]) || starts(b, [0x28, 0xb5, 0x2f, 0xfd])
  ) return 'archive';
  if (looksLikeText(b)) return 'text';
  return 'unknown';
}

function looksLikeText(b: Uint8Array): boolean {
  const n = Math.min(b.length, 4096);
  if (n === 0) return true;
  let odd = 0;
  for (let i = 0; i < n; i++) {
    const c = b[i];
    if (c === 0) return false;
    if (c < 9 || (c > 13 && c < 32)) odd++;
  }
  return odd / n < 0.05;
}

export const EXECUTABLE_KINDS: ReadonlySet<FileKind> = new Set(['pe', 'elf', 'macho']);

/** Extensions people open expecting a document, picture or video. */
export const DOCUMENT_EXTENSIONS = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'txt', 'rtf', 'csv',
  'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'heic', 'svg',
  'mp3', 'mp4', 'mov', 'avi', 'mkv', 'wav', 'm4a',
]);

/** Extensions Windows (or a browser) will run when double-clicked. */
export const RUNNABLE_EXTENSIONS = new Set([
  'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'msi', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'hta', 'lnk', 'ps1', 'cpl', 'jar', 'apk', 'app', 'dmg', 'pkg', 'iso', 'img',
]);

export function extOf(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? name;
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : '';
}

export function baseName(name: string): string {
  return name.split(/[\\/]/).pop() ?? name;
}

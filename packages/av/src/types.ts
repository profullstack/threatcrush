/** Which part of CrushAV produced a detection. */
export type AvEngine = 'heuristic' | 'signature' | 'clamav' | 'reputation';

/**
 * How bad one detection is. `info` never changes a verdict: it explains
 * something a person may want to know (a document carries macros) without
 * calling the file infected.
 */
export type AvSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/**
 * The verdict for one file.
 * - `malicious`: a signature, ClamAV or a high-confidence rule matched.
 * - `suspicious`: something looks wrong but could be legitimate.
 * - `clean`: nothing matched. Not a promise, just the honest result.
 * - `error`: the file could not be read.
 */
export type AvVerdict = 'clean' | 'suspicious' | 'malicious' | 'error';

export interface AvDetection {
  engine: AvEngine;
  /** Stable id, e.g. `CrushAV.PowerShell.DownloadCradle` or a ClamAV name. */
  id: string;
  /** Short human name. */
  name: string;
  severity: AvSeverity;
  /**
   * What this detection does to the verdict. `info` is shown but never makes a
   * file suspicious; keeping the false-positive rate low matters more than
   * catching everything, because people stop trusting a scanner that cries wolf.
   */
  impact: 'malicious' | 'suspicious' | 'info';
  /** Plain-English explanation a non-expert can act on. */
  description: string;
}

/** Coarse file kind from magic bytes, independent of the file name. */
export type FileKind =
  | 'pe' // Windows executable / DLL
  | 'elf' // Linux executable
  | 'macho' // macOS executable
  | 'zip' // zip container (also docx/xlsx/jar/apk)
  | 'ole' // legacy Office / MSI
  | 'pdf'
  | 'lnk' // Windows shortcut
  | 'rtf'
  | 'dex' // Android bytecode
  | 'script' // shebang script
  | 'image'
  | 'media'
  | 'archive'
  | 'text'
  | 'unknown';

export interface AvFileResult {
  /** Path or display name. */
  path: string;
  size: number;
  /** Lower-case hex SHA-256 of the whole file, when it was hashed. */
  sha256: string | null;
  kind: FileKind;
  verdict: AvVerdict;
  detections: AvDetection[];
  /** Why the file was skipped or partially scanned, if it was. */
  note?: string;
}

/** What the reputation service knows about one hash. */
export interface HashReputation {
  sha256: string;
  /** Source that lists the file as malware, e.g. `malshare.com`. */
  knownMalicious: string | null;
  /** Malware family / signature name when a source gives one. */
  malwareName: string | null;
  /** 0-100 from CIRCL hashlookup: how sure we are this is a known-good file. */
  trust: number | null;
  /** A file name the hash was seen under, for display only. */
  fileName: string | null;
}

export interface AvSummary {
  scanned: number;
  malicious: number;
  suspicious: number;
  clean: number;
  errors: number;
  skipped: number;
  /** Engines that actually ran. */
  engines: AvEngine[];
  startedAt: string;
  finishedAt: string;
}

import { baseName, DOCUMENT_EXTENSIONS, EXECUTABLE_KINDS, extOf } from './magic';
import type { AvDetection, AvSeverity, FileKind } from './types';

/**
 * CrushAV heuristic rules.
 *
 * Every rule here runs on bytes alone, so the same rules protect a Linux box,
 * a Windows laptop, a browser tab and a phone. Rules are scoped tightly to the
 * file types where the pattern means something: a reverse shell in a `.sh` is
 * an attack, the same line in a pentest write-up `.md` is homework. The bar for
 * `malicious` is "a reasonable person would never want this file"; anything
 * that legitimate software also does is at most `suspicious`.
 */

export interface RuleContext {
  name: string;
  ext: string;
  kind: FileKind;
  /** Actual file size (bytes may be truncated). */
  size: number;
  bytes: Uint8Array;
  /** Bytes as Latin-1, so every byte maps to one char. */
  text: string;
  /** UTF-16LE strings view for Windows binaries and shortcuts ('' otherwise). */
  wide: string;
}

export interface AvRule {
  id: string;
  name: string;
  severity: AvSeverity;
  impact: AvDetection['impact'];
  description: string;
  /** Return true, or a detection override (e.g. upgraded impact), on a match. */
  test(ctx: RuleContext): boolean | Partial<AvDetection>;
}

export const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

const SCRIPT_EXTS = new Set(['ps1', 'psm1', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'hta', 'sh', 'bash', 'zsh', 'py', 'pl', 'rb', 'php', 'command', 'applescript', 'scpt']);
const WIN_SCRIPT_EXTS = new Set(['js', 'jse', 'vbs', 'vbe', 'wsf', 'hta']);
const WEB_EXTS = new Set(['html', 'htm', 'shtml', 'xhtml', 'svg', 'hta']);
const SERVER_SCRIPT_EXTS = new Set(['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'asp', 'aspx', 'ashx', 'jsp', 'jspx']);

const isScript = (c: RuleContext) => c.kind === 'script' || SCRIPT_EXTS.has(c.ext);
/**
 * Somewhere Windows would actually run PowerShell from. A `.js` file counts
 * only when it is a Windows Script Host script: a Node bundle that merely
 * contains the words (a security tool's own rules, say) is not one. Measured:
 * 49 false hits on bundled CLI builds before this guard.
 */
const POWERSHELL_HOST_EXTS = new Set(['ps1', 'psm1', 'bat', 'cmd', 'vbs', 'vbe', 'wsf', 'hta']);
const isWindowsScriptContext = (c: RuleContext) =>
  POWERSHELL_HOST_EXTS.has(c.ext) ||
  c.kind === 'lnk' ||
  (['js', 'jse'].includes(c.ext) && /ActiveXObject|WScript\.|GetObject\(\s*["']winmgmts/i.test(c.text));
const NON_RUNNABLE_SOURCE_EXTS = new Set(['ts', 'tsx', 'mts', 'cts', 'md', 'markdown', 'rst', 'go', 'rs', 'c', 'h', 'cc', 'cpp', 'hpp', 'java', 'kt', 'cs', 'swift', 'scala']);
/** Ransom notes are plain text or HTML, usually with no other extension. */
const NOTE_EXTS = new Set(['txt', 'html', 'htm', 'hta', 'rtf', '']);
const allText = (c: RuleContext) => (c.wide ? `${c.text}\n${c.wide}` : c.text);

const RANSOM_COMMANDS = [
  /vssadmin(?:\.exe)?["']?\s+delete\s+shadows/i,
  /wmic(?:\.exe)?["']?\s+shadowcopy\s+delete/i,
  /wbadmin(?:\.exe)?["']?\s+delete\s+(?:catalog|backup|systemstatebackup)/i,
  /bcdedit(?:\.exe)?["']?\s+\/set\s+\{default\}\s+(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/i,
  /Get-WmiObject\s+Win32_Shadowcopy\s*\|\s*ForEach-Object\s*\{\s*\$_\.Delete\(\)/i,
];

export const RULES: AvRule[] = [
  {
    id: 'CrushAV.Test.EICAR',
    name: 'EICAR test file',
    severity: 'low',
    impact: 'malicious',
    description:
      'The industry-standard harmless antivirus test file. It cannot do anything; it only proves the scanner works.',
    test: (c) => c.size <= 128 && c.text.trimStart().startsWith(EICAR),
  },
  {
    id: 'CrushAV.Disguise.ExecutableAsDocument',
    name: 'Program disguised as a document',
    severity: 'high',
    impact: 'malicious',
    description:
      'This file is a program, but its name says it is a document, picture or video. Real documents never do this; it is how malware tricks people into running it. Do not open it.',
    test: (c) => EXECUTABLE_KINDS.has(c.kind) && DOCUMENT_EXTENSIONS.has(c.ext),
  },
  {
    id: 'CrushAV.Disguise.DoubleExtension',
    name: 'Fake file extension',
    severity: 'high',
    impact: 'suspicious',
    description:
      'The name hides a runnable extension behind a harmless-looking one (like "invoice.pdf.exe"). Windows hides the last part by default, so this looks like a document but runs as a program.',
    test: (c) =>
      /\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|mp3|mp4|mov|zip)[\s_.]*\.(?:exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|lnk|ps1|cpl)$/i.test(baseName(c.name)) ||
      /\s{6,}\.(?:exe|scr|com|pif|bat|cmd|js|vbs|hta|lnk)$/i.test(baseName(c.name)),
  },
  {
    id: 'CrushAV.Disguise.RightToLeftOverride',
    name: 'Reversed file name trick',
    severity: 'high',
    impact: 'malicious',
    description:
      'The file name contains an invisible character that reverses the text after it, so "photo‮gpj.exe" displays as "photoexe.jpg". Legitimate files have no reason to do this.',
    test: (c) => baseName(c.name).includes('‮'),
  },
  {
    id: 'CrushAV.PowerShell.EncodedCommand',
    name: 'Hidden PowerShell command',
    severity: 'high',
    impact: 'suspicious',
    description:
      'Runs PowerShell with a long base64-encoded command, which hides what it does. Malware droppers use this constantly; legitimate software rarely needs to.',
    test: (c) =>
      (isWindowsScriptContext(c) || c.kind === 'pe') &&
      /powershell(?:\.exe)?["']?[^\n]{0,120}?\s-(?:e|ec|en|enc|enco|encod|encodedcommand)\s+["']?[A-Za-z0-9+/]{80,}={0,2}/i.test(allText(c)),
  },
  {
    id: 'CrushAV.PowerShell.DownloadExecute',
    name: 'Downloads and runs code',
    severity: 'medium',
    impact: 'suspicious',
    description:
      'Downloads code from the internet and runs it straight away. Some installers do this; if you did not expect this script, delete it.',
    test: (c) => {
      // Scripts and shortcuts only: in compiled binaries, short tokens like
      // "iwr" and "IEX" turn up in random bytes (measured: 5 hits in 4,118
      // Ubuntu /usr binaries). Binaries carrying PowerShell are still caught by
      // the encoded-command, shortcut and ransomware rules.
      if (!isWindowsScriptContext(c)) return false;
      const t = allText(c);
      const download =/(?:DownloadString|DownloadData|DownloadFile|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|Net\.WebClient|Start-BitsTransfer)/i.test(t);
      const execute = /(?:\bIEX\b|Invoke-Expression|\|\s*iex\b|Start-Process|\.Invoke\(\))/i.test(t);
      if (!download || !execute) return false;
      const stealthy =
        /-w(?:indowstyle)?\s+h(?:idden)?\b/i.test(t) && /-ex(?:ecutionpolicy)?\s+bypass/i.test(t);
      return stealthy
        ? { impact: 'malicious', severity: 'high', description: 'Downloads code and runs it in a hidden window with security checks bypassed. This is how most Windows malware gets installed.' }
        : true;
    },
  },
  {
    id: 'CrushAV.Script.WindowsDropper',
    name: 'Script that downloads and runs programs',
    severity: 'high',
    impact: 'malicious',
    description:
      'A Windows script (JS/VBS/HTA) that fetches something from the internet and launches it. Email attachments like this are malware droppers; nothing legitimate is delivered this way.',
    test: (c) => {
      if (!WIN_SCRIPT_EXTS.has(c.ext)) return false;
      const t = c.text;
      return (
        /WScript\.Shell|Shell\.Application/i.test(t) &&
        /\.(?:Run|Exec|ShellExecute)\s*\(/i.test(t) &&
        /(?:MSXML2\.(?:Server)?XMLHTTP|WinHttp\.WinHttpRequest|ADODB\.Stream|Microsoft\.XMLHTTP)/i.test(t)
      );
    },
  },
  {
    id: 'CrushAV.Shortcut.LolbinLauncher',
    name: 'Booby-trapped shortcut',
    severity: 'high',
    impact: 'malicious',
    description:
      'A Windows shortcut (.lnk) that launches PowerShell, mshta or a similar tool to fetch something from the internet. Shortcuts like this arrive in zip and ISO attachments to install malware.',
    test: (c) =>
      c.kind === 'lnk' &&
      /(?:powershell|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|cmd(?:\.exe)?\s*\/c)/i.test(allText(c)) &&
      /(?:https?:\/\/|\\\\[\w.-]+@SSL|-enc(?:odedcommand)?\s)/i.test(allText(c)),
  },
  {
    id: 'CrushAV.Office.MacroInDocx',
    name: 'Macros hidden in a regular Office file',
    severity: 'high',
    impact: 'suspicious',
    description:
      'This document carries macro code even though its type (.docx/.xlsx/.pptx) is not supposed to have any. That mismatch is a common way to sneak malicious macros past filters.',
    test: (c) => c.kind === 'zip' && ['docx', 'xlsx', 'pptx'].includes(c.ext) && c.text.includes('vbaProject.bin'),
  },
  {
    id: 'CrushAV.Office.AutoMacro',
    name: 'Office macro that runs on open and starts programs',
    severity: 'high',
    impact: 'malicious',
    description:
      'An Office document whose macro runs automatically when opened and starts other programs or downloads files. Never click "Enable content" on this one.',
    test: (c) => {
      if (c.kind !== 'ole') return false;
      const t = allText(c);
      if (!/_VBA_PROJECT|VBA\b/i.test(t)) return false;
      const auto = /(?:Auto_?Open|Document_Open|Workbook_Open|AutoExec|Auto_Close|Document_Close)/i.test(t);
      const act = /(?:\bShell\b|WScript\.Shell|CreateObject|URLDownloadToFile|powershell|MSXML2)/i.test(t);
      if (auto && act) return true;
      if (auto) return { impact: 'suspicious', severity: 'medium', name: 'Office macro that runs on open', description: 'This document has a macro that runs automatically when opened. Only enable macros for documents you were expecting from someone you trust.' };
      return false;
    },
  },
  {
    id: 'CrushAV.Office.MacroEnabled',
    name: 'Document contains macros',
    severity: 'info',
    impact: 'info',
    description: 'This is a macro-enabled Office document. That is normal for some spreadsheets, but only enable macros if you trust the sender.',
    test: (c) => c.kind === 'zip' && ['docm', 'xlsm', 'pptm', 'dotm', 'xltm'].includes(c.ext) && c.text.includes('vbaProject.bin'),
  },
  {
    id: 'CrushAV.PDF.Launch',
    name: 'PDF that tries to start a program',
    severity: 'high',
    impact: 'suspicious',
    description: 'This PDF contains a /Launch action, which asks your PDF reader to run a program. Normal documents do not need that.',
    test: (c) => {
      if (c.kind !== 'pdf' || !/\/Launch\b/.test(c.text)) return false;
      return /(?:cmd\.exe|powershell|mshta|\.exe\b|\.bat\b|\.vbs\b)/i.test(c.text)
        ? { impact: 'malicious', description: 'This PDF tries to start a Windows program (cmd, PowerShell or an .exe) when opened. That is an attack; do not open it.' }
        : true;
    },
  },
  {
    id: 'CrushAV.PDF.AutoJavaScript',
    name: 'PDF runs JavaScript on open',
    severity: 'info',
    impact: 'info',
    description: 'This PDF runs JavaScript when opened. Fillable forms do this legitimately, so it is shown for information only.',
    test: (c) => c.kind === 'pdf' && /\/(?:OpenAction|AA)\b/.test(c.text) && /\/(?:JavaScript|JS)\b/.test(c.text),
  },
  {
    id: 'CrushAV.Shell.ReverseShell',
    name: 'Remote-control backdoor (reverse shell)',
    severity: 'critical',
    impact: 'malicious',
    description: 'This script connects out to another computer and hands it a command line on this one. That gives a stranger full control of the machine.',
    test: (c) => {
      if (!isScript(c)) return false;
      const t = c.text;
      return (
        /bash\s+-i\s*>&\s*\/dev\/tcp\//.test(t) ||
        /\/dev\/tcp\/\d{1,3}(?:\.\d{1,3}){3}\/\d{2,5}\s*0>&1/.test(t) ||
        /\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+\/bin\/(?:ba)?sh\b/.test(t) ||
        /socket\.socket\([\s\S]{0,300}?(?:os\.dup2|pty\.spawn)\([\s\S]{0,300}?\/bin\/(?:ba)?sh/.test(t) ||
        /New-Object\s+System\.Net\.Sockets\.TCPClient\([\s\S]{0,600}?(?:\bIEX\b|Invoke-Expression)/i.test(t)
      );
    },
  },
  {
    id: 'CrushAV.Web.Webshell',
    name: 'Website backdoor (webshell)',
    severity: 'critical',
    impact: 'malicious',
    description: 'Server code that runs whatever a visitor sends it. Attackers plant these on hacked websites to keep control. Remove it and change your hosting passwords.',
    test: (c) => {
      if (!SERVER_SCRIPT_EXTS.has(c.ext)) return false;
      const t = c.text;
      return (
        /\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open|create_function)\s*\(\s*@?(?:(?:base64_decode|gzinflate|str_rot13|gzuncompress|stripslashes)\s{0,4}\(\s{0,4}@?){0,4}\$_(?:POST|GET|REQUEST|COOKIE)\b/i.test(t) ||
        /\beval\s*\(\s*gz(?:inflate|uncompress)\s*\(\s*base64_decode\s*\(/i.test(t) ||
        /Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter/.test(t) ||
        /Request\.(?:Form|QueryString|Item)\[[^\]]+\][\s\S]{0,120}?(?:Process\.Start|eval\s*\()/i.test(t)
      );
    },
  },
  {
    id: 'CrushAV.PUA.CoinMiner',
    name: 'Cryptocurrency miner',
    severity: 'high',
    impact: 'suspicious',
    description: 'Software that uses your computer to mine cryptocurrency for someone. If you did not install a miner yourself, it is stealing your electricity and slowing you down.',
    test: (c) => {
      // Source in compiled languages and docs only *mentions* miners (scanner rules, tests, write-ups).
      if (NON_RUNNABLE_SOURCE_EXTS.has(c.ext)) return false;
      const t = c.text;
      return /stratum2?\+(?:tcp|ssl|tls):\/\//i.test(t) && /(?:xmrig|donate-level|cryptonight|randomx|nicehash|cpu-max-threads-hint)/i.test(t);
    },
  },
  {
    id: 'CrushAV.Ransomware.ShadowCopyWipe',
    name: 'Deletes backups (ransomware behaviour)',
    severity: 'critical',
    impact: 'malicious',
    description: 'This program deletes Windows backup copies and disables recovery, which is what ransomware does right before encrypting files. Disconnect from the network and do not run it.',
    test: (c) => {
      if (!(EXECUTABLE_KINDS.has(c.kind) || isWindowsScriptContext(c))) return false;
      const t = allText(c);
      const hits = RANSOM_COMMANDS.filter((r) => r.test(t)).length;
      if (hits >= 2) return true;
      if (hits === 1) return { impact: 'suspicious', severity: 'high', description: 'This program deletes Windows backup copies. Ransomware does this before encrypting files; a few admin tools do it on purpose. If you do not know what this is, do not run it.' };
      return false;
    },
  },
  {
    id: 'CrushAV.Ransomware.Note',
    name: 'Ransom note',
    severity: 'critical',
    impact: 'malicious',
    description: 'This looks like a ransom note, which ransomware leaves behind after encrypting files. Disconnect this computer from the network, do not pay, and check nomoreransom.org for a free decryptor.',
    test: (c) =>
      c.size <= 64 * 1024 &&
      c.kind === 'text' &&
      NOTE_EXTS.has(c.ext) &&
      /(?:all\s+)?your\s+(?:important\s+|personal\s+)?(?:files|documents|data)\s+(?:have\s+been|are|were)\s+(?:encrypted|locked)/i.test(c.text) &&
      /(?:bitcoin|\bBTC\b|monero|\.onion\b|tor\s+browser|decrypt(?:or|ion)\s+(?:key|tool|software|program))/i.test(c.text),
  },
  {
    id: 'CrushAV.HackTool.CredentialDumper',
    name: 'Password-stealing tool',
    severity: 'high',
    impact: 'malicious',
    description: 'A tool that pulls saved passwords out of Windows memory (Mimikatz or a copy of it). Attackers use it to spread through networks.',
    test: (c) => (c.kind === 'pe' || c.ext === 'ps1') && /sekurlsa::(?:logonpasswords|wdigest|msv)|lsadump::(?:sam|dcsync|secrets)/i.test(allText(c)),
  },
  {
    id: 'CrushAV.macOS.PasswordPhishStealer',
    name: 'Mac password-stealing script',
    severity: 'critical',
    impact: 'malicious',
    description: 'Shows a fake macOS password prompt and then reaches for your keychain, browser data or wallets. This is how Mac stealers like AMOS work. Do not enter your password; delete it.',
    test: (c) => {
      if (!(isScript(c) || c.kind === 'macho')) return false;
      const t = c.text;
      return /display\s+dialog[\s\S]{0,400}?with\s+hidden\s+answer/i.test(t) &&
        /(?:Library\/Keychains|login\.keychain|Cookies|Login Data|wallet|find-generic-password|dscl\s+\.\s+-?authonly|curl\s)/i.test(t);
    },
  },
  {
    id: 'CrushAV.Web.ClickFix',
    name: 'Fake "verify you are human" trick (ClickFix)',
    severity: 'critical',
    impact: 'malicious',
    description: 'A web page that secretly copies a command to your clipboard and tells you to paste it into Run or Terminal to "verify" yourself. Pasting it installs malware. Never paste commands a website gives you.',
    test: (c) => {
      if (!(WEB_EXTS.has(c.ext) || c.ext === 'js')) return false;
      const t = c.text;
      return /(?:navigator\.clipboard\.writeText|document\.execCommand\(\s*["']copy)/.test(t) &&
        /(?:powershell|mshta|cmd(?:\.exe)?\s*\/c|curl\s[^\n]{0,200}\|\s*(?:ba|z)?sh|osascript)/i.test(t) &&
        /(?:Win(?:dows)?\s*(?:key\s*)?\+\s*R|Windows\s+key|Ctrl\s*\+\s*V|Cmd\s*\+\s*Space|verify\s+you\s+are\s+(?:a\s+)?human|I(?:'|&#39;)?m\s+not\s+a\s+robot)/i.test(t);
    },
  },
  {
    id: 'CrushAV.Web.HtmlSmuggling',
    name: 'Web page that builds a hidden download',
    severity: 'high',
    impact: 'suspicious',
    description: 'This HTML or SVG file carries a large hidden file inside itself and saves it to your computer when opened. Attackers use this to sneak malware past email filters.',
    test: (c) => {
      if (!WEB_EXTS.has(c.ext)) return false;
      const t = c.text;
      return /new\s+Blob\s*\(/.test(t) &&
        /(?:\.download\s*=|msSaveOrOpenBlob|msSaveBlob)/.test(t) &&
        /(?:atob\s*\(|base64)/.test(t) &&
        /[A-Za-z0-9+/]{20000}/.test(t);
    },
  },
  {
    id: 'CrushAV.Web.SvgRedirect',
    name: 'Image file that runs code',
    severity: 'medium',
    impact: 'suspicious',
    description: 'This SVG "image" contains a script that redirects you or decodes hidden content. Phishing emails use SVG attachments like this to send you to fake login pages.',
    test: (c) => c.ext === 'svg' && /<script\b/i.test(c.text) && /(?:location(?:\.href)?\s*=|location\.replace\(|window\.open\(|atob\s*\()/.test(c.text),
  },
];

/** Build a rule context. `bytes` may be a prefix of the file. */
export function buildContext(name: string, bytes: Uint8Array, kind: FileKind, size: number): RuleContext {
  let text = '';
  // Latin-1 decode in chunks; String.fromCharCode on a huge array overflows the stack.
  for (let i = 0; i < bytes.length; i += 0x8000) {
    text += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000) as unknown as number[]);
  }
  let wide = '';
  if (kind === 'pe' || kind === 'lnk' || kind === 'ole') {
    const parts: string[] = [];
    let run = '';
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const lo = bytes[i];
      if (bytes[i + 1] === 0 && lo >= 0x20 && lo < 0x7f) run += String.fromCharCode(lo);
      else {
        if (run.length >= 4) parts.push(run);
        run = '';
      }
    }
    if (run.length >= 4) parts.push(run);
    wide = parts.join('\n');
  }
  return { name, ext: extOf(name), kind, size, bytes, text, wide };
}

export function runRules(ctx: RuleContext, rules: AvRule[] = RULES): AvDetection[] {
  const out: AvDetection[] = [];
  for (const r of rules) {
    let hit: boolean | Partial<AvDetection>;
    try {
      hit = r.test(ctx);
    } catch {
      continue;
    }
    if (!hit) continue;
    const base: AvDetection = { engine: 'heuristic', id: r.id, name: r.name, severity: r.severity, impact: r.impact, description: r.description };
    out.push(hit === true ? base : { ...base, ...hit });
  }
  return out;
}

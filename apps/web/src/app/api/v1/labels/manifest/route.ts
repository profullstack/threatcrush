import { NextResponse } from "next/server";
import { LABEL_DOMAIN, LABEL_VALUES, LABELER_DID, labelerKey, publicKeyB64 } from "@/lib/labeler-sign";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const DEFINITIONS: Record<string, string> = {
  malware: "A file CrushAV calls malicious (signature, high-confidence heuristic) or that a hash-reputation source lists as malware, or a file that actively loads from a domain listed for malware.",
  phishing: "A page that sends typed credentials to a chat bot or webhook, a ClickFix lure, or a file that actively posts to or loads from a domain listed for phishing.",
  cryptominer: "A page or script that starts a cryptocurrency miner in the visitor's browser.",
  spam: "Reserved. This labeler does not issue it yet.",
};

/** GET /api/v1/labels/manifest: who this labeler is, its key, its values and how to appeal (DIP-0036). */
export function GET() {
  const key = labelerKey();
  return NextResponse.json(
    {
      kind: "labeler_manifest",
      ver: 1,
      did: LABELER_DID,
      name: "ThreatCrush",
      public_key: key ? publicKeyB64(key) : null,
      key_type: "ed25519",
      signature: {
        format: `${LABEL_DOMAIN}\\n<src>\\n<uri>\\n<val>\\n<0|1 neg>\\n<cts>\\n<exp>`,
        encoding: "utf-8 input, base64url signature, raw base64url public key",
      },
      subjects: ["sha256:<lower-case hex of the whole file>"],
      values: LABEL_VALUES.map((v) => ({ val: v, definition: DEFINITIONS[v] })),
      endpoints: {
        query: "https://threatcrush.com/api/v1/labels/query",
        scan: "https://threatcrush.com/api/v1/labels/scan",
        log: "https://threatcrush.com/api/v1/labels/log",
      },
      appeal: "mailto:support@threatcrush.com?subject=Label%20appeal",
      spec: "https://github.com/profullstack/c0mpute/blob/master/dips/v2.x/0036-layered-moderation.md",
    },
    { headers: { "Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=300" } },
  );
}

# Build the ThreatCrush DNS monitor module

> ugig.net gig posting — implements [PRD-05](../05-dns-monitor-module.md)

- **Title:** Build the ThreatCrush DNS monitor module
- **Skills required:** `typescript`, `nodejs`, `linux`, `dns`, `security`, `entropy-analysis`
- **Budget type:** fixed
- **Budget (USD):** 1,500 – 2,500
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/dns-monitor`
- **Spec:** `docs/prds/05-dns-monitor-module.md`

## What we need

The README claims DNS-tunneling/DGA detection and lists `dns-monitor` as a
bundled module — it doesn't exist. Build the module that catches DNS-based
exfiltration and DGA beaconing.

## Scope

1. A DNS event source (resolver/query logs or passive `:53` observation);
   document what each environment realistically provides.
2. Tunneling heuristics: TXT query rate, label length, entropy thresholds.
3. DGA heuristics: domain entropy / n-gram / dictionary checks.
4. Thresholds via the rule engine (PRD-01); detections to `detections` (PRD-00).

## Acceptance criteria

- A scripted DNS-tunneling pattern and a high-entropy DGA burst are both flagged.
- Low false positives against a normal-traffic fixture corpus.
- PR with green CI and the fixture corpus committed.

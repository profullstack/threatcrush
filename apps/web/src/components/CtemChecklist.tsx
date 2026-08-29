"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import type { Checklist } from "@/content/ctem-guide.generated";
import { getUtm } from "@/lib/reader-tracking";

type Props = {
  checklist: Checklist;
  total: number;
  sessionId: string;
  /** Reading depth at the moment of submission, attached to the lead. */
  getReadPercent?: () => number;
};

const STORAGE_KEY = "tc_ctem_checklist";

/** Persist ticks so a reload mid-assessment does not throw the work away. */
function loadSaved(validIds: Set<string>): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((v): v is string => typeof v === "string" && validIds.has(v));
  } catch {
    return [];
  }
}

export default function CtemChecklist({ checklist, total, sessionId, getReadPercent }: Props) {
  const validIds = useMemo(
    () => new Set(checklist.stages.flatMap((s) => s.items.map((i) => i.id))),
    [checklist],
  );

  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [hydrated, setHydrated] = useState(false);

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [consentMarketing, setConsentMarketing] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [sent, setSent] = useState(false);

  const resultRef = useRef<HTMLDivElement | null>(null);
  const recordedRef = useRef<number>(-1);

  useEffect(() => {
    setChecked(new Set(loadSaved(validIds)));
    setHydrated(true);
  }, [validIds]);

  useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify([...checked]));
    } catch {
      /* storage blocked — ticking still works for this page view */
    }
  }, [checked, hydrated]);

  const score = total > 0 ? Math.round((checked.size / total) * 100) : 0;
  const band = useMemo(
    () =>
      checklist.bands.find((b) => score >= b.min && score <= b.max) ??
      checklist.bands[checklist.bands.length - 1],
    [checklist.bands, score],
  );

  const gaps = useMemo(
    () =>
      checklist.stages
        .map((stage) => ({
          n: stage.n,
          name: stage.name,
          missing: stage.items.filter((i) => !checked.has(i.id)),
        }))
        .filter((s) => s.missing.length > 0),
    [checklist.stages, checked],
  );

  const toggle = useCallback((id: string) => {
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  /**
   * Record the anonymous score once the reader stops ticking. Debounced so a
   * run down the list writes one row rather than twenty-seven.
   */
  useEffect(() => {
    if (!hydrated || checked.size === 0 || !sessionId) return;
    const t = setTimeout(() => {
      if (recordedRef.current === checked.size) return;
      recordedRef.current = checked.size;
      void fetch("/api/checklist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: sessionId, answers: [...checked] }),
      }).catch(() => {});
    }, 2500);
    return () => clearTimeout(t);
  }, [checked, hydrated, sessionId]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!name || !email) return;
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/checklist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: sessionId,
          answers: [...checked],
          name,
          email,
          company: company || undefined,
          consent_marketing: consentMarketing,
          read_percent: getReadPercent?.() ?? undefined,
          utm: getUtm(),
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Something went wrong");
      setSent(true);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  const started = checked.size > 0;

  return (
    <section id="checklist" className="scroll-mt-28">
      <div className="rounded-2xl border border-tc-green/30 bg-tc-card/60 backdrop-blur-md p-6 sm:p-8 glow-box">
        <p className="font-mono text-xs text-tc-green tracking-wider mb-3">
          // SELF-ASSESSMENT — {total} CONTROLS
        </p>
        <h2 className="text-2xl sm:text-3xl font-black text-white mb-2">{checklist.title}</h2>
        <p className="text-tc-green font-semibold mb-4">{checklist.subtitle}</p>
        <p className="text-tc-text-dim leading-relaxed mb-6">{checklist.intro}</p>

        {/* ── Live score ── */}
        <div
          className="sticky top-20 z-20 -mx-6 sm:-mx-8 mb-8 border-y border-tc-border bg-tc-darker/95 backdrop-blur px-6 sm:px-8 py-4"
          aria-live="polite"
        >
          <div className="flex items-center gap-4">
            <div className="font-mono text-3xl sm:text-4xl font-black text-tc-green glow-green tabular-nums w-24">
              {score}%
            </div>
            <div className="flex-1 min-w-0">
              <div className="h-2 rounded-full bg-tc-border overflow-hidden">
                <div
                  className="h-full rounded-full bg-tc-green transition-[width] duration-300 ease-out"
                  style={{ width: `${score}%` }}
                />
              </div>
              <p className="mt-1.5 text-xs text-tc-text-dim">
                {checked.size} of {total} controls running
                {started && (
                  <>
                    {" · "}
                    <span className="text-tc-green font-semibold">{band.label}</span>
                  </>
                )}
              </p>
            </div>
          </div>
        </div>

        {/* ── Stages ── */}
        <div className="space-y-8">
          {checklist.stages.map((stage) => {
            const done = stage.items.filter((i) => checked.has(i.id)).length;
            return (
              <div key={stage.id}>
                <div className="flex items-baseline gap-3 border-b-2 border-tc-green/40 pb-2 mb-4">
                  <span className="font-mono text-sm text-tc-green font-bold">{stage.n}</span>
                  <h3 className="text-xl font-bold text-white">{stage.name}</h3>
                  <span className="ml-auto font-mono text-xs text-tc-text-dim tabular-nums">
                    {done}/{stage.items.length}
                  </span>
                </div>
                <p className="text-sm italic text-tc-text-dim mb-4">{stage.question}</p>

                <ul className="space-y-2">
                  {stage.items.map((item) => {
                    const on = checked.has(item.id);
                    return (
                      <li key={item.id}>
                        <label
                          className={`flex gap-3 rounded-xl border p-4 cursor-pointer transition-all ${
                            on
                              ? "border-tc-green/50 bg-tc-green/5"
                              : "border-tc-border bg-tc-darker/40 hover:border-tc-green/25"
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={on}
                            onChange={() => toggle(item.id)}
                            className="mt-1 h-4 w-4 flex-shrink-0 accent-tc-green"
                          />
                          <span className="min-w-0">
                            <span
                              className={`block font-semibold text-sm ${
                                on ? "text-tc-green" : "text-tc-text"
                              }`}
                            >
                              {item.title}
                            </span>
                            <span className="mt-1 block text-sm text-tc-text-dim leading-relaxed">
                              {item.detail}
                            </span>
                          </span>
                        </label>
                      </li>
                    );
                  })}
                </ul>
              </div>
            );
          })}
        </div>

        {/* ── Result ── */}
        <div ref={resultRef} className="mt-10 pt-8 border-t border-tc-border">
          {!started ? (
            <p className="text-sm text-tc-text-dim text-center">
              Tick the controls you have running to see your readiness band.
            </p>
          ) : (
            <>
              <p className="font-mono text-xs text-tc-green tracking-wider mb-3">// YOUR RESULT</p>
              <h3 className="text-2xl font-black text-white mb-1">
                {score}% — <span className="text-tc-green glow-green">{band.label}</span>
              </h3>
              <p className="text-tc-text-dim leading-relaxed mb-6">{band.summary}</p>

              {gaps.length > 0 && (
                <div className="rounded-xl border border-tc-border bg-tc-darker/60 p-5 mb-6">
                  <p className="font-mono text-xs text-tc-green tracking-wider mb-3">
                    // {total - checked.size} CONTROLS NOT RUNNING
                  </p>
                  <div className="space-y-4">
                    {gaps.map((g) => (
                      <div key={g.n}>
                        <p className="text-sm font-bold text-white mb-1">
                          <span className="font-mono text-tc-green">{g.n}</span> {g.name}
                        </p>
                        <ul className="space-y-1">
                          {g.missing.map((m) => (
                            <li
                              key={m.id}
                              className="flex gap-2 text-sm text-tc-text-dim leading-relaxed"
                            >
                              <span className="text-tc-green/50 flex-shrink-0">·</span>
                              <span>{m.title}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ── Lead capture: the gap list, in writing ── */}
              {sent ? (
                <div className="rounded-xl border border-tc-green/40 bg-tc-green/5 p-6 text-center">
                  <div className="text-4xl mb-3">📬</div>
                  <h4 className="text-xl font-bold text-tc-green glow-green mb-2">
                    Sent to {email}
                  </h4>
                  <p className="text-sm text-tc-text-dim mb-4">
                    Your score, your band, and every control you did not tick — so you can work
                    the list without keeping this tab open.
                  </p>
                  <pre className="rounded-lg bg-black/60 border border-tc-border px-3 py-2 font-mono text-xs text-tc-green overflow-x-auto text-left">
                    curl -fsSL https://threatcrush.com/install.sh | sh
                  </pre>
                </div>
              ) : (
                <form
                  onSubmit={handleSubmit}
                  className="rounded-xl border border-tc-green/30 bg-tc-darker/60 p-5 sm:p-6"
                >
                  <h4 className="text-lg font-bold text-white mb-1">
                    {gaps.length ? "Email me the gap list" : "Email me my result"}
                  </h4>
                  <p className="text-sm text-tc-text-dim mb-4">
                    {gaps.length ? (
                      <>
                        We&apos;ll send your score and the {total - checked.size}{" "}
                        {total - checked.size === 1 ? "control" : "controls"} you didn&apos;t tick.
                        No sales call.
                      </>
                    ) : (
                      <>
                        We&apos;ll send your score and the full control list for your records. No
                        sales call.
                      </>
                    )}
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
                    <input
                      type="text"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      required
                      autoComplete="name"
                      placeholder="Your name"
                      aria-label="Your name"
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-4 py-2.5 text-tc-text placeholder:text-tc-text-dim/40 focus:border-tc-green/50 focus:outline-none focus:ring-1 focus:ring-tc-green/30 transition-all text-sm"
                    />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      autoComplete="email"
                      placeholder="you@company.com"
                      aria-label="Work email"
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-4 py-2.5 text-tc-text placeholder:text-tc-text-dim/40 focus:border-tc-green/50 focus:outline-none focus:ring-1 focus:ring-tc-green/30 transition-all font-mono text-sm"
                    />
                  </div>
                  <input
                    type="text"
                    value={company}
                    onChange={(e) => setCompany(e.target.value)}
                    autoComplete="organization"
                    placeholder="Company (optional)"
                    aria-label="Company"
                    className="w-full rounded-lg border border-tc-border bg-tc-darker px-4 py-2.5 text-tc-text placeholder:text-tc-text-dim/40 focus:border-tc-green/50 focus:outline-none focus:ring-1 focus:ring-tc-green/30 transition-all text-sm mb-3"
                  />
                  <label className="flex items-start gap-2.5 text-xs text-tc-text-dim cursor-pointer mb-4">
                    <input
                      type="checkbox"
                      checked={consentMarketing}
                      onChange={(e) => setConsentMarketing(e.target.checked)}
                      className="mt-0.5 accent-tc-green"
                    />
                    <span>
                      Send me occasional ThreatCrush updates. We don&apos;t spam — opt out from any
                      email.
                    </span>
                  </label>

                  {error && <p className="text-red-400 text-sm mb-3">{error}</p>}

                  <button
                    type="submit"
                    disabled={!name || !email || loading}
                    className="w-full rounded-xl bg-tc-green px-6 py-3.5 font-bold text-black transition-all hover:bg-tc-green-dim disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    {loading ? "Sending..." : "Email me my results →"}
                  </button>
                </form>
              )}
            </>
          )}
        </div>

        <p className="mt-6 text-[11px] italic text-tc-text-dim/70">{checklist.disclaimer}</p>
      </div>
    </section>
  );
}

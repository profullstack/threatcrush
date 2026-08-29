"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import CtemChecklist from "@/components/CtemChecklist";
import {
  CHECKLIST,
  CHECKLIST_TOTAL,
  GUIDE_READ_MINUTES,
  GUIDE_SECTIONS,
} from "@/content/ctem-guide.generated";
import { getSessionId, getUtm, sendProgress } from "@/lib/reader-tracking";

const SLUG = "ctem-guide";
const PDF_PATH = "/whitepaper/threatcrush-ctem-guide.pdf";

/** Depths at which we beacon. Anything finer is noise, anything coarser loses the drop-off. */
const MILESTONES = [10, 25, 50, 75, 90, 100];

type NavEntry = { id: string; title: string };

/**
 * Everything the header covers: the fixed nav plus the progress bar pinned
 * under it. Read from the same token the CSS uses so the rail highlights the
 * section you can actually see, not one hidden behind the header.
 */
function headerOffset() {
  if (typeof window === "undefined") return 112;
  const raw = getComputedStyle(document.documentElement).getPropertyValue("--tc-header-h");
  const px = Number.parseFloat(raw);
  return (Number.isFinite(px) ? px : 81) + 40;
}

const NAV: NavEntry[] = [
  ...GUIDE_SECTIONS.map((s) => ({ id: s.id, title: s.title })),
  { id: "checklist", title: "Readiness checklist" },
];

export default function GuideReader() {
  const [percent, setPercent] = useState(0);
  const [activeId, setActiveId] = useState<string>(NAV[0]?.id ?? "");
  const [tocOpen, setTocOpen] = useState(false);

  const sessionIdRef = useRef("");
  const [sessionId, setSessionId] = useState("");
  const percentRef = useRef(0);
  const activeIdRef = useRef(activeId);
  const secondsRef = useRef(0);
  const firedRef = useRef<Set<number>>(new Set());
  const articleRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const id = getSessionId();
    sessionIdRef.current = id;
    setSessionId(id);
  }, []);

  const beacon = useCallback((completed = false) => {
    if (!sessionIdRef.current) return;
    sendProgress({
      session_id: sessionIdRef.current,
      slug: SLUG,
      read_percent: percentRef.current,
      seconds_engaged: secondsRef.current,
      furthest_section: activeIdRef.current || null,
      completed,
      referrer: typeof document !== "undefined" ? document.referrer || undefined : undefined,
      utm: getUtm(),
    });
  }, []);

  /* ── Scroll progress ─────────────────────────────────────────────── */
  useEffect(() => {
    let frame = 0;

    const measure = () => {
      frame = 0;
      const el = articleRef.current;
      if (!el) return;

      // Progress through the article itself, not the whole document: the site
      // footer is not part of the read, and counting it caps everyone at ~85%.
      const start = el.offsetTop;
      const readable = Math.max(1, el.offsetHeight - window.innerHeight * 0.6);
      const travelled = window.scrollY + window.innerHeight * 0.4 - start;
      const pct = Math.min(100, Math.max(0, Math.round((travelled / readable) * 100)));

      if (pct !== percentRef.current) {
        percentRef.current = pct;
        setPercent(pct);

        for (const m of MILESTONES) {
          if (pct >= m && !firedRef.current.has(m)) {
            firedRef.current.add(m);
            beacon(m === 100);
          }
        }
      }
    };

    const onScroll = () => {
      if (!frame) frame = window.requestAnimationFrame(measure);
    };

    measure();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      if (frame) window.cancelAnimationFrame(frame);
    };
  }, [beacon]);

  /* ── Engaged time (visible tab only) ─────────────────────────────── */
  useEffect(() => {
    const tick = window.setInterval(() => {
      if (document.visibilityState === "visible") secondsRef.current += 1;
    }, 1000);
    return () => window.clearInterval(tick);
  }, []);

  /* ── Flush on the way out ────────────────────────────────────────── */
  useEffect(() => {
    const flush = () => {
      if (document.visibilityState === "hidden") beacon(percentRef.current >= 100);
    };
    document.addEventListener("visibilitychange", flush);
    window.addEventListener("pagehide", flush);
    return () => {
      document.removeEventListener("visibilitychange", flush);
      window.removeEventListener("pagehide", flush);
    };
  }, [beacon]);

  /* ── Active section for the rail ─────────────────────────────────── */
  useEffect(() => {
    const targets = NAV.map((n) => document.getElementById(n.id)).filter(
      (el): el is HTMLElement => Boolean(el),
    );
    if (!targets.length) return;

    const observer = new IntersectionObserver(
      (entries) => {
        // The topmost intersecting heading wins; sorting keeps it stable when
        // several sections are on screen on a tall display.
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) {
          const id = visible[0].target.id;
          activeIdRef.current = id;
          setActiveId(id);
        }
      },
      { rootMargin: `-${headerOffset()}px 0px -70% 0px`, threshold: 0 },
    );

    targets.forEach((t) => observer.observe(t));
    return () => observer.disconnect();
  }, []);

  const getReadPercent = useCallback(() => percentRef.current, []);

  const jumpTo = (id: string) => {
    setTocOpen(false);
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <>
      {/* ── Progress bar, pinned under the site header ──
          top comes from the header's own token: 4rem was shorter than the
          header, so the bar drew a line across the logo and nav. z-30 keeps it
          under the header, including when the mobile menu drops open. */}
      <div className="fixed top-[var(--tc-header-h)] left-0 right-0 z-30 pointer-events-none">
        <div className="h-1 bg-tc-border/60">
          <div
            className="h-full bg-tc-green transition-[width] duration-150 ease-out"
            style={{ width: `${percent}%` }}
          />
        </div>
        <div className="mx-auto max-w-7xl px-6 flex justify-end">
          <span
            className="pointer-events-auto mt-1 rounded-full border border-tc-border bg-tc-darker/90 px-2.5 py-0.5 font-mono text-[11px] tabular-nums text-tc-green backdrop-blur"
            aria-hidden="true"
          >
            {percent}%
          </span>
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-6 pt-28 pb-24">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10">
          {/* ── Contents rail ── */}
          <aside className="lg:col-span-3">
            <div className="lg:sticky lg:top-[calc(var(--tc-header-h)+2.5rem)]">
              <button
                type="button"
                onClick={() => setTocOpen((v) => !v)}
                aria-expanded={tocOpen}
                className="lg:hidden w-full flex items-center justify-between rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-sm font-semibold text-tc-text"
              >
                <span>Contents</span>
                <span className="font-mono text-xs text-tc-green">
                  {tocOpen ? "▲" : "▼"} {percent}%
                </span>
              </button>

              <nav
                aria-label="Guide contents"
                className={`${tocOpen ? "block" : "hidden"} lg:block mt-3 lg:mt-0`}
              >
                <p className="hidden lg:block font-mono text-xs text-tc-green tracking-wider mb-3">
                  // CONTENTS
                </p>
                <ul className="space-y-0.5 border-l border-tc-border">
                  {NAV.map((n) => {
                    const on = activeId === n.id;
                    return (
                      <li key={n.id}>
                        <button
                          type="button"
                          onClick={() => jumpTo(n.id)}
                          aria-current={on ? "true" : undefined}
                          className={`block w-full text-left -ml-px border-l-2 pl-3 pr-2 py-1.5 text-sm transition-colors ${
                            on
                              ? "border-tc-green text-tc-green font-semibold"
                              : "border-transparent text-tc-text-dim hover:text-tc-text hover:border-tc-border"
                          }`}
                        >
                          {n.title}
                        </button>
                      </li>
                    );
                  })}
                </ul>

                <div className="mt-6 rounded-xl border border-tc-border bg-tc-card/60 p-4">
                  <p className="text-xs text-tc-text-dim mb-3">
                    {GUIDE_READ_MINUTES} min read · no paywall · no signup
                  </p>
                  <a
                    href={PDF_PATH}
                    download
                    className="block rounded-lg border border-tc-green/40 px-3 py-2 text-center text-sm font-semibold text-tc-green transition-colors hover:bg-tc-green/10"
                  >
                    ↓ Download PDF
                  </a>
                </div>
              </nav>
            </div>
          </aside>

          {/* ── The guide ── */}
          <div className="lg:col-span-9 min-w-0">
            <div ref={articleRef}>
              <article className="guide-prose">
                {GUIDE_SECTIONS.map((section) => (
                  <section
                    key={section.id}
                    id={section.id}
                    className="scroll-mt-[calc(var(--tc-header-h)+2.5rem)]"
                  >
                    {section.id !== "top" && <h2>{section.title}</h2>}
                    <div dangerouslySetInnerHTML={{ __html: section.html }} />
                  </section>
                ))}
              </article>

              <div className="mt-16">
                <CtemChecklist
                  checklist={CHECKLIST}
                  total={CHECKLIST_TOTAL}
                  sessionId={sessionId}
                  getReadPercent={getReadPercent}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

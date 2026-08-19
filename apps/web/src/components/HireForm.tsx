"use client";

import { useCallback, useState, type FormEvent } from "react";

type Status = "idle" | "submitting" | "success" | "error";

const inputClass =
  "w-full bg-tc-darker border border-tc-border rounded-lg px-3 py-2.5 text-sm text-tc-text focus:border-tc-green focus:outline-none transition-colors";
const labelClass = "block text-sm font-medium text-tc-text-dim mb-1.5";

// Posts to the shared /api/contact route with topic "hire"; the extra fields
// (target, stack, timeline) ride along as labelled rows in the notification
// email and are appended to the persisted message.
export function HireForm() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [target, setTarget] = useState("");
  const [stack, setStack] = useState("");
  const [timeline, setTimeline] = useState("");
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState("");

  const handleSubmit = useCallback(
    async (e: FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      setStatus("submitting");
      setError("");

      try {
        const res = await fetch("/api/contact", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name,
            email,
            company,
            target,
            stack,
            timeline,
            message,
            topic: "hire",
          }),
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Failed to send");

        setStatus("success");
        setName("");
        setEmail("");
        setCompany("");
        setTarget("");
        setStack("");
        setTimeline("");
        setMessage("");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Something went wrong");
        setStatus("error");
      }
    },
    [name, email, company, target, stack, timeline, message],
  );

  return (
    <div className="relative bg-tc-card border border-tc-border rounded-2xl overflow-hidden">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-tc-green to-transparent opacity-40" />

      <div className="p-8">
        {status === "success" ? (
          <div className="text-center py-8">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-tc-green/10 text-tc-green text-2xl mb-4">
              ✓
            </div>
            <h3 className="text-xl font-bold text-white mb-2">Got it — talk soon.</h3>
            <p className="text-sm text-tc-text-dim">
              We&apos;ll come back with a scope and a fixed price, usually the same
              business day. If it&apos;s urgent, email{" "}
              <a href="mailto:hello@threatcrush.com" className="text-tc-green hover:underline">
                hello@threatcrush.com
              </a>
              .
            </p>
            <button
              onClick={() => setStatus("idle")}
              className="mt-6 text-sm text-tc-green hover:underline"
            >
              Send another request
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="hire-name" className={labelClass}>
                  Name
                </label>
                <input
                  id="hire-name"
                  type="text"
                  required
                  autoComplete="name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className={inputClass}
                />
              </div>

              <div>
                <label htmlFor="hire-email" className={labelClass}>
                  Email
                </label>
                <input
                  id="hire-email"
                  type="email"
                  required
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={inputClass}
                />
              </div>

              <div>
                <label htmlFor="hire-company" className={labelClass}>
                  Company <span className="text-tc-text-dim/60">(optional)</span>
                </label>
                <input
                  id="hire-company"
                  type="text"
                  autoComplete="organization"
                  value={company}
                  onChange={(e) => setCompany(e.target.value)}
                  className={inputClass}
                />
              </div>

              <div>
                <label htmlFor="hire-target" className={labelClass}>
                  App or repo URL <span className="text-tc-text-dim/60">(optional)</span>
                </label>
                <input
                  id="hire-target"
                  type="text"
                  placeholder="https://github.com/you/app"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className={inputClass}
                />
              </div>

              <div>
                <label htmlFor="hire-stack" className={labelClass}>
                  Stack <span className="text-tc-text-dim/60">(optional)</span>
                </label>
                <input
                  id="hire-stack"
                  type="text"
                  placeholder="Node + Postgres on AWS, 3 services"
                  value={stack}
                  onChange={(e) => setStack(e.target.value)}
                  className={inputClass}
                />
              </div>

              <div>
                <label htmlFor="hire-timeline" className={labelClass}>
                  Timeline <span className="text-tc-text-dim/60">(optional)</span>
                </label>
                <input
                  id="hire-timeline"
                  type="text"
                  placeholder="Customer audit in 3 weeks"
                  value={timeline}
                  onChange={(e) => setTimeline(e.target.value)}
                  className={inputClass}
                />
              </div>
            </div>

            <div>
              <label htmlFor="hire-message" className={labelClass}>
                What do you need looked at?
              </label>
              <textarea
                id="hire-message"
                required
                rows={5}
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Size of the app, what worries you, whether anyone has assessed it before, compliance driver if there is one…"
                className={`${inputClass} resize-y`}
              />
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg px-4 py-3 text-sm">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={status === "submitting"}
              className="w-full rounded-lg bg-tc-green px-6 py-3 font-bold text-black text-lg transition-all hover:bg-tc-green-dim disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {status === "submitting" ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin" />
                  Sending…
                </span>
              ) : (
                "Request a scope"
              )}
            </button>

            <p className="text-xs text-tc-text-dim">
              Engagements start at $400 for a scan with human input and are priced per
              app. You get the number in writing before any work starts.
            </p>
          </form>
        )}
      </div>
    </div>
  );
}

"use client";

import { useState, useCallback, FormEvent } from "react";

type Status = "idle" | "submitting" | "success" | "error";

export default function PricingPage() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
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
            message,
            topic: "pricing",
          }),
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Failed to send");

        setStatus("success");
        setName("");
        setEmail("");
        setCompany("");
        setMessage("");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Something went wrong");
        setStatus("error");
      }
    },
    [name, email, company, message],
  );

  return (
    <div className="min-h-screen bg-tc-darker">
      <section className="pt-20 pb-12 px-4 text-center">
        <div className="max-w-3xl mx-auto">
          <h1 className="text-4xl md:text-5xl font-bold font-mono text-white mb-4">
            Contact Us for{" "}
            <span className="text-tc-green glow-green">Pricing</span>
          </h1>
          <p className="text-lg text-tc-text-dim max-w-xl mx-auto">
            Tell us a bit about your environment and we&apos;ll get back to you
            with a quote that fits.
          </p>
        </div>
      </section>

      <section className="pb-20 px-4">
        <div className="max-w-lg mx-auto">
          <div className="relative bg-tc-card border border-tc-border rounded-2xl overflow-hidden">
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-tc-green to-transparent opacity-40" />

            <div className="p-8">
              {status === "success" ? (
                <div className="text-center py-8">
                  <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-tc-green/10 text-tc-green text-2xl mb-4">
                    ✓
                  </div>
                  <h2 className="text-xl font-bold text-white mb-2">
                    Thanks — we got it.
                  </h2>
                  <p className="text-sm text-tc-text-dim">
                    We&apos;ll be in touch shortly with pricing details.
                  </p>
                  <button
                    onClick={() => setStatus("idle")}
                    className="mt-6 text-sm text-tc-green hover:underline"
                  >
                    Send another message
                  </button>
                </div>
              ) : (
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <label
                      htmlFor="name"
                      className="block text-sm font-medium text-tc-text-dim mb-1.5"
                    >
                      Name
                    </label>
                    <input
                      id="name"
                      type="text"
                      required
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      className="w-full bg-tc-darker border border-tc-border rounded-lg px-3 py-2.5 text-sm text-tc-text focus:border-tc-green focus:outline-none transition-colors"
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="email"
                      className="block text-sm font-medium text-tc-text-dim mb-1.5"
                    >
                      Email
                    </label>
                    <input
                      id="email"
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full bg-tc-darker border border-tc-border rounded-lg px-3 py-2.5 text-sm text-tc-text focus:border-tc-green focus:outline-none transition-colors"
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="company"
                      className="block text-sm font-medium text-tc-text-dim mb-1.5"
                    >
                      Company{" "}
                      <span className="text-tc-text-dim/60">(optional)</span>
                    </label>
                    <input
                      id="company"
                      type="text"
                      value={company}
                      onChange={(e) => setCompany(e.target.value)}
                      className="w-full bg-tc-darker border border-tc-border rounded-lg px-3 py-2.5 text-sm text-tc-text focus:border-tc-green focus:outline-none transition-colors"
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="message"
                      className="block text-sm font-medium text-tc-text-dim mb-1.5"
                    >
                      How can we help?
                    </label>
                    <textarea
                      id="message"
                      required
                      rows={5}
                      value={message}
                      onChange={(e) => setMessage(e.target.value)}
                      placeholder="Team size, deployment needs, timeline, anything else relevant…"
                      className="w-full bg-tc-darker border border-tc-border rounded-lg px-3 py-2.5 text-sm text-tc-text focus:border-tc-green focus:outline-none transition-colors resize-y"
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
                      "Request Pricing"
                    )}
                  </button>
                </form>
              )}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

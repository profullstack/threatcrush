"use client";

import { useEffect, useState } from "react";
import { ProfileFields } from "@profullstack/profile/react";
import type { ProfileField } from "@profullstack/profile";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";

type Values = Partial<Record<ProfileField, string | null>>;
// Email is the account address, shown in the Profile card above.
const FIELDS: ProfileField[] = ["first_name", "last_name", "company_domain", "job_title", "linkedin_url"];

/**
 * The profile fields shared across Profullstack properties, read and written
 * through /api/v1/me/profile.
 */
export default function ProfileFieldsCard() {
  const { signedIn } = useAuth();
  const [values, setValues] = useState<Values>({});
  const [errors, setErrors] = useState<Partial<Record<ProfileField, string>>>({});
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!signedIn) return;
    fetch("/api/v1/me/profile", { headers: authHeaders(), cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((body) => {
        const p = body?.profile ?? {};
        setValues(Object.fromEntries(FIELDS.map((k) => [k, p[k] ?? ""])));
      })
      .catch(() => setError("Could not load your profile."))
      .finally(() => setLoaded(true));
  }, [signedIn]);

  if (!signedIn) return null;

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSaved(false);
    setError(null);
    setErrors({});
    try {
      const res = await fetch("/api/v1/me/profile", {
        method: "PATCH",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(values),
      });
      const body = await res.json().catch(() => ({}));
      if (res.ok) setSaved(true);
      else {
        setErrors(body.errors ?? {});
        setError(body.error ?? "Could not save.");
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="mx-auto max-w-3xl px-6 pb-16">
      <form onSubmit={save} className="bg-tc-card border border-tc-border rounded-xl p-6 space-y-4">
        <h2 className="text-lg font-semibold text-white">About you</h2>
        <ProfileFields
          fields={FIELDS}
          idPrefix="account-"
          values={values}
          onChange={setValues}
          errors={errors}
          disabled={!loaded}
        />
        {error && <p className="text-sm text-red-400">{error}</p>}
        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={saving || !loaded}
            className="text-sm bg-tc-green text-black px-3 py-1.5 rounded-lg font-semibold hover:bg-tc-green-dim disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save"}
          </button>
          {saved && <span className="text-sm text-tc-green">Saved.</span>}
        </div>
      </form>
    </section>
  );
}

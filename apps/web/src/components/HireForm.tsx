import { ContactForm } from "@profullstack/contact-form/react";
import type { ContactFormProps } from "@profullstack/contact-form";

// The /hire inquiry. The questions, token and honeypot come from
// lib/contact.ts (contact.props(), minted per render by the page), and the
// form posts to the shared /api/contact route under the hire topic. The
// extra fields (target, stack, timeline) ride along as labelled rows in the
// notification email and are appended to the persisted message.
// Its look is the .tc-hire-form rules in globals.css.
export function HireForm({ form }: { form: ContactFormProps }) {
  return (
    <div className="relative bg-tc-card border border-tc-border rounded-2xl overflow-hidden">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-tc-green to-transparent opacity-40" />

      <div className="p-8">
        <ContactForm {...form} className="tc-hire-form" idPrefix="hire" resetLabel="Send another request">
          <p className="mt-2 text-sm text-tc-text-dim">
            If it&apos;s urgent, email{" "}
            <a href="mailto:hello@threatcrush.com" className="text-tc-green hover:underline">
              hello@threatcrush.com
            </a>
            .
          </p>
        </ContactForm>
        <p className="mt-4 text-xs text-tc-text-dim">
          Engagements start at $400 for a scan with human input and are priced per
          app. You get the number in writing before any work starts.
        </p>
      </div>
    </div>
  );
}

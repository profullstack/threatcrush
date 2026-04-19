import "server-only";

const TELNYX_API_KEY = process.env.TELNYX_API_KEY || "";
const TELNYX_PHONE_NUMBER = process.env.TELNYX_PHONE_NUMBER || "";

export function isTelnyxConfigured(): boolean {
  return TELNYX_API_KEY.length > 0 && TELNYX_PHONE_NUMBER.length > 0;
}

/**
 * Send a plain SMS via Telnyx Messaging API.
 * Throws on non-2xx responses with the Telnyx error body for logging.
 */
export async function sendTelnyxSms(to: string, text: string): Promise<void> {
  if (!isTelnyxConfigured()) {
    throw new Error("Telnyx is not configured (TELNYX_API_KEY / TELNYX_PHONE_NUMBER)");
  }

  const res = await fetch("https://api.telnyx.com/v2/messages", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${TELNYX_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: TELNYX_PHONE_NUMBER,
      to,
      text,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Telnyx send failed: ${res.status} ${body}`);
  }
}

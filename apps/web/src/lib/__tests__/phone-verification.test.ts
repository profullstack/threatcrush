import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMemoryTables } from "@/__tests__/helpers/memory-tables";

let db = createMemoryTables();

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({ from: (table: string) => db.from(table) }),
}));

vi.mock("@/lib/telnyx", () => ({
  sendTelnyxSms: vi.fn(),
}));

import { sendTelnyxSms } from "@/lib/telnyx";
import {
  issuePhoneCode,
  SMS_SENDS_PER_DAY,
  SMS_SENDS_PER_HOUR,
} from "@/lib/phone-verification";

const mockSend = vi.mocked(sendTelnyxSms);
const MINUTE = 60_000;
const START = new Date("2026-09-25T12:00:00.000Z").getTime();

let nextUser = 0;
/** Every send comes from a fresh account, as it would in a signup loop. */
function sendFromNewAccount(phone: string) {
  nextUser++;
  return issuePhoneCode({ userId: `user-${nextUser}`, phone, bypassCooldown: true });
}

async function outcome(phone: string): Promise<"sent" | number> {
  try {
    await sendFromNewAccount(phone);
    return "sent";
  } catch (err) {
    return (err as Error & { status?: number }).status ?? -1;
  }
}

function advance(ms: number) {
  vi.setSystemTime(Date.now() + ms);
}

beforeEach(() => {
  db = createMemoryTables();
  mockSend.mockReset();
  mockSend.mockResolvedValue(undefined);
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(START);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("per-number SMS ceiling", () => {
  it(`sends ${SMS_SENDS_PER_HOUR} codes an hour to one number and refuses the next with 429 without sending`, async () => {
    // Formatting differences must not buy extra sends.
    const spellings = ["+15551234567", "(555) 123-4567", "555.123.4567", "+1 555 123 4567"];
    const results = [];
    for (const phone of spellings) results.push(await outcome(phone));

    expect(results).toEqual(["sent", "sent", "sent", 429]);
    expect(mockSend).toHaveBeenCalledTimes(SMS_SENDS_PER_HOUR);
    // The refused account got no code stored either.
    expect(db.tables.phone_verification_codes.map((row) => row.user_id)).not.toContain(`user-${nextUser}`);
  });

  it("tells the caller how long to wait", async () => {
    for (let i = 0; i < SMS_SENDS_PER_HOUR; i++) {
      await sendFromNewAccount("+15551234567");
      advance(10 * MINUTE);
    }

    // The oldest send ages out 60 min after it was made, 30 min from now.
    await expect(sendFromNewAccount("+15551234567")).rejects.toMatchObject({
      status: 429,
      retryAfterSeconds: 30 * 60,
      message: expect.stringContaining("30 minutes"),
    });
  });

  it("allows another send once the oldest one in the hour ages out, even after refused retries", async () => {
    for (let i = 0; i < SMS_SENDS_PER_HOUR; i++) await sendFromNewAccount("+15551234567");
    for (let i = 0; i < 5; i++) {
      advance(5 * MINUTE);
      expect(await outcome("+15551234567")).toBe(429);
    }

    vi.setSystemTime(START + 60 * MINUTE - 1);
    expect(await outcome("+15551234567")).toBe(429);
    vi.setSystemTime(START + 60 * MINUTE + 1);
    expect(await outcome("+15551234567")).toBe("sent");
    expect(mockSend).toHaveBeenCalledTimes(SMS_SENDS_PER_HOUR + 1);
  });

  it(`caps one number at ${SMS_SENDS_PER_DAY} a day even when sends are spread out`, async () => {
    // 25 minutes apart never trips the hourly ceiling.
    for (let i = 0; i < SMS_SENDS_PER_DAY; i++) {
      expect(await outcome("+15551234567")).toBe("sent");
      advance(25 * MINUTE);
    }
    expect(await outcome("+15551234567")).toBe(429);
    expect(mockSend).toHaveBeenCalledTimes(SMS_SENDS_PER_DAY);

    vi.setSystemTime(START + 24 * 60 * MINUTE + 1);
    expect(await outcome("+15551234567")).toBe("sent");
  });

  it("counts each number separately", async () => {
    for (let i = 0; i < SMS_SENDS_PER_HOUR; i++) await sendFromNewAccount("+15551234567");

    expect(await outcome("+15557654321")).toBe("sent");
  });

  it("applies to resends from the same account as well as to signups", async () => {
    for (let i = 0; i < SMS_SENDS_PER_HOUR; i++) {
      await issuePhoneCode({ userId: "user-same", phone: "+15551234567" });
      advance(1 * MINUTE); // past the 30 s per-account cooldown
    }

    await expect(issuePhoneCode({ userId: "user-same", phone: "+15551234567" })).rejects.toMatchObject({
      status: 429,
    });
    expect(mockSend).toHaveBeenCalledTimes(SMS_SENDS_PER_HOUR);
  });
});

import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin, getSupabaseClient } from "@/lib/supabase";

// The metered endpoint intentionally supports one text model with a known price.
// Explicit-only cache mode with no breakpoints prevents unreported cache-write
// charges from making the customer's 20% margin calculation inaccurate.
// Current rates: https://developers.openai.com/api/docs/models/gpt-5.6-luna
const MODEL = "gpt-5.6-luna";
const INPUT_USD_PER_MILLION = 0.2;
const CACHED_INPUT_USD_PER_MILLION = 0.02;
const OUTPUT_USD_PER_MILLION = 1.2;
const MARGIN = 0.2;
const MAX_BODY_BYTES = 64 * 1024;
const DEFAULT_MAX_OUTPUT_TOKENS = 2048;
const MAX_OUTPUT_TOKENS = 4096;
export const runtime = "nodejs";

type InputMessage = { role: "system" | "developer" | "user" | "assistant"; content: string };

function error(message: string, status: number) {
  return NextResponse.json({ error: { message, type: "threatcrush_billing_error" } }, { status });
}

function chargeUsd(value: number): number {
  return Number(value.toFixed(12));
}

function reserveUsd(value: number): number {
  return Number((Math.ceil(value * 1_000_000_000_000) / 1_000_000_000_000).toFixed(12));
}

function parseInput(value: unknown): string | InputMessage[] | null {
  if (typeof value === "string") return value.length ? value : null;
  if (!Array.isArray(value) || value.length === 0 || value.length > 50) return null;
  const messages: InputMessage[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") return null;
    const record = item as Record<string, unknown>;
    if (!["system", "developer", "user", "assistant"].includes(String(record.role))) return null;
    if (typeof record.content !== "string") return null;
    messages.push({ role: record.role as InputMessage["role"], content: record.content });
  }
  return messages.some((message) => message.role === "user") ? messages : null;
}

async function releaseReservation(admin: ReturnType<typeof getSupabaseAdmin>, reservationId: string, userId: string) {
  const { error: releaseError } = await admin.rpc("release_ai_usage_credits", {
    p_reservation_id: reservationId,
    p_user_id: userId,
  });
  if (releaseError) console.error("[usage/ai] reservation release failed:", releaseError.message);
}

/** OpenAI Responses API proxy. Each successful response is billed to credits. */
export async function POST(request: NextRequest) {
  const match = /^Bearer\s+(.+)$/i.exec(request.headers.get("authorization") || "");
  if (!match) return error("Sign in and send your ThreatCrush access token as a Bearer token.", 401);

  const auth = await getSupabaseClient().auth.getUser(match[1]);
  const user = auth.data.user;
  if (auth.error || !user?.email) return error("Invalid or expired access token.", 401);
  if (!process.env.OPENAI_API_KEY) return error("AI requests are temporarily unavailable.", 503);

  const declaredBodyBytes = Number(request.headers.get("content-length"));
  if (Number.isFinite(declaredBodyBytes) && declaredBodyBytes > MAX_BODY_BYTES) {
    return error(`Request body must be at most ${MAX_BODY_BYTES} bytes.`, 413);
  }

  let raw: string;
  try {
    raw = await request.text();
  } catch {
    return error("Could not read the request body.", 400);
  }
  const bodyBytes = Buffer.byteLength(raw, "utf8");
  if (bodyBytes === 0 || bodyBytes > MAX_BODY_BYTES) {
    return error(`Request body must be between 1 byte and ${MAX_BODY_BYTES} bytes.`, 413);
  }

  let body: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return error("A JSON object is required.", 400);
    body = parsed as Record<string, unknown>;
  } catch {
    return error("Malformed JSON request body.", 400);
  }

  const allowedFields = new Set(["model", "input", "instructions", "max_output_tokens", "reasoning"]);
  if (Object.keys(body).some((key) => !allowedFields.has(key))) {
    return error("Only model, input, instructions, max_output_tokens, and reasoning are supported.", 400);
  }
  if (body.model !== undefined && body.model !== MODEL) return error(`Supported model: ${MODEL}.`, 400);
  const input = parseInput(body.input);
  if (input === null) return error("input must be text or 1–50 text messages including a user message.", 400);
  if (body.instructions !== undefined && typeof body.instructions !== "string") {
    return error("instructions must be text.", 400);
  }
  const maxOutputTokens = body.max_output_tokens === undefined ? DEFAULT_MAX_OUTPUT_TOKENS : body.max_output_tokens;
  if (!Number.isInteger(maxOutputTokens) || Number(maxOutputTokens) < 1 || Number(maxOutputTokens) > MAX_OUTPUT_TOKENS) {
    return error(`max_output_tokens must be an integer from 1 to ${MAX_OUTPUT_TOKENS}.`, 400);
  }
  let reasoning: { effort: string } | undefined;
  if (body.reasoning !== undefined) {
    if (!body.reasoning || typeof body.reasoning !== "object" || Array.isArray(body.reasoning)) {
      return error("reasoning must be an object with an effort field.", 400);
    }
    const effort = (body.reasoning as Record<string, unknown>).effort;
    if (!["low", "medium", "high"].includes(String(effort))) {
      return error("reasoning.effort must be low, medium, or high.", 400);
    }
    reasoning = { effort: String(effort) };
  }

  // UTF-8 bytes are a conservative token upper bound. Reserve the maximum
  // possible provider cost before calling OpenAI, then settle actual usage.
  const maximumProviderCost =
    (bodyBytes * INPUT_USD_PER_MILLION + Number(maxOutputTokens) * OUTPUT_USD_PER_MILLION) / 1_000_000;
  const reservationAmount = reserveUsd(maximumProviderCost * (1 + MARGIN));
  const admin = getSupabaseAdmin();
  const { data: reservationId, error: reserveError } = await admin.rpc("reserve_ai_usage_credits", {
    p_user_id: user.id,
    p_amount_usd: reservationAmount,
  });
  if (reserveError) {
    if (reserveError.message.includes("insufficient_credits")) {
      return error("Not enough credits for this request. Add credits on the AI Usage page.", 402);
    }
    console.error("[usage/ai] reserve failed:", reserveError.message);
    return error("Could not reserve credits for this request.", 503);
  }
  if (typeof reservationId !== "string") return error("Could not reserve credits for this request.", 503);

  let upstream: Response;
  try {
    upstream = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: MODEL,
        input,
        max_output_tokens: Number(maxOutputTokens),
        store: false,
        prompt_cache_options: { mode: "explicit" },
        ...(body.instructions !== undefined ? { instructions: body.instructions } : {}),
        ...(reasoning ? { reasoning } : {}),
      }),
      signal: AbortSignal.timeout(120_000),
    });
  } catch (cause) {
    await releaseReservation(admin, reservationId, user.id);
    const timedOut = cause instanceof DOMException && cause.name === "TimeoutError";
    return error(timedOut ? "The AI request timed out." : "The AI provider could not be reached.", 502);
  }

  let result: Record<string, unknown>;
  try {
    const parsed: unknown = await upstream.json();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("bad upstream body");
    result = parsed as Record<string, unknown>;
  } catch {
    await releaseReservation(admin, reservationId, user.id);
    return error("The AI provider returned an invalid response.", 502);
  }

  if (!upstream.ok) {
    await releaseReservation(admin, reservationId, user.id);
    const upstreamError = result.error as { message?: unknown } | undefined;
    return NextResponse.json({ error: { message: typeof upstreamError?.message === "string" ? upstreamError.message : "AI provider request failed." } }, { status: upstream.status });
  }

  const usage = result.usage as {
    input_tokens?: unknown;
    output_tokens?: unknown;
    input_tokens_details?: { cached_tokens?: unknown };
  } | undefined;
  const inputTokens = Number(usage?.input_tokens);
  const outputTokens = Number(usage?.output_tokens);
  const cachedTokens = Number(usage?.input_tokens_details?.cached_tokens ?? 0);
  if (![inputTokens, outputTokens, cachedTokens].every(Number.isSafeInteger)
      || inputTokens < 0 || outputTokens < 0 || cachedTokens < 0 || cachedTokens > inputTokens) {
    console.error("[usage/ai] OpenAI response omitted valid token usage; reservation retained:", reservationId);
    return error("The AI provider did not return billable usage details.", 502);
  }

  const uncachedTokens = inputTokens - cachedTokens;
  const providerCostUsd = (
    uncachedTokens * INPUT_USD_PER_MILLION +
    cachedTokens * CACHED_INPUT_USD_PER_MILLION +
    outputTokens * OUTPUT_USD_PER_MILLION
  ) / 1_000_000;
  const amountChargedUsd = chargeUsd(providerCostUsd * (1 + MARGIN));
  const { error: settleError } = await admin.rpc("settle_ai_usage_credits", {
    p_reservation_id: reservationId,
    p_user_id: user.id,
    p_email: user.email,
    p_provider_cost_usd: providerCostUsd,
    p_charge_usd: amountChargedUsd,
    p_model: MODEL,
    p_prompt_tokens: inputTokens,
    p_completion_tokens: outputTokens,
    p_cached_tokens: cachedTokens,
  });
  if (settleError) {
    // Keep the reservation active so a transient ledger failure cannot make
    // already-spent provider usage appear free.
    console.error("[usage/ai] settlement failed; reservation retained:", settleError.message);
    return error("The AI response was generated, but its credit charge could not be saved. Contact support.", 503);
  }

  return NextResponse.json(result, {
    headers: {
      "Cache-Control": "no-store",
      "X-ThreatCrush-Provider-Cost-USD": providerCostUsd.toFixed(9),
      "X-ThreatCrush-Credits-Charged-USD": amountChargedUsd.toFixed(12),
    },
  });
}

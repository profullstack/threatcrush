import { NextRequest } from "next/server";
import { createProfileHandlers } from "@profullstack/profile";
import { getAuthenticatedRequestUser } from "@/lib/api-auth";
import { profileStore } from "@/lib/profile";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET / PUT / PATCH /api/v1/me/profile: the signed-in user's profile fields
// (Bearer access token, like the rest of /api).
const handlers = () =>
  createProfileHandlers({
    store: profileStore(),
    getUser: async (req) => {
      const user = await getAuthenticatedRequestUser(req as NextRequest);
      return user ? { id: user.userId, email: user.email } : null;
    },
  });

// user_profiles.email is the account address (org invites and member lookups
// match on it), so it always follows the account and is never set from here.
async function withoutEmail(req: Request): Promise<Request> {
  const text = await req.text();
  let body: unknown = {};
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      return new Request(req.url, { method: req.method, headers: req.headers, body: text });
    }
  }
  if (body && typeof body === "object") delete (body as Record<string, unknown>).email;
  const headers = new Headers(req.headers);
  headers.set("content-type", "application/json");
  return new Request(req.url, { method: req.method, headers, body: JSON.stringify(body) });
}

export const GET = (req: NextRequest) => handlers().GET(req);
export const PUT = async (req: NextRequest) => handlers().PUT(await withoutEmail(req));
export const PATCH = async (req: NextRequest) => handlers().PATCH(await withoutEmail(req));

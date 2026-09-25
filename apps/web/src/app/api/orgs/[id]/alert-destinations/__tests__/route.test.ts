import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventEmitter } from "node:events";
import { NextRequest } from "next/server";
import { createMemoryTables } from "@/__tests__/helpers/memory-tables";

const mockLookup = vi.fn();
const mockHttpsRequest = vi.fn();
const mockHttpRequest = vi.fn();

vi.mock("dns/promises", () => ({
  default: { lookup: (...args: unknown[]) => mockLookup(...args) },
}));
vi.mock("node:https", () => ({
  default: { request: (...args: unknown[]) => mockHttpsRequest(...args) },
}));
vi.mock("node:http", () => ({
  default: { request: (...args: unknown[]) => mockHttpRequest(...args) },
}));

const ORG = "org-1";
let db = createMemoryTables();

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: {
      getUser: async (token: string) => ({
        data: { user: token === "owner-token" ? { id: "owner-1" } : null },
      }),
    },
    from: (table: string) => db.from(table),
  }),
}));

import { POST as createDestination } from "@/app/api/orgs/[id]/alert-destinations/route";
import {
  PATCH as updateDestination,
  POST as testDestination,
} from "@/app/api/orgs/[id]/alert-destinations/[dest_id]/route";

interface FakeResponseSpec {
  status: number;
  headers?: Record<string, string>;
}

/** Stands in for https.request: hands back the scripted response on end(). */
function scriptRequest(spec: FakeResponseSpec) {
  return (_options: unknown, callback: (res: unknown) => void) => {
    const req = new EventEmitter() as EventEmitter & Record<string, unknown>;
    req.write = vi.fn();
    req.destroy = vi.fn();
    req.end = () => {
      const res = new EventEmitter() as EventEmitter & Record<string, unknown>;
      res.statusCode = spec.status;
      res.headers = spec.headers ?? {};
      res.destroy = vi.fn();
      callback(res);
      queueMicrotask(() => res.emit("end"));
    };
    return req;
  };
}

const PUBLIC_HOST_ADDRESS = "93.184.216.34";

function request(method: string, body?: unknown) {
  return new NextRequest(`http://localhost/api/orgs/${ORG}/alert-destinations`, {
    method,
    headers: { authorization: "Bearer owner-token", "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function create(type: string, config: Record<string, unknown>) {
  return createDestination(request("POST", { name: "hook", type, config }), {
    params: Promise.resolve({ id: ORG }),
  });
}

function sendTest(destId: string) {
  return testDestination(request("POST"), { params: Promise.resolve({ id: ORG, dest_id: destId }) });
}

function insertDestination(type: string, config: Record<string, unknown>): string {
  const id = `dest-${db.tables.alert_destinations.length + 1}`;
  db.tables.alert_destinations.push({ id, organization_id: ORG, name: "hook", type, config, enabled: true });
  return id;
}

const INTERNAL_URLS = [
  "https://127.0.0.1:54321/rest/v1/",
  "https://169.254.169.254/latest/meta-data/",
  "https://[::1]/",
  "https://10.0.0.5/hook",
  "https://internal.example/hook", // resolves to a private address
];

beforeEach(() => {
  vi.clearAllMocks();
  db = createMemoryTables({
    organization_members: [{ org_id: ORG, user_id: "owner-1", role: "owner" }],
    alert_destinations: [],
  });
  mockLookup.mockImplementation(async (host: string) =>
    host === "internal.example"
      ? [{ address: "10.1.2.3", family: 4 }]
      : [{ address: PUBLIC_HOST_ADDRESS, family: 4 }],
  );
});

describe("creating an alert destination", () => {
  it.each([...INTERNAL_URLS, "http://hooks.example.com/hook", "not a url"])(
    "rejects %s without saving it",
    async (url) => {
      const res = await create("webhook", { url });

      expect(res.status).toBe(400);
      expect(db.tables.alert_destinations).toHaveLength(0);
    },
  );

  it("checks the Slack and Discord webhook_url field too", async () => {
    for (const type of ["slack", "discord"]) {
      const res = await create(type, { webhook_url: "https://169.254.169.254/" });
      expect(res.status, type).toBe(400);
    }
    expect(db.tables.alert_destinations).toHaveLength(0);
  });

  it("requires a URL for types that deliver to one", async () => {
    const res = await create("webhook", {});

    expect(res.status).toBe(400);
    expect((await res.json()).error).toContain("config.url");
  });

  it("saves an https URL on a public host", async () => {
    const res = await create("webhook", { url: "https://hooks.example.com/hook" });

    expect(res.status).toBe(201);
    expect(db.tables.alert_destinations).toHaveLength(1);
  });

  it("does not require a URL for types that do not deliver to one", async () => {
    const res = await create("pagerduty", { routing_key: "abc" });

    expect(res.status).toBe(201);
  });
});

describe("updating an alert destination", () => {
  it("rejects a config pointing at an internal address and keeps the old one", async () => {
    const id = insertDestination("webhook", { url: "https://hooks.example.com/hook" });

    const res = await updateDestination(
      request("PATCH", { config: { url: "https://169.254.169.254/" } }),
      { params: Promise.resolve({ id: ORG, dest_id: id }) },
    );

    expect(res.status).toBe(400);
    expect(db.tables.alert_destinations[0].config).toEqual({ url: "https://hooks.example.com/hook" });
  });
});

describe("sending a test alert", () => {
  it.each([...INTERNAL_URLS, "http://127.0.0.1:54321/rest/v1/", "http://hooks.example.com/hook"])(
    "refuses a stored %s without making a request",
    async (url) => {
      const id = insertDestination("webhook", { url });

      const res = await sendTest(id);

      expect(res.status).toBe(400);
      expect((await res.json()).success).toBeUndefined();
      expect(mockHttpsRequest).not.toHaveBeenCalled();
      expect(mockHttpRequest).not.toHaveBeenCalled();
    },
  );

  it("posts to a public https URL, connecting to the address it validated", async () => {
    mockHttpsRequest.mockImplementation(scriptRequest({ status: 204 }));
    const id = insertDestination("slack", { webhook_url: "https://hooks.example.com/services/x" });

    const res = await sendTest(id);

    expect(res.status).toBe(200);
    expect((await res.json()).success).toBe(true);
    expect(mockHttpsRequest).toHaveBeenCalledTimes(1);
    const options = mockHttpsRequest.mock.calls[0][0] as {
      hostname: string;
      method: string;
      lookup: (host: string, opts: object, cb: (err: unknown, address: string) => void) => void;
    };
    expect(options).toMatchObject({ hostname: "hooks.example.com", method: "POST" });
    let pinned = "";
    options.lookup("hooks.example.com", {}, (_err, address) => (pinned = address));
    expect(pinned).toBe(PUBLIC_HOST_ADDRESS);
  });

  it("reports a non-2xx answer as a failure with its status", async () => {
    mockHttpsRequest.mockImplementation(scriptRequest({ status: 500 }));
    const id = insertDestination("webhook", { url: "https://hooks.example.com/hook" });

    const res = await sendTest(id);
    const body = await res.json();

    expect(res.status).toBe(502);
    expect(body.success).toBeUndefined();
    expect(body.error).toContain("500");
  });

  it("does not follow a redirect, even to a public host", async () => {
    mockHttpsRequest.mockImplementation(
      scriptRequest({ status: 302, headers: { location: "https://elsewhere.example.com/" } }),
    );
    const id = insertDestination("webhook", { url: "https://hooks.example.com/hook" });

    const res = await sendTest(id);

    expect(res.status).toBe(502);
    expect((await res.json()).error).toContain("302");
    expect(mockHttpsRequest).toHaveBeenCalledTimes(1);
  });

  it("does not echo connection error details", async () => {
    mockHttpsRequest.mockImplementation(() => {
      const req = new EventEmitter() as EventEmitter & Record<string, unknown>;
      req.write = vi.fn();
      req.destroy = vi.fn();
      req.end = () => req.emit("error", new Error("connect ECONNREFUSED 93.184.216.34:443"));
      return req;
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    const id = insertDestination("webhook", { url: "https://hooks.example.com/hook" });

    const res = await sendTest(id);
    const body = await res.json();

    expect(res.status).toBe(502);
    expect(body.error).not.toMatch(/ECONNREFUSED|93\.184/);
  });
});

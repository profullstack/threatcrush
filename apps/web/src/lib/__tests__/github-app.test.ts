import { createPublicKey, createVerify, generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  createAppJwt,
  createInstallationToken,
  fetchBlobText,
  listInstallationRepos,
  listTree,
  normalizePrivateKey,
  readAppCredentials,
  GitHubApiError,
} from "../github-app";

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs1", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("createAppJwt", () => {
  it("produces a JWT that verifies against the matching public key", () => {
    const token = createAppJwt("12345", privateKey, 1_700_000_000);
    const [header, payload, signature] = token.split(".");

    const verifier = createVerify("RSA-SHA256");
    verifier.update(`${header}.${payload}`);
    verifier.end();

    const publicKey = createPublicKey(privateKey);
    expect(verifier.verify(publicKey, Buffer.from(signature, "base64url"))).toBe(true);
  });

  it("backdates iat and keeps exp inside GitHub's 10 minute ceiling", () => {
    const now = 1_700_000_000;
    const token = createAppJwt("12345", privateKey, now);
    const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));

    expect(claims.iss).toBe("12345");
    expect(claims.iat).toBe(now - 60);
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(600);
  });
});

describe("normalizePrivateKey", () => {
  it("repairs a key pasted with literal backslash-n", () => {
    const mangled = privateKey.replace(/\n/g, "\\n");
    expect(normalizePrivateKey(mangled)).toBe(privateKey.trim());
  });

  it("leaves a correctly formatted key alone", () => {
    expect(normalizePrivateKey(privateKey)).toBe(privateKey.trim());
  });

  it("signs successfully with a backslash-n mangled key", () => {
    const mangled = privateKey.replace(/\n/g, "\\n");
    expect(() => createAppJwt("1", mangled, 1_700_000_000)).not.toThrow();
  });

  it("accepts base64 of the whole PEM, which is what survives a vault round-trip", () => {
    const b64 = Buffer.from(privateKey, "utf8").toString("base64");
    expect(b64).not.toContain("\n");
    expect(b64).not.toContain("\\");
    expect(normalizePrivateKey(b64)).toBe(privateKey.trim());
    expect(() => createAppJwt("1", b64, 1_700_000_000)).not.toThrow();
  });

  it("produces the same signature from PEM and from its base64", () => {
    const b64 = Buffer.from(privateKey, "utf8").toString("base64");
    expect(createAppJwt("1", b64, 1_700_000_000)).toBe(
      createAppJwt("1", privateKey, 1_700_000_000)
    );
  });

  it("does not pass off undecodable junk as a key", () => {
    // Valid base64 that decodes to something that is not a PEM must not be
    // silently accepted — it has to reach sign() and fail there.
    const notAKey = Buffer.from("hello world", "utf8").toString("base64");
    expect(() => createAppJwt("1", notAKey, 1_700_000_000)).toThrow();
  });
});

describe("readAppCredentials", () => {
  it("returns null when either half is missing, rather than throwing", () => {
    expect(readAppCredentials({ GITHUB_APP_ID: "1" } as unknown as NodeJS.ProcessEnv)).toBeNull();
    expect(readAppCredentials({ GITHUB_APP_PRIVATE_KEY: "k" } as unknown as NodeJS.ProcessEnv)).toBeNull();
    expect(readAppCredentials({} as unknown as NodeJS.ProcessEnv)).toBeNull();
  });

  it("returns both when set", () => {
    const creds = readAppCredentials({
      GITHUB_APP_ID: " 42 ",
      GITHUB_APP_PRIVATE_KEY: " key ",
    } as unknown as NodeJS.ProcessEnv);
    expect(creds).toEqual({ appId: "42", privateKey: "key" });
  });
});

describe("createInstallationToken", () => {
  it("posts to the installation endpoint with a Bearer JWT", async () => {
    const fetchImpl = vi.fn(async (_url: string, _init?: RequestInit) =>
      jsonResponse({ token: "ghs_x", expires_at: "2026-01-01T00:00:00Z", permissions: { contents: "read" } })
    );

    const result = await createInstallationToken("jwt-here", 155501023, fetchImpl);

    expect(result.token).toBe("ghs_x");
    expect(result.permissions).toEqual({ contents: "read" });
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toContain("/app/installations/155501023/access_tokens");
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>).authorization).toBe("Bearer jwt-here");
  });

  it("throws a GitHubApiError carrying the status on failure", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ message: "Bad credentials" }, 401));
    await expect(createInstallationToken("jwt", 1, fetchImpl)).rejects.toBeInstanceOf(
      GitHubApiError
    );
  });
});

describe("listInstallationRepos", () => {
  it("stops paging as soon as a short page arrives", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        repositories: [
          { id: 1, name: "a", full_name: "org/a", private: false, default_branch: "main" },
        ],
      })
    );

    const repos = await listInstallationRepos("tok", fetchImpl);

    expect(repos).toEqual([
      { id: 1, name: "a", fullName: "org/a", private: false, defaultBranch: "main" },
    ]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("defaults a missing default_branch rather than producing an unusable ref", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({ repositories: [{ id: 2, name: "b", full_name: "org/b", private: true }] })
    );
    const repos = await listInstallationRepos("tok", fetchImpl);
    expect(repos[0].defaultBranch).toBe("main");
  });
});

describe("listTree", () => {
  it("keeps only blobs and surfaces GitHub's truncation flag", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        truncated: true,
        tree: [
          { path: "src", type: "tree", sha: "t1" },
          { path: "src/a.ts", type: "blob", sha: "b1", size: 10 },
          { path: "b.ts", type: "blob", sha: "b2" },
        ],
      })
    );

    const { entries, truncated } = await listTree("tok", "org/a", "main", fetchImpl);

    expect(truncated).toBe(true);
    expect(entries).toEqual([
      { path: "src/a.ts", sha: "b1", size: 10 },
      { path: "b.ts", sha: "b2", size: 0 },
    ]);
  });
});

describe("fetchBlobText", () => {
  it("decodes base64 content", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({ content: Buffer.from("hello", "utf8").toString("base64"), encoding: "base64" })
    );
    expect(await fetchBlobText("tok", "org/a", "sha", fetchImpl)).toBe("hello");
  });

  it("returns null for binary content rather than scanning noise", async () => {
    const binary = Buffer.from([0x00, 0x01, 0x02]).toString("base64");
    const fetchImpl = vi.fn(async () => jsonResponse({ content: binary, encoding: "base64" }));
    expect(await fetchBlobText("tok", "org/a", "sha", fetchImpl)).toBeNull();
  });

  it("returns null on a failed fetch instead of throwing mid-scan", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ message: "Not Found" }, 404));
    expect(await fetchBlobText("tok", "org/a", "sha", fetchImpl)).toBeNull();
  });
});

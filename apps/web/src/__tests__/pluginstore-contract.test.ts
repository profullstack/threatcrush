import { describe, expect, it } from "vitest";
import {
  normalizeConfigSchema,
  splitConfigSchema,
  type PluginInstallPayload,
} from "@profullstack/pluginstore";

describe("pluginstore contracts", () => {
  it("normalizes public config schema without accepting malformed fields", () => {
    const schema = normalizeConfigSchema([
      {
        key: "AI_GATEWAY_API_KEY",
        label: "Vercel AI Gateway API key",
        type: "secret",
        scope: "global",
        required: true,
        placeholder: "vck_...",
      },
      {
        key: "DEEPSEC_SANDBOX_ENABLED",
        label: "Use Vercel Sandbox",
        type: "boolean",
        default: false,
      },
      { key: "", label: "Bad", type: "secret" },
      { key: "BAD_TYPE", label: "Bad", type: "password" },
      null,
    ]);

    expect(schema).toEqual([
      expect.objectContaining({
        key: "AI_GATEWAY_API_KEY",
        label: "Vercel AI Gateway API key",
        type: "secret",
        scope: "global",
        required: true,
        placeholder: "vck_...",
      }),
      expect.objectContaining({
        key: "DEEPSEC_SANDBOX_ENABLED",
        type: "boolean",
        scope: "module",
        default: false,
      }),
    ]);
  });

  it("splits secret/plain and global/module fields for settings UIs", () => {
    const fields = normalizeConfigSchema([
      { key: "AI_GATEWAY_API_KEY", label: "Gateway key", type: "secret", scope: "global" },
      { key: "DEEPSEC_AGENT", label: "Agent", type: "string", scope: "module" },
    ]);

    const split = splitConfigSchema(fields);

    expect(split.secrets.map((field) => field.key)).toEqual(["AI_GATEWAY_API_KEY"]);
    expect(split.plain.map((field) => field.key)).toEqual(["DEEPSEC_AGENT"]);
    expect(split.global.map((field) => field.key)).toEqual(["AI_GATEWAY_API_KEY"]);
    expect(split.module.map((field) => field.key)).toEqual(["DEEPSEC_AGENT"]);
  });

  it("documents the DeepSec install payload shape", () => {
    const payload: PluginInstallPayload = {
      name: "deepsec",
      slug: "deepsec",
      version: "2.0.10",
      downloads: 0,
      license: "Apache-2.0",
      min_version: ">=0.2.0",
      os_support: ["linux", "darwin"],
      config_notes: "AI_GATEWAY_API_KEY is a per-user/global secret.",
      config_schema: normalizeConfigSchema([
        {
          key: "AI_GATEWAY_API_KEY",
          label: "Vercel AI Gateway API key",
          type: "secret",
          scope: "global",
          required: true,
        },
      ]),
      install: {
        npm_package: "deepsec",
        git_url: "https://github.com/vercel-labs/deepsec",
        tarball_url: null,
      },
    };

    expect(payload.install.npm_package).toBe("deepsec");
    expect(payload.config_schema[0]).toEqual(
      expect.objectContaining({
        key: "AI_GATEWAY_API_KEY",
        type: "secret",
        scope: "global",
      }),
    );
  });
});

import type { NextConfig } from "next";
import { join } from "node:path";

const securityHeaders = [
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "SAMEORIGIN" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  },
  { key: "X-DNS-Prefetch-Control", value: "on" },
];

const nextConfig: NextConfig = {
  output: "standalone",
  // `@threatcrush/scan` is an internal package: its `exports` resolve to
  // TypeScript source rather than a build output, so that the release workflow
  // — which builds the CLI alone — cannot publish a CLI referencing an
  // unbuilt dependency. Next.js does not transpile workspace sources by
  // default, so it is named here.
  transpilePackages: ["@threatcrush/scan"],
  // Tell Next.js where the monorepo root is so standalone-mode tracing picks up
  // only the files that apps/web actually imports.
  outputFileTracingRoot: join(__dirname, "..", ".."),
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;

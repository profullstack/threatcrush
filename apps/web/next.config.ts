import type { NextConfig } from "next";
import { join } from "node:path";

const nextConfig: NextConfig = {
  output: "standalone",
  // Tell Next.js where the monorepo root is so standalone-mode tracing picks up
  // only the files that apps/web actually imports.
  outputFileTracingRoot: join(__dirname, "..", ".."),
};

export default nextConfig;

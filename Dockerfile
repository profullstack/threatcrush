# threatcrush.com web app, run on Bun.
#
# Only the web container's runtime is Bun. pnpm stays the repo's package manager
# because the same workspace builds and publishes the threatcrush CLI and the
# desktop app; the install and the Next build below are unchanged (Node).
# Only the standalone server runs under Bun.
# dev2 builds this file (/home/anthony/www/threatcrush.com) and passes three
# NEXT_PUBLIC_* build args. The Node image never declared them, so its build
# never saw them; they stay undeclared so this build is identical. Port 3000,
# env and the health path are unchanged.
FROM node:22-slim AS builder

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

# git needed for postinstall hook
# git for the postinstall hook; python3/make/g++ so better-sqlite3 can build when no prebuilt binary matches
RUN apt-get update && apt-get install -y --no-install-recommends git python3 make g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace root + per-package manifests first for better layer caching.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json apps/web/
COPY apps/cli/package.json apps/cli/
COPY apps/desktop/package.json apps/desktop/
COPY apps/mobile/package.json apps/mobile/
COPY apps/extension/package.json apps/extension/
COPY apps/sdk/package.json apps/sdk/

RUN pnpm install --frozen-lockfile

# Now bring in the rest of the source.
COPY . .

# Build the web app only for the container image. The build stays on Node:
# under `bun --bun next build`, collecting /blog/[slug] fails because Bun cannot
# resolve jsdom's `require('../data/patch.json')` (isomorphic-dompurify) from
# Turbopack's hashed external. The standalone output then runs on Bun.
RUN pnpm --filter @profullstack/threatcrush-web build

FROM oven/bun:1.4.0-slim AS runner

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

WORKDIR /app

COPY --from=builder --chown=bun:bun /app/apps/web/.next/standalone ./
COPY --from=builder --chown=bun:bun /app/apps/web/public ./apps/web/public
COPY --from=builder --chown=bun:bun /app/apps/web/.next/static ./apps/web/.next/static

# The oven/bun image ships a non-root `bun` user.
USER bun

EXPOSE 3000

# /api/health answers 503 when the database is unreachable, which marks the
# container unhealthy instead of reporting a web process that cannot serve.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["bun", "-e", "fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/api/health').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]

CMD ["bun", "apps/web/server.js"]

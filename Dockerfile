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

# Build the web app only for the container image.
RUN pnpm --filter @profullstack/threatcrush-web build

FROM node:22-slim AS runner

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0
ENV PORT=3000
ENV NODE_OPTIONS=--max-old-space-size=1024

WORKDIR /app

COPY --from=builder --chown=node:node /app/apps/web/.next/standalone ./
COPY --from=builder --chown=node:node /app/apps/web/public ./apps/web/public
COPY --from=builder --chown=node:node /app/apps/web/.next/static ./apps/web/.next/static

USER node

EXPOSE 3000

# The slim image has neither curl nor wget, so the probe uses Node's fetch.
# /api/health answers 503 when the database is unreachable, which marks the
# container unhealthy instead of reporting a web process that cannot serve.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/api/health').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]

CMD ["node", "apps/web/server.js"]

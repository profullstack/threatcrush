FROM node:22-slim

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

# git needed for postinstall hook
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

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

# Next.js standalone output doesn't include static assets — copy them in.
RUN cp -r apps/web/public apps/web/.next/standalone/apps/web/public
RUN cp -r apps/web/.next/static apps/web/.next/standalone/apps/web/.next/static

ENV NODE_ENV=production
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

EXPOSE 3000

CMD ["node", "apps/web/.next/standalone/apps/web/server.js"]

FROM node:22-slim

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

# Install git for postinstall hook
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all package manifests first for better caching
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY cli/package.json cli/
COPY desktop/package.json desktop/
COPY mobile/package.json mobile/
COPY extension/package.json extension/

# Install all dependencies
RUN pnpm install --frozen-lockfile

# Copy source code
COPY . .

# Build the application
RUN pnpm build

ENV NODE_ENV=production
ENV HOSTNAME=0.0.0.0

# Use Railway's PORT env var, default to 3000
ENV PORT=3000

EXPOSE ${PORT}

CMD ["node", ".next/standalone/server.js"]

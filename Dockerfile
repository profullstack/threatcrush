FROM node:22-slim

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

# Install git for postinstall hook
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY cli/package.json cli/
COPY desktop/package.json desktop/
COPY mobile/package.json mobile/
COPY extension/package.json extension/

RUN pnpm install --frozen-lockfile

COPY . .

RUN pnpm build

# Next.js standalone output doesn't include static assets — copy them in
RUN cp -r .next/static .next/standalone/.next/static

ENV NODE_ENV=production
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

EXPOSE 3000

CMD ["node", ".next/standalone/server.js"]

// Suppress noisy errors from bots POSTing stale Server Action IDs against the
// new bundle. Next.js logs a fat stack on every hit; under bot traffic this is
// thousands of stacks/min and correlates with runaway memory growth.
const NOISE = [
  "Failed to find Server Action",
  "Expected RSC response, got text/plain",
];

const origError = console.error.bind(console);
console.error = (...args: unknown[]): void => {
  const msg = args
    .map((a) => (a instanceof Error ? `${a.message}\n${a.stack ?? ""}` : String(a)))
    .join(" ");
  if (NOISE.some((s) => msg.includes(s))) return;
  origError(...args);
};

export async function register(): Promise<void> {}

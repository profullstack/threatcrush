// Runs once in the browser on first navigation. No-op without a DSN.
import { initSentry } from "./src/lib/sentry";

initSentry("client");

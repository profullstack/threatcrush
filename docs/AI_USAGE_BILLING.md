# Metered AI usage

ThreatCrush credits can be used through the authenticated OpenAI Responses API
proxy at `/api/usage/v1/responses`. Successful requests are billed from the
provider's reported token usage. The customer charge is provider cost multiplied
by `1.20` (a flat 20% margin). Failed provider requests release their credit
reservation; the maximum possible charge is reserved before the provider call.

The proxy currently accepts text input for `gpt-5.6-luna`, up to 64 KiB per
request and 4,096 output tokens. The metered token prices are $0.20 per million
uncached input tokens, $0.02 per million cached input tokens, and $1.20 per
million output tokens. Pricing is pinned in the server code and must be updated
if OpenAI changes its rates. It accepts a ThreatCrush Supabase access token in
the `Authorization: Bearer` header. The OpenAI key stays on the ThreatCrush
server.

Example with the OpenAI Node SDK:

```ts
import OpenAI from "openai";

const ai = new OpenAI({
  apiKey: threatCrushAccessToken,
  baseURL: "https://threatcrush.com/api/usage/v1",
});

const response = await ai.responses.create({
  model: "gpt-5.6-luna",
  input: "Summarize this finding.",
});
```

Only requests sent through this proxy are deducted from ThreatCrush credits.
Other providers and direct module calls are not included in its usage ledger.
The proxy uses explicit-only prompt caching without cache breakpoints so its
token usage can be priced without unreported cache-write fees.

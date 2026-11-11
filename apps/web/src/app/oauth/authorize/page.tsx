import type { Metadata } from "next";
import AuthorizeClient from "./authorize-client";

export const metadata: Metadata = {
  title: "Connect an app — ThreatCrush",
  description: "Allow an AI app (ChatGPT, Claude, …) to use your ThreatCrush account through the ThreatCrush MCP server.",
  robots: { index: false, follow: false },
};

export default function OAuthAuthorizePage() {
  return <AuthorizeClient />;
}

import type { Metadata } from "next";
import CliLoginClient from "./cli-login-client";

export const metadata: Metadata = {
  title: "Approve CLI Login — ThreatCrush",
  description: "Approve a threatcrush CLI login from a server or terminal.",
  robots: { index: false, follow: false },
};

export default function CliLoginPage() {
  return <CliLoginClient />;
}

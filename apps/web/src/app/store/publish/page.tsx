import type { Metadata } from "next";
import PublishClient from "./publish-client";

export const metadata: Metadata = {
  title: "Publish Module — ThreatCrush",
  description: "Publish a ThreatCrush module to the marketplace.",
};

export default function PublishPage() {
  return <PublishClient />;
}

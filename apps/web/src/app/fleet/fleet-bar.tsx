"use client";

import { useEffect } from "react";

declare module "react" {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace JSX {
    interface IntrinsicElements {
      "fleet-bar": React.DetailedHTMLProps<React.HTMLAttributes<HTMLElement>, HTMLElement> & {
        endpoint?: string;
        refresh?: string;
        theme?: "light" | "dark";
      };
    }
  }
}

/** Registers and mounts the shared @profullstack/fleetbar panel, unmodified. */
export function FleetBar() {
  useEffect(() => {
    void import("@profullstack/fleetbar");
  }, []);
  // ThreatCrush has one (dark) theme; pin the panel to it whatever the OS prefers.
  return <fleet-bar endpoint="/api/fleetbar" theme="dark" />;
}

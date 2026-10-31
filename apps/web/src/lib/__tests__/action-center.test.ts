import { describe, expect, it } from "vitest";
import { actionCenterNextStep, filterActionCenterDetections } from "../action-center";

const servers = [
  { id: "srv-a", fleet_id: "fleet-a" },
  { id: "srv-b", fleet_id: "fleet-b" },
];
const detections = [
  { id: "d1", server_id: "srv-a", severity: "critical", source_ip: "203.0.113.20" },
  { id: "d2", server_id: "srv-a", severity: "medium", source_ip: "198.51.100.8" },
  { id: "d3", server_id: "srv-b", severity: "high", source_ip: null },
];

describe("Action Center filters", () => {
  it("combines severity, fleet, server, and IP filters", () => {
    expect(filterActionCenterDetections(detections, servers, {
      severity: "critical", fleetId: "fleet-a", serverId: "srv-a", ipQuery: "203.0.113",
    }).map((d) => d.id)).toEqual(["d1"]);
  });

  it("ignores letter case and whitespace in IP searches", () => {
    expect(filterActionCenterDetections(detections, servers, {
      severity: "all", fleetId: "all", serverId: "all", ipQuery: "  198.51.100.8  ",
    }).map((d) => d.id)).toEqual(["d2"]);
  });

  it("returns severity-specific review guidance", () => {
    expect(actionCenterNextStep("critical")).toContain("Investigate the host now");
    expect(actionCenterNextStep("high")).toContain("block it if");
    expect(actionCenterNextStep("info")).toBe("Review and resolve if expected.");
  });
});

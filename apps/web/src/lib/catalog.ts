import "server-only";
import { moduleSalesEnabled, PAID_MODULES } from "./paid-modules";
import { REPUTATION_PLANS, reputationProEnabled } from "./reputation";

/**
 * Everything threatcrush.com sells, in one place, for /pricing and the
 * checkout route. Subscriptions keep their own tables and kill switches
 * (REPUTATION_PRO_ENABLED, <MODULE>_SALES_ENABLED); the scan is a one-off
 * booking in scan_orders, on unless SCAN_SALES_ENABLED=false.
 */

export type ProductKind = "reputation" | "module" | "scan";

export interface CatalogPlan {
  id: string;
  name: string;
  months: number | null;
  amount_usd: number;
}

export interface CatalogProduct {
  slug: string;
  kind: ProductKind;
  name: string;
  url: string;
  enabled: boolean;
  plans: CatalogPlan[];
}

export const SCAN_PRODUCT_SLUG = "scan";
export const SCAN_PRICE_USD = 400;

export function scanSalesEnabled(): boolean {
  const name = "SCAN_SALES_ENABLED";
  return process.env[name] !== "false";
}

export function catalog(): CatalogProduct[] {
  return [
    {
      slug: "reputation-pro",
      kind: "reputation",
      name: "Reputation Pro",
      url: "/reputation",
      enabled: reputationProEnabled(),
      plans: REPUTATION_PLANS.map((p) => ({ ...p })),
    },
    ...Object.values(PAID_MODULES).map((m) => ({
      slug: m.slug,
      kind: "module" as const,
      name: m.name,
      url: `/${m.slug}`,
      enabled: moduleSalesEnabled(m),
      plans: m.plans.map((p) => ({ ...p })),
    })),
    {
      slug: SCAN_PRODUCT_SLUG,
      kind: "scan",
      name: "Security Scan, human-reviewed",
      url: "/hire",
      enabled: scanSalesEnabled(),
      plans: [{ id: "scan", name: "Security Scan, human-reviewed", months: null, amount_usd: SCAN_PRICE_USD }],
    },
  ];
}

export function findProduct(slug: unknown): CatalogProduct | null {
  return catalog().find((p) => p.slug === slug) ?? null;
}

export function findPlan(product: CatalogProduct, id: unknown): CatalogPlan | null {
  if (id === undefined || id === null || id === "") return product.plans[0] ?? null;
  return product.plans.find((p) => p.id === id) ?? null;
}

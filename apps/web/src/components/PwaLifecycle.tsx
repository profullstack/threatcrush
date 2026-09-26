"use client";

import { useEffect, useRef } from "react";
import { useAuth } from "@/lib/auth-context";
import {
  clearThreatCrushServiceWorkerCaches,
  registerThreatCrushServiceWorker,
  setThreatCrushServiceWorkerCacheScope,
  unsubscribeBrowserPush,
} from "@/lib/pwa-client";

export default function PwaLifecycle() {
  const { currentOrgId, loading, signedIn } = useAuth();
  const previousOrgId = useRef<string | null | undefined>(undefined);
  const previousSignedIn = useRef<boolean | undefined>(undefined);

  useEffect(() => {
    void registerThreatCrushServiceWorker();
  }, []);

  useEffect(() => {
    if (loading) return;

    const orgChanged =
      previousOrgId.current !== undefined && previousOrgId.current !== currentOrgId;
    const signedOut = previousSignedIn.current === true && !signedIn;

    if (signedOut) {
      void clearThreatCrushServiceWorkerCaches("logout");
      // A signed-out browser must stop showing the org's alerts. The session is
      // gone, so only the push service learns about it; the server drops the
      // row when its next push comes back 410.
      unsubscribeBrowserPush().catch(() => {});
    } else if (orgChanged) {
      void clearThreatCrushServiceWorkerCaches("org-switch");
    }

    if (signedIn) {
      void setThreatCrushServiceWorkerCacheScope(currentOrgId || "no-org");
    }

    previousOrgId.current = currentOrgId;
    previousSignedIn.current = signedIn;
  }, [currentOrgId, loading, signedIn]);

  return null;
}

"use client";

import { useEffect, useRef } from "react";
import { useAuth } from "@/lib/auth-context";
import {
  clearThreatCrushServiceWorkerCaches,
  registerThreatCrushServiceWorker,
  setThreatCrushServiceWorkerCacheScope,
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

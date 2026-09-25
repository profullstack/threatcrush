import { create } from 'zustand';
import {
  api,
  type Detection,
  type Organization,
  type PropertyRun,
  type Remediation,
  type Server,
} from '../lib/api';
import { useAuthStore } from './auth';

export const DETECTIONS_PAGE = 50;
const REMEDIATIONS_PAGE = 50;
const RUNS_PAGE = 25;

type LoadStatus = 'idle' | 'loading' | 'ready' | 'error';

interface OrgData {
  servers: Server[];
  detections: Detection[];
  detectionsTotal: number;
  remediations: Remediation[];
  runs: PropertyRun[];
  runsTotal: number;
}

const EMPTY_ORG_DATA: OrgData = {
  servers: [],
  detections: [],
  detectionsTotal: 0,
  remediations: [],
  runs: [],
  runsTotal: 0,
};

interface WorkspaceState extends OrgData {
  status: LoadStatus;
  error: string | null;
  orgs: Organization[];
  currentOrgId: string | null;
  loadingMore: boolean;

  /** Fetch orgs, pick the current one, then load its data. */
  load: () => Promise<void>;
  /** Re-fetch the current org's data (pull to refresh). */
  refresh: () => Promise<void>;
  selectOrg: (orgId: string) => Promise<void>;
  loadMoreDetections: () => Promise<void>;
  reset: () => void;
}

const message = (err: unknown) => (err instanceof Error ? err.message : 'Something went wrong.');

const initial = {
  ...EMPTY_ORG_DATA,
  status: 'idle' as LoadStatus,
  error: null,
  orgs: [],
  currentOrgId: null,
  loadingMore: false,
};

export const useWorkspaceStore = create<WorkspaceState>((set, get) => {
  const withSession = <T,>(call: (token: string) => Promise<T>) =>
    useAuthStore.getState().withSession(call);

  const loadOrgData = async (orgId: string) => {
    const [servers, detections, remediations, runs] = await withSession((token) =>
      Promise.all([
        api.listServers(token, orgId),
        api.listDetections(token, orgId, DETECTIONS_PAGE),
        api.listRemediations(token, orgId, REMEDIATIONS_PAGE),
        api.listRuns(token, orgId, RUNS_PAGE),
      ]),
    );
    // The user may have switched orgs while this was in flight.
    if (get().currentOrgId !== orgId) return;
    set({
      servers,
      detections: detections.detections,
      detectionsTotal: detections.total,
      remediations: remediations.remediations,
      runs: runs.runs,
      runsTotal: runs.total,
      status: 'ready',
      error: null,
    });
  };

  const run = async (task: () => Promise<void>) => {
    try {
      await task();
    } catch (err) {
      set({ status: 'error', error: message(err) });
    }
  };

  return {
    ...initial,

    load: () =>
      run(async () => {
        set({ status: 'loading', error: null });
        const [orgs, preferred] = await withSession((token) =>
          Promise.all([api.listOrgs(token), api.currentOrgId(token)]),
        );
        const current =
          orgs.find((o) => o.id === get().currentOrgId) ??
          orgs.find((o) => o.id === preferred) ??
          orgs[0] ??
          null;

        set({ orgs, currentOrgId: current?.id ?? null });
        if (!current) {
          set({ ...EMPTY_ORG_DATA, status: 'ready' });
          return;
        }
        await loadOrgData(current.id);
      }),

    refresh: () =>
      run(async () => {
        const orgId = get().currentOrgId;
        if (!orgId) return get().load();
        set({ status: 'loading', error: null });
        await loadOrgData(orgId);
      }),

    selectOrg: (orgId) =>
      run(async () => {
        if (orgId === get().currentOrgId) return;
        set({ ...EMPTY_ORG_DATA, currentOrgId: orgId, status: 'loading', error: null });
        // Same "current org" the web dashboard uses; losing this write only
        // means the next launch opens the previous org.
        withSession((token) => api.setCurrentOrg(token, orgId)).catch(() => undefined);
        await loadOrgData(orgId);
      }),

    loadMoreDetections: async () => {
      const { currentOrgId, detections, detectionsTotal, loadingMore } = get();
      if (!currentOrgId || loadingMore || detections.length >= detectionsTotal) return;
      set({ loadingMore: true });
      try {
        const next = await withSession((token) =>
          api.listDetections(token, currentOrgId, DETECTIONS_PAGE, detections.length),
        );
        if (get().currentOrgId !== currentOrgId) return;
        const seen = new Set(get().detections.map((d) => d.id));
        set({
          detections: [...get().detections, ...next.detections.filter((d) => !seen.has(d.id))],
          detectionsTotal: next.total,
        });
      } catch (err) {
        set({ error: message(err) });
      } finally {
        set({ loadingMore: false });
      }
    },

    reset: () => set(initial),
  };
});

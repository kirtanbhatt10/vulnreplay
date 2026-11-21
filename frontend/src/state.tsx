import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, tokenStore, type Project, type User } from './api';

interface Session {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  can: (role: 'analyst' | 'admin') => boolean;
  projects: Project[];
  project: Project | null;
  selectProject: (id: string) => void;
  reloadProjects: () => Promise<void>;
}

const Ctx = createContext<Session | null>(null);
const RANK = { viewer: 0, analyst: 1, admin: 2 } as const;
const PROJECT_KEY = 'vulnreplay.project';

export function SessionProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState<string | null>(() => localStorageSafeGet(PROJECT_KEY));

  const reloadProjects = useCallback(async () => {
    const list = await api.projects();
    setProjects(list);
    setProjectId((cur) => (cur && list.some((p) => p.id === cur) ? cur : list[0]?.id ?? null));
  }, []);

  useEffect(() => {
    if (!tokenStore.get()) { setLoading(false); return; }
    api.me().then(setUser).catch(() => tokenStore.clear()).finally(() => setLoading(false));
  }, []);

  useEffect(() => { if (user) reloadProjects().catch(() => undefined); }, [user, reloadProjects]);

  const value: Session = {
    user,
    loading,
    login: async (email, password) => {
      const res = await api.login(email, password);
      tokenStore.set(res.access_token);
      setUser(res.user);
    },
    logout: () => { tokenStore.clear(); setUser(null); setProjects([]); },
    can: (role) => (user ? RANK[user.role] >= RANK[role] : false),
    projects,
    project: projects.find((p) => p.id === projectId) ?? null,
    selectProject: (id) => { setProjectId(id); localStorageSafeSet(PROJECT_KEY, id); },
    reloadProjects,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

function localStorageSafeGet(key: string): string | null {
  try { return localStorage.getItem(key); } catch { return null; }
}
function localStorageSafeSet(key: string, value: string) {
  try { localStorage.setItem(key, value); } catch { /* storage unavailable */ }
}

export function useSession(): Session {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useSession outside SessionProvider');
  return ctx;
}

/** Load data with loading/error state; re-runs when deps change. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    fn().then((d) => { if (alive) setData(d); })
      .catch((e: unknown) => { if (alive) setError(e instanceof Error ? e.message : String(e)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, loading, reload: () => setTick((t) => t + 1), setData };
}

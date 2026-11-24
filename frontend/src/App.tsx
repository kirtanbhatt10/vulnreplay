import { lazy, Suspense } from 'react';
import { NavLink, Navigate, Route, Routes } from 'react-router-dom';
import { Loading } from './components/ui';
import Login from './pages/Login';
import { useSession } from './state';

// Pages are code-split so the initial bundle stays small; React Flow only loads with the pages that use it.
const CiCd = lazy(() => import('./pages/CiCd'));
const Comparison = lazy(() => import('./pages/Comparison'));
const EvidencePage = lazy(() => import('./pages/Evidence'));
const Execution = lazy(() => import('./pages/Execution'));
const Findings = lazy(() => import('./pages/Findings'));
const Generator = lazy(() => import('./pages/Generator'));
const Library = lazy(() => import('./pages/Library'));
const Overview = lazy(() => import('./pages/Overview'));
const Projects = lazy(() => import('./pages/Projects'));
const Scenarios = lazy(() => import('./pages/Scenarios'));
const SettingsPage = lazy(() => import('./pages/Settings'));

export const NAV = [
  { to: '/', label: 'Overview', icon: '◎' },
  { to: '/projects', label: 'Projects', icon: '▤' },
  { to: '/findings', label: 'Vulnerability Findings', icon: '⚑' },
  { to: '/evidence', label: 'Evidence Library', icon: '⎙' },
  { to: '/scenarios', label: 'Attack Scenarios', icon: '⇢' },
  { to: '/generator', label: 'Test Generator', icon: '⚙' },
  { to: '/execution', label: 'Test Execution', icon: '▶' },
  { to: '/library', label: 'Regression Library', icon: '❖' },
  { to: '/reports', label: 'Comparison Reports', icon: '⇄' },
  { to: '/cicd', label: 'CI/CD Integrations', icon: '⟳' },
  { to: '/settings', label: 'Settings', icon: '⚙︎' },
];

function Shell() {
  const { user, logout, projects, project, selectProject } = useSession();
  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-200">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-slate-800 bg-slate-950 md:flex">
        <div className="flex items-center gap-2 px-5 py-5">
          <img src="/favicon.svg" alt="" className="h-7 w-7" />
          <div>
            <div className="text-sm font-semibold text-white">VulnReplay</div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500">Security regression</div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3" aria-label="Main">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === '/'}
              className={({ isActive }) => `flex items-center gap-3 rounded-lg px-3 py-2 text-sm ${isActive ? 'bg-sky-500/10 text-sky-300' : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'}`}>
              <span aria-hidden className="w-4 text-center">{n.icon}</span>{n.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-slate-800 p-4 text-xs text-slate-500">
          <div className="truncate text-slate-300">{user?.email}</div>
          <div className="mt-0.5 capitalize">{user?.role}</div>
          <button onClick={logout} className="mt-2 text-sky-400 hover:underline">Sign out</button>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-slate-800 px-6 py-3">
          <label htmlFor="project" className="text-xs uppercase tracking-wide text-slate-500">Project</label>
          <select id="project" value={project?.id ?? ''} onChange={(e) => selectProject(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900 px-2 py-1 text-sm">
            {projects.length === 0 && <option value="">No projects</option>}
            {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <span className="ml-auto text-xs text-slate-500">Only test environments you are authorized to test.</span>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 px-6 py-6">
          <Suspense fallback={<Loading />}>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/projects" element={<Projects />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/evidence" element={<EvidencePage />} />
            <Route path="/scenarios" element={<Scenarios />} />
            <Route path="/generator" element={<Generator />} />
            <Route path="/execution" element={<Execution />} />
            <Route path="/library" element={<Library />} />
            <Route path="/reports" element={<Comparison />} />
            <Route path="/cicd" element={<CiCd />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          </Suspense>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  const { user, loading } = useSession();
  if (loading) return <div className="p-10"><Loading /></div>;
  return user ? <Shell /> : <Login />;
}

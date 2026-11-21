import type { ReactNode } from 'react';
import type { Classification } from '../api';

export const CLASS_META: Record<Classification, { label: string; cls: string; icon: string }> = {
  vulnerability_reproduced: { label: 'Vulnerability reproduced', cls: 'bg-rose-500/15 text-rose-300 ring-rose-500/30', icon: '●' },
  regression_detected: { label: 'Regression detected', cls: 'bg-orange-500/15 text-orange-300 ring-orange-500/30', icon: '▲' },
  remediation_verified: { label: 'Remediation verified', cls: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/30', icon: '✓' },
  inconclusive: { label: 'Inconclusive', cls: 'bg-amber-500/15 text-amber-200 ring-amber-500/30', icon: '?' },
  execution_failed: { label: 'Execution failed', cls: 'bg-slate-500/20 text-slate-300 ring-slate-500/30', icon: '×' },
};

const SEVERITY: Record<string, string> = {
  critical: 'bg-fuchsia-500/15 text-fuchsia-300 ring-fuchsia-500/30',
  high: 'bg-rose-500/15 text-rose-300 ring-rose-500/30',
  medium: 'bg-amber-500/15 text-amber-200 ring-amber-500/30',
  low: 'bg-sky-500/15 text-sky-300 ring-sky-500/30',
  info: 'bg-slate-500/20 text-slate-300 ring-slate-500/30',
};

const pill = 'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset whitespace-nowrap';

export function ClassificationBadge({ value }: { value: Classification | null | undefined }) {
  if (!value) return <span className={`${pill} bg-slate-500/10 text-slate-400 ring-slate-600/40`}>Not run</span>;
  const m = CLASS_META[value];
  return <span className={`${pill} ${m.cls}`} data-testid="classification"><span aria-hidden>{m.icon}</span>{m.label}</span>;
}

export function SeverityBadge({ value }: { value: string }) {
  return <span className={`${pill} ${SEVERITY[value] ?? SEVERITY.info} capitalize`}>{value}</span>;
}

export function Tag({ children, tone = 'slate' }: { children: ReactNode; tone?: 'slate' | 'sky' | 'emerald' | 'amber' }) {
  const tones = {
    slate: 'bg-slate-800 text-slate-300 ring-slate-700',
    sky: 'bg-sky-500/10 text-sky-300 ring-sky-500/30',
    emerald: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
    amber: 'bg-amber-500/10 text-amber-200 ring-amber-500/30',
  };
  return <span className={`${pill} ${tones[tone]}`}>{children}</span>;
}

export function Card({ title, actions, children, className = '' }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-xl border border-slate-800 bg-slate-900/60 ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-slate-800 px-4 py-3">
          <h2 className="text-sm font-semibold text-slate-200">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-white">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-2">{actions}</div>
    </div>
  );
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-2 py-6 text-sm text-slate-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-sky-400" aria-hidden />
      {label}
    </div>
  );
}

export function ErrorBox({ message }: { message: string | null }) {
  if (!message) return null;
  return <div role="alert" className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">{message}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-dashed border-slate-700 px-4 py-8 text-center text-sm text-slate-400">{children}</div>;
}

export function Button({ variant = 'primary', className = '', ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'ghost' | 'danger' }) {
  const styles = {
    primary: 'bg-sky-500 text-slate-950 hover:bg-sky-400 disabled:bg-slate-700 disabled:text-slate-400',
    ghost: 'border border-slate-700 text-slate-200 hover:bg-slate-800 disabled:text-slate-500',
    danger: 'bg-rose-500/90 text-white hover:bg-rose-500 disabled:bg-slate-700',
  };
  return <button type="button" className={`inline-flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 disabled:cursor-not-allowed ${styles[variant]} ${className}`} {...props} />;
}

export const inputCls = 'w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none';

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}

export function Stat({ label, value, tone = 'text-white' }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${tone}`}>{value}</div>
    </div>
  );
}

export function Code({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <pre className={`max-h-96 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 font-mono text-xs leading-relaxed text-slate-300 ${className}`}>{children}</pre>;
}

export function NeedProject() {
  return <Empty>Create or select a project first (Projects page).</Empty>;
}

export const fmtDate = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : '—');
export const humanize = (s: string) => s.replace(/_/g, ' ');

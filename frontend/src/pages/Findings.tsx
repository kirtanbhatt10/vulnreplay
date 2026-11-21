import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, type AssistantAnswer, type Finding } from '../api';
import { ExchangeViewer } from '../components/viewers';
import { Button, Card, Empty, ErrorBox, Field, fmtDate, humanize, inputCls, Loading, NeedProject, PageHeader, SeverityBadge, Tag } from '../components/ui';
import { useAsync, useSession } from '../state';

export const CATEGORIES = ['idor', 'broken_access_control', 'authorization_bypass', 'authentication_failure', 'sql_injection',
  'input_validation', 'security_headers', 'rate_limiting', 'cors_misconfiguration', 'session_management', 'other'];

export function AssistantPanel({ answer }: { answer: AssistantAnswer }) {
  const sections: [string, string[], string][] = [
    ['Verified facts', answer.verified_facts, 'text-emerald-300'], ['Hypotheses', answer.hypotheses, 'text-amber-200'],
    ['Suggested tests', answer.suggested_tests, 'text-sky-300'], ['Unknown', answer.unknowns, 'text-slate-400'],
    ['Recommendations', answer.recommendations, 'text-slate-200'],
  ];
  return (
    <div className="space-y-3 text-sm" data-testid="assistant">
      <p className="text-slate-200">{answer.summary}</p>
      <div className="flex gap-2"><Tag>confidence: {answer.confidence}</Tag><Tag>{answer.provider}</Tag></div>
      {sections.filter(([, items]) => items.length).map(([title, items, cls]) => (
        <div key={title}><h3 className={`text-xs font-semibold uppercase tracking-wide ${cls}`}>{title}</h3>
          <ul className="mt-1 list-inside list-disc text-slate-300">{items.map((i) => <li key={i}>{i}</li>)}</ul></div>
      ))}
      {answer.grounding_notes.map((n) => <p key={n} className="text-xs text-slate-500">{n}</p>)}
    </div>
  );
}

function FindingDetail({ id, projectId }: { id: string; projectId: string }) {
  const { can } = useSession();
  const nav = useNavigate();
  const { data, loading, error } = useAsync(() => api.finding(id), [id]);
  const [ai, setAi] = useState<AssistantAnswer | null>(null);
  const [mode, setMode] = useState('static_secret');
  const [msg, setMsg] = useState<string | null>(null);
  if (loading) return <Loading />;
  if (error || !data) return <ErrorBox message={error} />;
  const multiCapable = ['idor', 'broken_access_control', 'authorization_bypass'].includes(data.category);

  async function reconstruct() {
    setMsg(null);
    try {
      const options = mode === 'login_flow' ? { auth_mode: 'login_flow', login: { path: '/api/login', token_path: 'access_token' } } : { auth_mode: mode };
      await api.reconstruct(projectId, id, options);
      nav('/scenarios');
    } catch (err) { setMsg((err as Error).message); }
  }
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2"><SeverityBadge value={data.severity} /><Tag>{humanize(data.category)}</Tag>{data.cwe && <Tag>{data.cwe}</Tag>}<Tag>{data.source_tool}</Tag></div>
      {data.description && <p className="text-sm text-slate-300">{data.description}</p>}
      {data.exchanges?.map((x) => <ExchangeViewer key={x.index} exchange={x} />)}
      <div className="flex flex-wrap items-end gap-3">
        <Button variant="ghost" onClick={() => api.assistant({ task: 'explain_finding', finding_id: id }).then(setAi).catch((e) => setMsg(e.message))}>Explain with assistant</Button>
        {can('analyst') && data.evidence_id && (
          <>
            <label className="text-sm">
              <span className="sr-only">Authentication mode</span>
              <select className={inputCls} value={mode} onChange={(e) => setMode(e.target.value)} aria-label="Authentication mode">
                <option value="static_secret">Credentials from secrets</option>
                {multiCapable && <option value="login_flow">Multi-step: owner vs other user (login flow)</option>}
                <option value="none">Unauthenticated</option>
              </select>
            </label>
            <Button onClick={reconstruct}>Reconstruct attack scenario</Button>
          </>
        )}
      </div>
      <ErrorBox message={msg} />
      {ai && <Card title="AI security assistant"><AssistantPanel answer={ai} /></Card>}
    </div>
  );
}

function NewFinding({ projectId, onCreated }: { projectId: string; onCreated: (f: Finding) => void }) {
  const ev = useAsync(() => api.evidence(projectId), [projectId]);
  const [form, setForm] = useState({ title: '', category: 'idor', severity: 'high', evidence_id: '', description: '' });
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const evidence = ev.data?.find((x) => x.id === form.evidence_id);
      const f = await api.createFinding(projectId, { ...form, evidence_id: form.evidence_id || null,
        exchange_indexes: evidence ? Array.from({ length: evidence.exchange_count }, (_, i) => i) : [] });
      onCreated(f);
    } catch (err) { setError((err as Error).message); }
  }
  return (
    <form onSubmit={submit} className="space-y-3" aria-label="New finding">
      <Field label="Title"><input className={inputCls} required value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Category"><select className={inputCls} value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}>{CATEGORIES.map((c) => <option key={c} value={c}>{humanize(c)}</option>)}</select></Field>
        <Field label="Severity"><select className={inputCls} value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>{['critical', 'high', 'medium', 'low', 'info'].map((s) => <option key={s}>{s}</option>)}</select></Field>
      </div>
      <Field label="Linked evidence"><select className={inputCls} value={form.evidence_id} onChange={(e) => setForm({ ...form, evidence_id: e.target.value })}>
        <option value="">— none —</option>{ev.data?.map((x) => <option key={x.id} value={x.id}>{x.filename}</option>)}</select></Field>
      <Field label="Description"><textarea className={inputCls} rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
      <ErrorBox message={error} />
      <Button type="submit">Create finding</Button>
    </form>
  );
}

export default function Findings() {
  const { project, can } = useSession();
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const list = useAsync(() => (project ? api.findings(project.id, { severity, category }) : Promise.resolve([])), [project?.id, severity, category]);
  const [selected, setSelected] = useState<string | null>(null);
  if (!project) return <NeedProject />;
  return (
    <>
      <PageHeader title="Vulnerability Findings" subtitle="Findings imported from scanners and pentest evidence, or recorded manually." />
      <div className="mb-4 flex gap-3">
        <select aria-label="Filter severity" className={`${inputCls} w-40`} value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="">All severities</option>{['critical', 'high', 'medium', 'low', 'info'].map((s) => <option key={s}>{s}</option>)}</select>
        <select aria-label="Filter category" className={`${inputCls} w-56`} value={category} onChange={(e) => setCategory(e.target.value)}><option value="">All categories</option>{CATEGORIES.map((c) => <option key={c} value={c}>{humanize(c)}</option>)}</select>
      </div>
      <div className="grid gap-6 lg:grid-cols-5">
        <div className="space-y-2 lg:col-span-2">
          <ErrorBox message={list.error} />
          {list.loading ? <Loading /> : !list.data?.length ? <Empty>No findings match.</Empty> : list.data.map((f) => (
            <button key={f.id} onClick={() => setSelected(f.id)} className={`block w-full rounded-xl border bg-slate-900/60 p-3 text-left ${selected === f.id ? 'border-sky-500/60' : 'border-slate-800 hover:border-slate-700'}`}>
              <div className="flex items-center gap-2"><SeverityBadge value={f.severity} /><span className="text-xs text-slate-400">{humanize(f.category)}</span><span className="ml-auto text-xs text-slate-500">{f.status}</span></div>
              <div className="mt-1 text-sm font-medium text-white">{f.title}</div>
              <div className="text-xs text-slate-500">{f.source_tool} · {fmtDate(f.created_at)}</div>
            </button>
          ))}
          {can('analyst') && <Card title="Record a finding" className="mt-4"><NewFinding projectId={project.id} onCreated={(f) => { list.reload(); setSelected(f.id); }} /></Card>}
        </div>
        <div className="lg:col-span-3">{selected ? <Card title="Finding detail"><FindingDetail id={selected} projectId={project.id} /></Card> : <Empty>Select a finding to view its evidence.</Empty>}</div>
      </div>
    </>
  );
}

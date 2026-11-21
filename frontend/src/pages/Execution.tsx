import { useEffect, useState, type FormEvent } from 'react';
import { api, type Execution as Exec } from '../api';
import { StepResults } from '../components/viewers';
import { Button, Card, ClassificationBadge, Code, Empty, ErrorBox, Field, fmtDate, inputCls, Loading, NeedProject, PageHeader } from '../components/ui';
import { useAsync, useSession } from '../state';

export function ExecutionDetail({ id }: { id: string }) {
  const [ex, setEx] = useState<Exec | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const load = () => api.execution(id).then((e) => {
      if (!alive) return;
      setEx(e);
      if (e.status === 'queued' || e.status === 'running') timer = setTimeout(load, 1000);
    }).catch((err) => alive && setError(err.message));
    load();
    return () => { alive = false; clearTimeout(timer); };
  }, [id]);
  if (error) return <ErrorBox message={error} />;
  if (!ex) return <Loading />;
  const running = ex.status === 'queued' || ex.status === 'running';
  return (
    <div className="space-y-4" data-testid="execution-detail">
      <div className="flex flex-wrap items-center gap-3">
        {running ? <Loading label={`Execution ${ex.status}…`} /> : <ClassificationBadge value={ex.classification} />}
        {ex.is_baseline && <span className="text-xs text-sky-300">stored as vulnerable baseline</span>}
        <span className="text-sm text-slate-400">{ex.test_name} → {ex.target_name} · v{ex.test_version} · {fmtDate(ex.created_at)}</span>
        {running && <Button variant="danger" onClick={() => api.cancel(ex.id)}>Cancel</Button>}
      </div>
      {ex.comparison?.reasons?.length ? <ul className="list-inside list-disc text-sm text-slate-300">{ex.comparison.reasons.map((r) => <li key={r}>{r}</li>)}</ul> : null}
      {ex.result?.steps?.length ? <StepResults steps={ex.result.steps} /> : null}
      {ex.result?.log?.length ? <details><summary className="cursor-pointer text-sm text-slate-400">Execution log ({ex.result.request_count} requests)</summary><Code>{ex.result.log.join('\n')}</Code></details> : null}
    </div>
  );
}

export default function Execution() {
  const { project, can } = useSession();
  const pid = project?.id;
  const tests = useAsync(() => (pid ? api.tests(pid, { status: 'approved' }) : Promise.resolve([])), [pid]);
  const targets = useAsync(() => (pid ? api.targets(pid) : Promise.resolve([])), [pid]);
  const history = useAsync(() => (pid ? api.executions(pid) : Promise.resolve([])), [pid]);
  const [form, setForm] = useState({ test_id: '', target_id: '', label: '' });
  const [current, setCurrent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (!project) return <NeedProject />;
  const authorized = targets.data?.filter((t) => t.authorized) ?? [];

  async function run(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try { const ex = await api.execute(form); setCurrent(ex.id); setTimeout(history.reload, 1500); } catch (err) { setError((err as Error).message); }
  }

  return (
    <>
      <PageHeader title="Test Execution" subtitle="Controlled, rate-limited execution against explicitly authorized environments only." />
      <div className="grid gap-6 lg:grid-cols-3">
        {can('analyst') && (
          <Card title="Run a regression test">
            <form onSubmit={run} className="space-y-3">
              <Field label="Approved test"><select className={inputCls} required value={form.test_id} onChange={(e) => setForm({ ...form, test_id: e.target.value })}>
                <option value="">Select…</option>{tests.data?.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select></Field>
              <Field label="Authorized target" hint={authorized.length ? undefined : 'No authorized targets — an admin must authorize one on the Projects page.'}>
                <select className={inputCls} required value={form.target_id} onChange={(e) => setForm({ ...form, target_id: e.target.value })}>
                  <option value="">Select…</option>{authorized.map((t) => <option key={t.id} value={t.id}>{t.name} ({t.base_url})</option>)}</select></Field>
              <Field label="Label" hint="e.g. baseline, post-fix, release-2.3"><input className={inputCls} maxLength={64} value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} /></Field>
              <ErrorBox message={error} />
              <Button type="submit">Execute</Button>
            </form>
          </Card>
        )}
        <div className="space-y-4 lg:col-span-2">
          {current && <Card title="Execution result"><ExecutionDetail id={current} /></Card>}
          <Card title="Execution history">
            {history.loading ? <Loading /> : !history.data?.length ? <Empty>No executions yet.</Empty> : (
              <table className="w-full text-sm">
                <thead className="text-left text-xs uppercase text-slate-500"><tr><th className="py-2">When</th><th>Test</th><th>Target</th><th>Label</th><th>Result</th></tr></thead>
                <tbody className="divide-y divide-slate-800">
                  {history.data.map((e) => (
                    <tr key={e.id} className="cursor-pointer hover:bg-slate-900" onClick={() => setCurrent(e.id)}>
                      <td className="py-2 text-slate-400">{fmtDate(e.created_at)}</td><td>{e.test_name}</td><td>{e.target_name}</td><td>{e.label || '—'}</td><td><ClassificationBadge value={e.classification} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}

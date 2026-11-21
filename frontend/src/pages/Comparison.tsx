import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api, download, type Diff } from '../api';
import { DiffPanel } from '../components/viewers';
import { Button, Card, ClassificationBadge, Empty, ErrorBox, fmtDate, inputCls, Loading, NeedProject, PageHeader } from '../components/ui';
import { useAsync, useSession } from '../state';
import { AssistantPanel } from './Findings';

export default function Comparison() {
  const { project } = useSession();
  const [params, setParams] = useSearchParams();
  const tests = useAsync(() => (project ? api.tests(project.id) : Promise.resolve([])), [project?.id]);
  const testId = params.get('test') ?? tests.data?.find((t) => t.latest_classification)?.id ?? '';
  const execs = useAsync(() => (project && testId ? api.executions(project.id, testId) : Promise.resolve([])), [project?.id, testId]);
  const [pair, setPair] = useState<{ before: string; after: string }>({ before: '', after: '' });
  const [diff, setDiff] = useState<Diff | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [explain, setExplain] = useState<Awaited<ReturnType<typeof api.assistant>> | null>(null);
  if (!project) return <NeedProject />;
  const ordered = [...(execs.data ?? [])].reverse();
  const baseline = ordered.find((e) => e.is_baseline);
  const latest = ordered.at(-1);
  const before = pair.before || baseline?.id || '';
  const after = pair.after || latest?.id || '';

  async function runCompare() {
    setError(null);
    try { setDiff((await api.compare(before, after)).diff); } catch (e) { setError((e as Error).message); }
  }

  return (
    <>
      <PageHeader title="Comparison Reports" subtitle="Before/after evidence for remediation verification, exportable as HTML, PDF or JSON." />
      <div className="mb-4 max-w-md">
        <select aria-label="Test" className={inputCls} value={testId} onChange={(e) => { setParams({ test: e.target.value }); setDiff(null); setExplain(null); }}>
          <option value="">Select a test…</option>{tests.data?.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
      </div>
      {!testId ? <Empty>Select a test.</Empty> : execs.loading ? <Loading /> : !ordered.length ? <Empty>This test has not been executed.</Empty> : (
        <div className="space-y-6">
          <Card title="Vulnerability timeline" actions={<>
            {(['html', 'pdf', 'json'] as const).map((f) => <Button key={f} variant="ghost" onClick={() => download(`/tests/${testId}/report?format=${f}`, `vulnreplay-report.${f}`).catch((e) => setError(e.message))}>{f.toUpperCase()}</Button>)}
          </>}>
            <ol className="relative ml-2 border-l border-slate-700" data-testid="timeline">
              {ordered.map((e) => (
                <li key={e.id} className="mb-4 ml-5">
                  <span className="absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full border border-slate-900 bg-slate-500" />
                  <div className="flex flex-wrap items-center gap-2"><ClassificationBadge value={e.classification} /><span className="text-sm text-slate-200">{e.label || 'run'}</span>{e.is_baseline && <span className="text-xs text-sky-300">baseline</span>}
                    <span className="text-xs text-slate-500">{e.target_name} · {fmtDate(e.created_at)} · {e.summary ? `${e.summary.assertions_passed}/${e.summary.assertions_total} assertions` : ''}</span>
                    <button className="text-xs text-sky-400" onClick={() => api.assistant({ task: 'explain_result', execution_id: e.id }).then(setExplain)}>explain</button></div>
                </li>
              ))}
            </ol>
          </Card>
          {explain && <Card title="Why this result?"><AssistantPanel answer={explain} /></Card>}
          <Card title="Request/response comparison" actions={<Button onClick={runCompare} disabled={!before || !after}>Compare</Button>}>
            <div className="mb-4 grid gap-3 md:grid-cols-2">
              {(['before', 'after'] as const).map((side) => (
                <label key={side} className="text-sm"><span className="mb-1 block text-xs uppercase text-slate-500">{side}</span>
                  <select aria-label={`${side} execution`} className={inputCls} value={side === 'before' ? before : after} onChange={(e) => setPair({ before, after, [side]: e.target.value })}>
                    {ordered.map((e) => <option key={e.id} value={e.id}>{fmtDate(e.created_at)} · {e.label || 'run'} · {e.classification}</option>)}</select></label>
              ))}
            </div>
            <ErrorBox message={error} />
            {diff ? <DiffPanel diff={diff} /> : <p className="text-sm text-slate-500">Choose two executions and press Compare.</p>}
          </Card>
        </div>
      )}
    </>
  );
}

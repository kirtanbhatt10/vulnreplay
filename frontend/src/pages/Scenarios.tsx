import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import { AttackFlow } from '../components/viewers';
import { Button, Card, Code, Empty, ErrorBox, humanize, Loading, NeedProject, PageHeader, SeverityBadge, Tag } from '../components/ui';
import { useAsync, useSession } from '../state';

export default function Scenarios() {
  const { project, can } = useSession();
  const nav = useNavigate();
  const list = useAsync(() => (project ? api.scenarios(project.id) : Promise.resolve([])), [project?.id]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (!project) return <NeedProject />;
  const scn = list.data?.find((s) => s.id === (selected ?? list.data?.[0]?.id));

  async function generate(useAi: boolean) {
    if (!scn) return;
    setError(null);
    try { const t = await api.generate(project!.id, scn.id, useAi); nav(`/generator?test=${t.id}`); } catch (e) { setError((e as Error).message); }
  }

  return (
    <>
      <PageHeader title="Attack Scenarios" subtitle="Structured reconstructions of the original attack, derived only from imported evidence." />
      {list.loading ? <Loading /> : !list.data?.length ? <Empty>No scenarios yet. Open a finding and choose “Reconstruct attack scenario”.</Empty> : (
        <div className="grid gap-6 lg:grid-cols-4">
          <ul className="space-y-2">
            {list.data.map((s) => (
              <li key={s.id}><button onClick={() => setSelected(s.id)} className={`w-full rounded-xl border bg-slate-900/60 p-3 text-left text-sm ${scn?.id === s.id ? 'border-sky-500/60' : 'border-slate-800 hover:border-slate-700'}`}>
                <div className="font-medium text-white">{s.title}</div><div className="text-xs text-slate-400">{humanize(s.category)}{s.data.multi_step ? ' · multi-step' : ''}</div></button></li>
            ))}
          </ul>
          {scn && (
            <div className="space-y-4 lg:col-span-3">
              <Card title={scn.title} actions={can('analyst') && <><Button variant="ghost" onClick={() => generate(true)}>Generate with AI (review required)</Button><Button onClick={() => generate(false)}>Generate test</Button></>}>
                <div className="mb-3 flex flex-wrap gap-2"><SeverityBadge value={scn.data.risk_assessment.severity} /><Tag>{humanize(scn.category)}</Tag><Tag tone="sky">{scn.data.method} {scn.data.target_endpoint}</Tag><Tag>auth: {scn.data.authentication_context.type}</Tag><span className="font-mono text-xs text-slate-500">{scn.data.scenario_id}</span></div>
                <AttackFlow steps={scn.data.request_sequence} />
                <ErrorBox message={error} />
              </Card>
              <div className="grid gap-4 md:grid-cols-2">
                <Card title="Observed vs expected">
                  <dl className="space-y-2 text-sm"><dt className="text-xs uppercase text-rose-300">Observed</dt><dd className="text-slate-300">{scn.data.observed_behavior}</dd>
                    <dt className="text-xs uppercase text-emerald-300">Expected (secure)</dt><dd className="text-slate-300">{scn.data.expected_behavior}</dd>
                    <dt className="text-xs uppercase text-slate-400">Risk</dt><dd className="text-slate-300">{scn.data.risk_assessment.impact}</dd></dl>
                </Card>
                <Card title="Reproduction instructions">
                  <ol className="space-y-1 text-sm text-slate-300">{scn.data.reproduction_instructions.map((r) => <li key={r}>{r}</li>)}</ol>
                  <h3 className="mt-3 text-xs uppercase text-slate-500">Preconditions</h3>
                  <ul className="list-inside list-disc text-sm text-slate-400">{scn.data.preconditions.map((p) => <li key={p}>{p}</li>)}</ul>
                </Card>
              </div>
              <Card title="Secure expectations (assertions)">
                <Code>{JSON.stringify(scn.data.secure_expectations, null, 2)}</Code>
                {scn.data.review_notes.map((n) => <p key={n} className="mt-2 text-sm text-amber-200">{n}</p>)}
                <p className="mt-2 text-xs text-slate-500">Evidence: {scn.data.evidence_references.join(', ')}</p>
              </Card>
            </div>
          )}
        </div>
      )}
    </>
  );
}

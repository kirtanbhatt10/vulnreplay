import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import { Button, Card, Code, Empty, ErrorBox, Loading, NeedProject, PageHeader, Tag } from '../components/ui';
import { useAsync, useSession } from '../state';

const FORMATS = [['json', 'JSON definition'], ['pytest', 'Pytest + HTTPX'], ['playwright', 'Playwright']] as const;

export default function Generator() {
  const { project, can } = useSession();
  const [params, setParams] = useSearchParams();
  const tests = useAsync(() => (project ? api.tests(project.id) : Promise.resolve([])), [project?.id]);
  const testId = params.get('test') ?? tests.data?.[0]?.id ?? null;
  const test = useAsync(() => (testId ? api.test(testId) : Promise.resolve(null)), [testId]);
  const [format, setFormat] = useState<string>('json');
  const code = useAsync(() => (testId ? api.renderTest(testId, format) : Promise.resolve('')), [testId, format, test.data?.current_version]);
  const [error, setError] = useState<string | null>(null);
  if (!project) return <NeedProject />;

  async function approve() {
    if (!testId) return;
    setError(null);
    try { test.setData(await api.approveTest(testId)); } catch (e) { setError((e as Error).message); }
  }

  return (
    <>
      <PageHeader title="Test Generator" subtitle="Generated tests reference secrets by name and must be reviewed and approved before they can run." />
      {tests.loading ? <Loading /> : !tests.data?.length ? <Empty>No tests yet. Generate one from an <Link className="text-sky-400" to="/scenarios">attack scenario</Link>.</Empty> : (
        <div className="grid gap-6 lg:grid-cols-4">
          <ul className="space-y-2">
            {tests.data.map((t) => (
              <li key={t.id}><button onClick={() => setParams({ test: t.id })} className={`w-full rounded-xl border bg-slate-900/60 p-3 text-left text-sm ${t.id === testId ? 'border-sky-500/60' : 'border-slate-800 hover:border-slate-700'}`}>
                <div className="font-medium text-white">{t.name}</div>
                <div className="mt-1 flex gap-2"><Tag tone={t.status === 'approved' ? 'emerald' : 'amber'}>{t.status}</Tag><Tag>{t.origin}</Tag><Tag>v{t.current_version}</Tag></div></button></li>
            ))}
          </ul>
          <div className="space-y-4 lg:col-span-3">
            {test.data && (
              <Card title={test.data.name} actions={can('analyst') && test.data.status !== 'approved' && <Button onClick={approve}>Approve for execution</Button>}>
                <div className="mb-3 flex flex-wrap gap-2 text-sm">
                  <Tag tone={test.data.status === 'approved' ? 'emerald' : 'amber'}>{test.data.status}</Tag>
                  {test.data.origin === 'ai' && <Tag tone="amber">AI-generated · human review required</Tag>}
                  <span className="text-slate-400">Secrets required:</span>
                  {test.data.definition?.secrets.length ? test.data.definition.secrets.map((s) => <code key={s} className="rounded bg-slate-800 px-1.5 text-xs">VULNREPLAY_SECRET_{s}</code>) : <span className="text-slate-500">none</span>}
                </div>
                <div className="mb-2 flex gap-1" role="tablist">
                  {FORMATS.map(([f, label]) => <button key={f} role="tab" aria-selected={format === f} onClick={() => setFormat(f)} className={`rounded-md px-3 py-1 text-xs ${format === f ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}>{label}</button>)}
                </div>
                {code.loading ? <Loading /> : <Code className="max-h-[32rem]">{code.data}</Code>}
                <ErrorBox message={error ?? code.error} />
              </Card>
            )}
          </div>
        </div>
      )}
    </>
  );
}

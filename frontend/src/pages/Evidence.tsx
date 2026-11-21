import { useState, type FormEvent } from 'react';
import { api, type Evidence } from '../api';
import { ExchangeViewer } from '../components/viewers';
import { Button, Card, Empty, ErrorBox, Field, fmtDate, inputCls, Loading, NeedProject, PageHeader, Tag } from '../components/ui';
import { useAsync, useSession } from '../state';

const FORMATS = ['auto', 'har', 'burp', 'zap', 'sarif', 'raw-http', 'json', 'incident-log'];

export function UploadForm({ projectId, onDone }: { projectId: string; onDone: (e: Evidence) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [format, setFormat] = useState('auto');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    try { onDone(await api.uploadEvidence(projectId, file, format)); setFile(null); (e.target as HTMLFormElement).reset(); }
    catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }
  return (
    <form onSubmit={submit} className="space-y-3" aria-label="Upload evidence">
      <Field label="Evidence file" hint="Burp XML, ZAP JSON, HAR, SARIF, raw HTTP, JSON report or JSONL incident log. Max 5 MB. Never executed.">
        <input type="file" aria-label="Evidence file" onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="block w-full text-sm text-slate-300 file:mr-3 file:rounded-md file:border-0 file:bg-slate-800 file:px-3 file:py-1.5 file:text-slate-200" />
      </Field>
      <Field label="Format">
        <select className={inputCls} value={format} onChange={(e) => setFormat(e.target.value)}>{FORMATS.map((f) => <option key={f}>{f}</option>)}</select>
      </Field>
      <ErrorBox message={error} />
      <Button type="submit" disabled={!file || busy}>{busy ? 'Importing…' : 'Import evidence'}</Button>
    </form>
  );
}

export default function EvidencePage() {
  const { project, can } = useSession();
  const list = useAsync(() => (project ? api.evidence(project.id) : Promise.resolve([])), [project?.id]);
  const [selected, setSelected] = useState<string | null>(null);
  const detail = useAsync(() => (selected ? api.evidenceDetail(selected) : Promise.resolve(null)), [selected]);
  const [last, setLast] = useState<Evidence | null>(null);
  if (!project) return <NeedProject />;

  return (
    <>
      <PageHeader title="Evidence Library" subtitle="Original evidence is preserved byte-for-byte and fingerprinted with SHA-256." />
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <ErrorBox message={list.error} />
          {list.loading ? <Loading /> : !list.data?.length ? <Empty>No evidence imported yet.</Empty> : (
            <ul className="space-y-2">
              {list.data.map((e) => (
                <li key={e.id}>
                  <button onClick={() => setSelected(e.id)} className={`w-full rounded-xl border p-3 text-left ${selected === e.id ? 'border-sky-500/60' : 'border-slate-800 hover:border-slate-700'} bg-slate-900/60`}>
                    <div className="flex flex-wrap items-center gap-2"><span className="font-medium text-white">{e.filename}</span><Tag tone="sky">{e.format}</Tag><span className="text-xs text-slate-400">{e.exchange_count} exchange(s) · {(e.size_bytes / 1024).toFixed(1)} KB</span></div>
                    <div className="mt-1 font-mono text-[11px] text-slate-500">sha256 {e.sha256}</div>
                    <div className="text-xs text-slate-500">Imported {fmtDate(e.created_at)} by {String(e.provenance.imported_by ?? 'unknown')}</div>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {selected && (
            <Card title="Evidence viewer">
              {detail.loading ? <Loading /> : detail.data && (
                <div className="space-y-3">{detail.data.exchanges?.map((x) => <ExchangeViewer key={x.index} exchange={x} />)}</div>
              )}
            </Card>
          )}
        </div>
        {can('analyst') && (
          <Card title="Import evidence">
            <UploadForm projectId={project.id} onDone={(e) => { setLast(e); list.reload(); setSelected(e.id); }} />
            {last && (
              <p className="mt-3 text-sm text-emerald-300" role="status">Imported {last.filename}: {last.exchange_count} exchange(s), {last.findings?.length ?? 0} finding(s).</p>
            )}
          </Card>
        )}
      </div>
    </>
  );
}

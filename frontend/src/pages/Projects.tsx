import { useState, type FormEvent } from 'react';
import { api, type Target } from '../api';
import { Button, Card, Empty, ErrorBox, Field, inputCls, Loading, PageHeader, Tag } from '../components/ui';
import { useAsync, useSession } from '../state';

export default function Projects() {
  const { projects, project, selectProject, reloadProjects, can } = useSession();
  const [name, setName] = useState('');
  const [desc, setDesc] = useState('');
  const [error, setError] = useState<string | null>(null);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const p = await api.createProject(name, desc);
      await reloadProjects();
      selectProject(p.id);
      setName(''); setDesc('');
    } catch (err) { setError((err as Error).message); }
  }

  return (
    <>
      <PageHeader title="Projects" subtitle="Group evidence, tests and authorized environments per application." />
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-3 lg:col-span-2">
          {projects.length === 0 && <Empty>No projects yet.</Empty>}
          {projects.map((p) => (
            <button key={p.id} onClick={() => selectProject(p.id)}
              className={`block w-full rounded-xl border p-4 text-left ${p.id === project?.id ? 'border-sky-500/60 bg-sky-500/5' : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'}`}>
              <div className="font-medium text-white">{p.name}</div>
              {p.description && <div className="text-sm text-slate-400">{p.description}</div>}
              {p.stats && <div className="mt-2 flex gap-4 text-xs text-slate-400"><span>{p.stats.evidence} evidence</span><span>{p.stats.findings} findings</span><span>{p.stats.tests} tests</span><span>{p.stats.executions} executions</span></div>}
            </button>
          ))}
        </div>
        {can('analyst') && (
          <Card title="New project">
            <form onSubmit={create} className="space-y-3">
              <Field label="Name"><input className={inputCls} required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} /></Field>
              <Field label="Description"><textarea className={inputCls} rows={3} value={desc} onChange={(e) => setDesc(e.target.value)} /></Field>
              <ErrorBox message={error} />
              <Button type="submit">Create project</Button>
            </form>
          </Card>
        )}
      </div>
      {project && <Targets projectId={project.id} />}
    </>
  );
}

function Targets({ projectId }: { projectId: string }) {
  const { can } = useSession();
  const { data, error, loading, reload } = useAsync(() => api.targets(projectId), [projectId]);
  const [form, setForm] = useState({ name: '', base_url: 'http://localhost:8001', environment: 'staging' });
  const [msg, setMsg] = useState<string | null>(null);

  async function add(e: FormEvent) {
    e.preventDefault();
    setMsg(null);
    try { await api.createTarget(projectId, form); reload(); } catch (err) { setMsg((err as Error).message); }
  }
  async function authorize(t: Target, authorized: boolean) {
    const note = authorized ? window.prompt('Authorization note: who approved testing this environment, and the scope?') : 'revoked';
    if (!note) return;
    const priv = authorized && window.confirm('Allow private network addresses (e.g. a docker-compose lab)?');
    try { await api.authorizeTarget(t.id, { authorized, authorization_note: note, allow_private_network: priv }); reload(); } catch (err) { setMsg((err as Error).message); }
  }

  return (
    <div className="mt-8 grid gap-6 lg:grid-cols-3">
      <Card title="Authorized target environments" className="lg:col-span-2">
        <ErrorBox message={error} />
        {loading ? <Loading /> : !data?.length ? <Empty>No targets. Tests can only run against targets an administrator has authorized.</Empty> : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-slate-500"><tr><th className="py-2">Name</th><th>Base URL</th><th>Status</th><th /></tr></thead>
            <tbody className="divide-y divide-slate-800">
              {data.map((t) => (
                <tr key={t.id}>
                  <td className="py-2">{t.name} <span className="text-xs text-slate-500">({t.environment})</span></td>
                  <td className="font-mono text-xs">{t.base_url}</td>
                  <td>{t.authorized ? <Tag tone="emerald">authorized{t.allow_private_network ? ' · private net' : ''}</Tag> : <Tag tone="amber">not authorized</Tag>}
                    {t.authorization_note && <div className="mt-1 text-xs text-slate-500">{t.authorization_note}</div>}</td>
                  <td className="text-right">{can('admin') && <Button variant="ghost" onClick={() => authorize(t, !t.authorized)}>{t.authorized ? 'Revoke' : 'Authorize'}</Button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {can('analyst') && (
        <Card title="Add target">
          <form onSubmit={add} className="space-y-3">
            <Field label="Name"><input className={inputCls} required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
            <Field label="Base URL" hint="Host must be in the operator allowlist (VULNREPLAY_ALLOWED_HOSTS)."><input className={inputCls} required value={form.base_url} onChange={(e) => setForm({ ...form, base_url: e.target.value })} /></Field>
            <Field label="Environment">
              <select className={inputCls} value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })}>
                <option value="local">local</option><option value="staging">staging</option><option value="lab">lab</option>
              </select>
            </Field>
            <ErrorBox message={msg} />
            <Button type="submit">Add target</Button>
          </form>
        </Card>
      )}
    </div>
  );
}

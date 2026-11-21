import { useState, type FormEvent } from 'react';
import { api, type Role } from '../api';
import { Button, Card, ErrorBox, fmtDate, inputCls, Loading, PageHeader, Tag } from '../components/ui';
import { useAsync, useSession } from '../state';

function Users() {
  const users = useAsync(() => api.users(), []);
  const [form, setForm] = useState<{ email: string; password: string; role: Role }>({ email: '', password: '', role: 'analyst' });
  const [error, setError] = useState<string | null>(null);
  async function add(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try { await api.createUser(form); setForm({ email: '', password: '', role: 'analyst' }); users.reload(); } catch (err) { setError((err as Error).message); }
  }
  return (
    <Card title="Users & roles">
      {users.loading ? <Loading /> : (
        <ul className="mb-4 divide-y divide-slate-800 text-sm">{users.data?.map((u) => <li key={u.id} className="flex items-center gap-2 py-2"><span>{u.email}</span><Tag tone={u.role === 'admin' ? 'sky' : 'slate'}>{u.role}</Tag>{!u.is_active && <Tag tone="amber">inactive</Tag>}</li>)}</ul>
      )}
      <form onSubmit={add} className="grid gap-3 md:grid-cols-4">
        <input aria-label="Email" className={inputCls} type="email" required placeholder="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <input aria-label="Password" className={inputCls} type="password" required minLength={10} placeholder="password (10+ chars)" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <select aria-label="Role" className={inputCls} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}><option>viewer</option><option>analyst</option><option>admin</option></select>
        <Button type="submit">Add user</Button>
      </form>
      <ErrorBox message={error} />
    </Card>
  );
}

function Audit() {
  const audit = useAsync(() => api.audit(), []);
  return (
    <Card title="Audit log (latest 50)">
      {audit.loading ? <Loading /> : <ul className="max-h-80 space-y-1 overflow-auto font-mono text-xs text-slate-400">{audit.data?.map((a) => <li key={a.id}>{fmtDate(a.created_at)} · {a.action} · {a.subject}</li>)}</ul>}
    </Card>
  );
}

export default function SettingsPage() {
  const { can } = useSession();
  const settings = useAsync(() => api.settings(), []);
  const s = settings.data;
  return (
    <>
      <PageHeader title="Settings" subtitle="Execution safety limits are set by the operator through environment variables." />
      <ErrorBox message={settings.error} />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Execution safety">
          {!s ? <Loading /> : (
            <dl className="grid grid-cols-2 gap-y-2 text-sm">
              <dt className="text-slate-400">Environment</dt><dd>{s.environment}</dd>
              <dt className="text-slate-400">Allowed target hosts</dt><dd className="flex flex-wrap gap-1">{s.allowed_hosts.map((h) => <Tag key={h}>{h}</Tag>)}</dd>
              <dt className="text-slate-400">Request timeout</dt><dd>{s.request_timeout_seconds}s</dd>
              <dt className="text-slate-400">Max requests / execution</dt><dd>{s.max_requests_per_execution}</dd>
              <dt className="text-slate-400">Min interval between requests</dt><dd>{s.min_request_interval_ms} ms</dd>
              <dt className="text-slate-400">Max upload size</dt><dd>{(s.max_upload_bytes / 1048576).toFixed(0)} MB</dd>
              <dt className="text-slate-400">Local LLM assistant</dt><dd>{s.llm_enabled ? `enabled (${s.llm_model})` : 'disabled — deterministic analysis'}</dd>
            </dl>
          )}
        </Card>
        {can('admin') && <Users />}
        {can('admin') && <Audit />}
      </div>
    </>
  );
}

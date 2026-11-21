import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, download } from '../api';
import { Button, ClassificationBadge, Empty, ErrorBox, fmtDate, humanize, inputCls, Loading, NeedProject, PageHeader, Tag } from '../components/ui';
import { useAsync, useSession } from '../state';
import { CATEGORIES } from './Findings';

export default function Library() {
  const { project } = useSession();
  const [filters, setFilters] = useState({ q: '', category: '', tag: '', status: '' });
  const list = useAsync(() => (project ? api.tests(project.id, filters) : Promise.resolve([])), [project?.id, JSON.stringify(filters)]);
  const [error, setError] = useState<string | null>(null);
  if (!project) return <NeedProject />;
  return (
    <>
      <PageHeader title="Regression Library" subtitle="Every reproduced vulnerability becomes a permanent, versioned security regression test."
        actions={<Button variant="ghost" onClick={() => download(`/projects/${project.id}/tests-export`, 'vulnreplay-suite.json').catch((e) => setError(e.message))}>Export approved suite</Button>} />
      <div className="mb-4 grid gap-3 md:grid-cols-4">
        <input aria-label="Search tests" placeholder="Search by name…" className={inputCls} value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
        <select aria-label="Category" className={inputCls} value={filters.category} onChange={(e) => setFilters({ ...filters, category: e.target.value })}><option value="">All categories</option>{CATEGORIES.map((c) => <option key={c} value={c}>{humanize(c)}</option>)}</select>
        <input aria-label="Tag" placeholder="Tag" className={inputCls} value={filters.tag} onChange={(e) => setFilters({ ...filters, tag: e.target.value })} />
        <select aria-label="Status" className={inputCls} value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}><option value="">Any status</option><option>draft</option><option>approved</option><option>archived</option></select>
      </div>
      <ErrorBox message={error ?? list.error} />
      {list.loading ? <Loading /> : !list.data?.length ? <Empty>No tests match these filters.</Empty> : (
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs uppercase text-slate-500"><tr><th className="px-4 py-2">Test</th><th>Category</th><th>Tags</th><th>Version</th><th>Status</th><th>Latest result</th><th /></tr></thead>
            <tbody className="divide-y divide-slate-800">
              {list.data.map((t) => (
                <tr key={t.id}>
                  <td className="px-4 py-2 font-medium text-white">{t.name}<div className="text-xs font-normal text-slate-500">{t.origin} · created {fmtDate(t.created_at)}</div></td>
                  <td>{humanize(t.category)}</td>
                  <td><div className="flex flex-wrap gap-1">{t.tags.map((g) => <Tag key={g}>{g}</Tag>)}</div></td>
                  <td>v{t.current_version}<div className="text-xs text-slate-500">{t.versions.length} version(s)</div></td>
                  <td><Tag tone={t.status === 'approved' ? 'emerald' : 'amber'}>{t.status}</Tag></td>
                  <td><ClassificationBadge value={t.latest_classification} /><div className="text-xs text-slate-500">{fmtDate(t.latest_execution_at)}</div></td>
                  <td className="pr-4 text-right"><Link className="text-xs text-sky-400" to={`/reports?test=${t.id}`}>History →</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

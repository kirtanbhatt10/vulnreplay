import { Link } from 'react-router-dom';
import { api, type Classification } from '../api';
import { Card, ClassificationBadge, Empty, ErrorBox, fmtDate, Loading, PageHeader, Stat } from '../components/ui';
import { useAsync, useSession } from '../state';

const ORDER: Classification[] = ['regression_detected', 'vulnerability_reproduced', 'inconclusive', 'execution_failed', 'remediation_verified'];
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const BAR: Record<Classification, string> = {
  regression_detected: 'bg-orange-400', vulnerability_reproduced: 'bg-rose-400', inconclusive: 'bg-amber-300',
  execution_failed: 'bg-slate-400', remediation_verified: 'bg-emerald-400',
};

export default function Overview() {
  const { project } = useSession();
  const { data, error, loading } = useAsync(() => api.dashboard(project?.id), [project?.id]);
  return (
    <>
      <PageHeader title="Overview" subtitle={project ? `Live status for ${project.name}` : 'All projects'} />
      <ErrorBox message={error} />
      {loading && !data ? <Loading /> : data && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
            <Stat label="Evidence files" value={data.counts.evidence} />
            <Stat label="Findings" value={data.counts.findings} />
            <Stat label="Regression tests" value={data.counts.tests} />
            <Stat label="Approved tests" value={data.counts.approved_tests} />
            <Stat label="Executions" value={data.counts.executions} />
          </div>
          <div className="grid gap-6 lg:grid-cols-2">
            <Card title="Latest result per test">
              {Object.keys(data.latest_status_by_test).length === 0 ? <Empty>No tests executed yet.</Empty> : (
                <ul className="space-y-2">
                  {ORDER.filter((c) => data.latest_status_by_test[c]).map((c) => {
                    const n = data.latest_status_by_test[c];
                    const total = Object.values(data.latest_status_by_test).reduce((a, b) => a + b, 0);
                    return (
                      <li key={c} className="flex items-center gap-3">
                        <div className="w-52"><ClassificationBadge value={c} /></div>
                        <div className="h-2 flex-1 overflow-hidden rounded bg-slate-800">
                          <div className={`h-full ${BAR[c]}`} style={{ width: `${(n / total) * 100}%` }} />
                        </div>
                        <span className="w-8 text-right tabular-nums text-slate-300">{n}</span>
                      </li>
                    );
                  })}
                </ul>
              )}
            </Card>
            <Card title="Findings by severity">
              {data.counts.findings === 0 ? <Empty>No findings imported. <Link className="text-sky-400" to="/evidence">Import evidence</Link>.</Empty> : (
                <div className="flex items-end gap-4">
                  {SEV_ORDER.map((s) => (
                    <div key={s} className="flex-1 text-center">
                      <div className="text-2xl font-semibold tabular-nums text-white">{data.findings_by_severity[s] ?? 0}</div>
                      <div className="text-xs capitalize text-slate-400">{s}</div>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>
          <Card title="Recent executions" actions={<Link to="/execution" className="text-xs text-sky-400">Run a test →</Link>}>
            {data.recent_executions.length === 0 ? <Empty>No executions yet.</Empty> : (
              <table className="w-full text-sm">
                <thead className="text-left text-xs uppercase text-slate-500"><tr><th className="py-2">When</th><th>Label</th><th>Version</th><th>Result</th></tr></thead>
                <tbody className="divide-y divide-slate-800">
                  {data.recent_executions.map((e) => (
                    <tr key={e.id}><td className="py-2 text-slate-400">{fmtDate(e.created_at)}</td><td>{e.label || '—'}{e.is_baseline && <span className="ml-2 text-xs text-sky-300">baseline</span>}</td><td>v{e.test_version}</td><td><ClassificationBadge value={e.classification} /></td></tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </div>
      )}
    </>
  );
}

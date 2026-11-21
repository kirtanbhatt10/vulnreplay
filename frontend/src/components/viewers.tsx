import { Background, Controls, MarkerType, Position, ReactFlow, type Edge, type Node } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useState } from 'react';
import type { AssertionResult, Diff, Exchange, ScenarioStep, StepResult } from '../api';
import { Code, Tag } from './ui';

/** Request/response evidence viewer. All content is rendered as text (React escapes it). */
export function ExchangeViewer({ exchange }: { exchange: Exchange }) {
  const [tab, setTab] = useState<'request' | 'response'>('request');
  const resp = exchange.response;
  const status = resp?.status ?? null;
  const tone = status === null ? 'slate' : status < 300 ? 'emerald' : status < 500 ? 'amber' : 'slate';
  return (
    <div className="rounded-lg border border-slate-800" data-testid="exchange">
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 px-3 py-2 text-sm">
        <Tag tone="sky">{exchange.method}</Tag>
        <code className="break-all text-slate-200">{exchange.url}</code>
        {status !== null && <Tag tone={tone}>HTTP {status}</Tag>}
        <span className="ml-auto text-xs text-slate-500">#{exchange.index} · {exchange.source_ref}</span>
      </div>
      <div className="flex gap-1 px-3 pt-2" role="tablist">
        {(['request', 'response'] as const).map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
            className={`rounded-md px-2 py-1 text-xs capitalize ${tab === t ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}>{t}</button>
        ))}
      </div>
      <div className="p-3">
        {tab === 'request' ? (
          <Code>{`${exchange.method} ${exchange.path}${Object.keys(exchange.query).length ? '?' + new URLSearchParams(exchange.query) : ''}\n`}
            {Object.entries(exchange.headers).map(([k, v]) => `${k}: ${v}\n`).join('')}
            {exchange.body ? `\n${exchange.body}` : ''}{exchange.body_truncated ? '\n… [truncated]' : ''}</Code>
        ) : resp ? (
          <Code>{`HTTP ${resp.status ?? '?'}\n`}{Object.entries(resp.headers).map(([k, v]) => `${k}: ${v}\n`).join('')}
            {resp.body ? `\n${resp.body}` : '\n(no body captured)'}{resp.body_truncated ? '\n… [truncated]' : ''}</Code>
        ) : <p className="text-sm text-slate-500">No response captured in the evidence.</p>}
      </div>
    </div>
  );
}

const ACTOR_COLOR: Record<string, string> = { owner: '#34d399', attacker: '#fb7185', anonymous: '#94a3b8' };

/** Attack sequence visualization with React Flow. */
export function AttackFlow({ steps }: { steps: ScenarioStep[] }) {
  const nodes: Node[] = steps.map((s, i) => ({
    id: String(s.order),
    position: { x: i * 250, y: s.actor === 'owner' ? 0 : 110 },
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
    data: {
      label: (
        <div className="text-left">
          <div className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: ACTOR_COLOR[s.actor] ?? '#38bdf8' }}>
            {s.order}. {s.actor}{s.repeat > 1 ? ` ×${s.repeat}` : ''}
          </div>
          <div className="mt-0.5 font-mono text-[11px] text-slate-100">{s.method} {s.path}</div>
          <div className="mt-0.5 text-[10px] leading-tight text-slate-400">{s.purpose}</div>
          {s.observed_status != null && <div className="mt-1 text-[10px] text-rose-300">observed: HTTP {s.observed_status}</div>}
        </div>
      ),
    },
    style: { background: '#0b1220', border: `1px solid ${ACTOR_COLOR[s.actor] ?? '#334155'}`, borderRadius: 10, width: 210, padding: 8 },
  }));
  const edges: Edge[] = steps.slice(1).map((s, i) => ({
    id: `e${i}`, source: String(steps[i].order), target: String(s.order), animated: i === steps.length - 2,
    type: 'smoothstep', markerEnd: { type: MarkerType.ArrowClosed, color: '#64748b' }, style: { stroke: '#64748b' },
  }));
  return (
    <div className="h-64 rounded-lg border border-slate-800 bg-slate-950" data-testid="attack-flow">
      <ReactFlow nodes={nodes} edges={edges} fitView nodesDraggable={false} proOptions={{ hideAttribution: true }}>
        <Background color="#1e293b" gap={18} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

function AssertionRow({ a }: { a: AssertionResult }) {
  return (
    <li className="flex items-start gap-2 text-sm">
      <span className={a.passed ? 'text-emerald-400' : 'text-rose-400'} aria-label={a.passed ? 'passed' : 'failed'}>{a.passed ? '✓' : '✗'}</span>
      <span className="text-slate-200">{a.description || a.type}</span>
      <span className="ml-auto shrink-0 font-mono text-xs text-slate-500">{a.detail}</span>
    </li>
  );
}

export function StepResults({ steps }: { steps: StepResult[] }) {
  return (
    <ol className="space-y-3">
      {steps.map((s) => (
        <li key={s.id} className="rounded-lg border border-slate-800 p-3">
          <div className="mb-2 flex flex-wrap items-center gap-2 text-sm">
            <Tag tone={s.role === 'probe' ? 'amber' : 'slate'}>{s.role}</Tag>
            <span className="font-medium text-slate-100">{s.name || s.id}</span>
            {s.requests.at(-1) && <span className="font-mono text-xs text-slate-400">→ HTTP {s.requests.at(-1)!.status} · {s.requests.at(-1)!.duration_ms} ms{s.requests.length > 1 ? ` · ${s.requests.length} requests` : ''}</span>}
          </div>
          {s.error && <p className="text-sm text-rose-300">{s.error}</p>}
          <ul className="space-y-1">{[...s.expectations, ...s.assertions].map((a, i) => <AssertionRow key={i} a={a} />)}</ul>
        </li>
      ))}
    </ol>
  );
}

export function DiffPanel({ diff }: { diff: Diff }) {
  return (
    <div className="space-y-4" data-testid="diff">
      {diff.status_only_change && (
        <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-100">
          Only the HTTP status changed. A status change alone does not prove remediation.
        </p>
      )}
      <ul className="list-inside list-disc text-sm text-slate-300">{diff.signals.map((s) => <li key={s}>{s}</li>)}</ul>
      {diff.steps.filter((s) => s.comparable).map((s) => (
        <div key={s.step} className="grid gap-3 md:grid-cols-2">
          {(['before', 'after'] as const).map((side) => (
            <div key={side} className="rounded-lg border border-slate-800 p-3 text-sm">
              <div className="mb-2 text-xs uppercase tracking-wide text-slate-500">{side} · step {s.step}</div>
              <dl className="grid grid-cols-2 gap-y-1 text-slate-300">
                <dt className="text-slate-500">Status</dt><dd className="font-mono">{s.status?.[side]}</dd>
                <dt className="text-slate-500">Auth behaviour</dt><dd>{s.auth_behavior?.[side]}</dd>
                <dt className="text-slate-500">Data exposures</dt><dd className={(s.data_exposure?.[side] ?? 0) > 0 ? 'text-rose-300' : 'text-emerald-300'}>{s.data_exposure?.[side]}</dd>
                <dt className="text-slate-500">Error response</dt><dd>{s.error_response?.[side] ? 'yes' : 'no'}</dd>
                <dt className="text-slate-500">Timing</dt><dd className="font-mono">{s.timing_ms?.[side]} ms</dd>
              </dl>
              {side === 'after' && (s.structure?.removed_fields.length ?? 0) > 0 && (
                <p className="mt-2 text-xs text-emerald-300">Fields no longer returned: {s.structure!.removed_fields.slice(0, 8).join(', ')}</p>
              )}
              {side === 'after' && (s.security_headers?.added.length ?? 0) > 0 && (
                <p className="mt-2 text-xs text-emerald-300">Headers added: {s.security_headers!.added.join(', ')}</p>
              )}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

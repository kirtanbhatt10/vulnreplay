import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../App';
import { ExchangeViewer, DiffPanel, StepResults } from '../components/viewers';
import { ClassificationBadge } from '../components/ui';
import { SessionProvider } from '../state';
import type { Exchange } from '../api';

type Handler = (url: string, init?: RequestInit) => { status?: number; body: unknown } | undefined;

const PROJECT = { id: 'p1', name: 'Demo lab', description: '', created_at: '2026-11-21T10:00:00Z', stats: { evidence: 1, findings: 1, tests: 1, executions: 2 } };
const USER = { id: 'u1', email: 'analyst@example.test', role: 'analyst', is_active: true, created_at: '' };
const DASH = {
  counts: { projects: 1, evidence: 3, findings: 4, tests: 2, approved_tests: 2, executions: 5 },
  latest_status_by_test: { regression_detected: 1, remediation_verified: 1 },
  findings_by_severity: { high: 3, medium: 1 },
  recent_executions: [{ id: 'e1', label: 'baseline', test_version: 1, classification: 'vulnerability_reproduced', is_baseline: true, created_at: '2026-11-21T10:00:00Z' }],
};

function mockFetch(extra: Handler = () => undefined) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const custom = extra(url, init);
    const route = custom ?? (
      url.endsWith('/auth/login') ? { body: { access_token: 'tok', user: USER } }
        : url.endsWith('/auth/me') ? { body: USER }
          : url.endsWith('/projects') ? { body: [PROJECT] }
            : url.includes('/dashboard') ? { body: DASH }
              : { body: [] });
    return new Response(JSON.stringify(route.body), { status: route.status ?? 200, headers: { 'content-type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fn);
  return calls;
}

function renderApp(path = '/') {
  return render(<MemoryRouter initialEntries={[path]}><SessionProvider><App /></SessionProvider></MemoryRouter>);
}

beforeEach(() => { sessionStorage.clear(); localStorage.clear(); vi.unstubAllGlobals(); });

describe('authentication', () => {
  it('logs in and shows the dashboard with real API numbers', async () => {
    const calls = mockFetch();
    renderApp();
    await userEvent.type(screen.getByLabelText('Email'), 'analyst@example.test');
    await userEvent.type(screen.getByLabelText('Password'), 'analyst-password-123');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
    expect(await screen.findByText('Regression detected')).toBeInTheDocument();
    expect(screen.getByText('Evidence files').nextSibling).toHaveTextContent('3');
    expect(sessionStorage.getItem('vulnreplay.token')).toBe('tok');
    const dashCall = calls.find((c) => c.url.includes('/dashboard'));
    expect(new Headers(dashCall?.init?.headers).get('Authorization')).toBe('Bearer tok');
  });

  it('shows the API error on failed login', async () => {
    mockFetch((url) => (url.endsWith('/auth/login') ? { status: 401, body: { detail: 'Invalid credentials' } } : undefined));
    renderApp();
    await userEvent.type(screen.getByLabelText('Email'), 'x@example.test');
    await userEvent.type(screen.getByLabelText('Password'), 'wrong-password');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid credentials');
  });
});

describe('navigation and pages', () => {
  beforeEach(() => sessionStorage.setItem('vulnreplay.token', 'tok'));

  it('renders all eleven navigation entries and navigates', async () => {
    mockFetch();
    renderApp();
    const nav = await screen.findByRole('navigation', { name: 'Main' });
    expect(within(nav).getAllByRole('link')).toHaveLength(11);
    await userEvent.click(within(nav).getByRole('link', { name: /Regression Library/ }));
    expect(await screen.findByRole('heading', { name: 'Regression Library' })).toBeInTheDocument();
    await userEvent.click(within(nav).getByRole('link', { name: /CI\/CD Integrations/ }));
    expect(await screen.findByText(/vulnreplay run regression-library/)).toBeInTheDocument();
  });

  it('shows a loading state, then an error state from the API', async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => { release = r; });
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/dashboard')) { await gate; return new Response(JSON.stringify({ detail: 'database unavailable' }), { status: 500, headers: { 'content-type': 'application/json' } }); }
      const body = url.endsWith('/auth/me') ? USER : url.endsWith('/projects') ? [PROJECT] : [];
      return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
    }));
    renderApp();
    expect(await screen.findByRole('status')).toHaveTextContent('Loading');
    release();
    expect(await screen.findByRole('alert')).toHaveTextContent('database unavailable');
  });

  it('uploads an evidence file as multipart form data', async () => {
    const calls = mockFetch((url, init) => (url.endsWith('/projects/p1/evidence') && init?.method === 'POST'
      ? { status: 201, body: { id: 'ev1', filename: 'x.har', format: 'har', exchange_count: 2, findings: [], sha256: 'a'.repeat(64), size_bytes: 10, created_at: '', provenance: {} } }
      : undefined));
    renderApp('/evidence');
    const input = await screen.findByLabelText('Evidence file');
    await userEvent.upload(input, new File(['{"log":{"entries":[]}}'], 'x.har', { type: 'application/json' }));
    await userEvent.click(screen.getByRole('button', { name: 'Import evidence' }));
    expect(await screen.findByText(/Imported x.har: 2 exchange/)).toBeInTheDocument();
    const post = calls.find((c) => c.init?.method === 'POST');
    expect(post?.init?.body).toBeInstanceOf(FormData);
    expect((post?.init?.body as FormData).get('format')).toBe('auto');
  });

  it('shows upload validation errors from the server', async () => {
    mockFetch((url, init) => (init?.method === 'POST' && url.includes('/evidence') ? { status: 422, body: { detail: 'Binary, archive or serialized-object uploads are not accepted' } } : undefined));
    renderApp('/evidence');
    await userEvent.upload(await screen.findByLabelText('Evidence file'), new File(['x'], 'x.pkl'));
    await userEvent.click(screen.getByRole('button', { name: 'Import evidence' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('serialized-object');
  });

  it('submits the new-project form', async () => {
    const calls = mockFetch((url, init) => (url.endsWith('/projects') && init?.method === 'POST' ? { status: 201, body: { ...PROJECT, id: 'p2', name: 'Payments API' } } : undefined));
    renderApp('/projects');
    const form = (await screen.findByRole('heading', { name: 'New project' })).closest('section')!;
    await userEvent.type(within(form).getByLabelText('Name'), 'Payments API');
    await userEvent.click(within(form).getByRole('button', { name: 'Create project' }));
    await waitFor(() => expect(calls.some((c) => c.init?.method === 'POST' && JSON.parse(String(c.init.body)).name === 'Payments API')).toBe(true));
  });
});

describe('evidence and regression rendering', () => {
  const ex: Exchange = {
    index: 0, method: 'GET', url: 'http://localhost:8001/api/invoices/1001', path: '/api/invoices/1001',
    headers: { Authorization: '[REDACTED]' }, cookies: {}, query: {}, body: null, body_truncated: false, timestamp: null,
    source_ref: 'items/item[0]', response: { status: 200, headers: {}, body: '<img src=x onerror=alert(1)>alice@lab.vulnreplay.test', body_truncated: false },
  };

  it('renders evidence as inert text, never HTML', async () => {
    const { container } = render(<ExchangeViewer exchange={ex} />);
    expect(screen.getByText('HTTP 200')).toBeInTheDocument();
    expect(screen.getByText(/\[REDACTED\]/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: 'response' }));
    expect(screen.getByText(/onerror=alert/)).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
  });

  it('renders each classification distinctly', () => {
    render(<>{(['vulnerability_reproduced', 'remediation_verified', 'regression_detected', 'inconclusive', 'execution_failed'] as const).map((c) => <ClassificationBadge key={c} value={c} />)}</>);
    expect(screen.getAllByTestId('classification').map((n) => n.textContent)).toEqual([
      '●Vulnerability reproduced', '✓Remediation verified', '▲Regression detected', '?Inconclusive', '×Execution failed']);
  });

  it('renders step assertions and a before/after diff', () => {
    render(<StepResults steps={[{ id: 'cross_user_access', name: 'other user', role: 'probe', error: null, expectations: [],
      requests: [{ url: '', status: 404, duration_ms: 3, headers: {}, security_headers: {}, body_preview: '', body_length: 0 }],
      assertions: [{ type: 'status_in', description: 'access denied', passed: true, detail: 'status 404' }, { type: 'body_not_contains', description: 'email hidden', passed: false, detail: 'present' }] }]} />);
    expect(screen.getByLabelText('passed')).toBeInTheDocument();
    expect(screen.getByLabelText('failed')).toBeInTheDocument();
    render(<DiffPanel diff={{ signals: ['p: status 200 -> 403'], status_only_change: true, meaningful_change: false,
      steps: [{ step: 'p', comparable: true, status: { before: 200, after: 403, changed: true }, auth_behavior: { before: 'allowed', after: 'denied' }, data_exposure: { before: 1, after: 1 } }] }} />);
    expect(screen.getByText(/status change alone does not prove remediation/)).toBeInTheDocument();
  });
});

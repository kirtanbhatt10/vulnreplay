// Typed client for the VulnReplay REST API. The bearer token is kept in sessionStorage only.

export type Role = 'admin' | 'analyst' | 'viewer';
export type Classification =
  | 'vulnerability_reproduced'
  | 'remediation_verified'
  | 'regression_detected'
  | 'inconclusive'
  | 'execution_failed';

export interface User { id: string; email: string; role: Role; is_active: boolean; created_at: string }
export interface Project {
  id: string; name: string; description: string; created_at: string;
  stats?: { evidence: number; findings: number; tests: number; executions: number };
}
export interface Target {
  id: string; project_id: string; name: string; base_url: string; environment: string;
  authorized: boolean; authorization_note: string; allow_private_network: boolean; created_at: string;
}
export interface Exchange {
  index: number; method: string; url: string; path: string; headers: Record<string, string>;
  cookies: Record<string, string>; query: Record<string, string>; body: string | null; body_truncated: boolean;
  timestamp: string | null; source_ref: string;
  response: { status: number | null; headers: Record<string, string>; body: string | null; body_truncated: boolean } | null;
}
export interface Evidence {
  id: string; filename: string; format: string; sha256: string; size_bytes: number; created_at: string;
  exchange_count: number; provenance: Record<string, unknown>; exchanges?: Exchange[]; findings?: Finding[];
}
export interface Finding {
  id: string; title: string; category: string; severity: string; description: string; cwe: string | null;
  source_tool: string; evidence_id: string | null; exchange_indexes: number[]; status: string; created_at: string;
  exchanges?: Exchange[];
}
export interface ScenarioStep {
  order: number; actor: string; purpose: string; method: string; path: string; evidence_ref: string | null;
  observed_status: number | null; repeat: number; headers: Record<string, string>;
}
export interface ScenarioData {
  scenario_id: string; title: string; category: string; target_endpoint: string; method: string;
  authentication_context: Record<string, string>; preconditions: string[]; request_sequence: ScenarioStep[];
  expected_behavior: string; observed_behavior: string; evidence_references: string[];
  reproduction_instructions: string[]; risk_assessment: { severity: string; impact: string; cwe?: string | null };
  secure_expectations: Assertion[]; sensitive_markers: string[]; multi_step: boolean; review_notes: string[];
}
export interface Scenario { id: string; title: string; category: string; finding_id: string | null; data: ScenarioData; created_at: string }
export interface Assertion { type: string; description?: string; values?: number[]; value?: string; name?: string; path?: string }
export interface StepDef {
  id: string; name: string; role: 'setup' | 'probe' | 'cleanup'; repeat: number;
  request: { method: string; path: string; headers: Record<string, string>; query: Record<string, string> };
  expect: Assertion[]; assert_secure: Assertion[];
}
export interface TestDefinition { id: string; name: string; category: string; severity: string; steps: StepDef[]; secrets: string[]; tags: string[] }
export interface RegressionTest {
  id: string; name: string; category: string; tags: string[]; origin: string; status: string; current_version: number;
  created_at: string; definition?: TestDefinition; versions: { version: number; change_note: string; created_at: string }[];
  latest_classification?: Classification | null; latest_execution_at?: string | null;
}
export interface AssertionResult { type: string; description: string; passed: boolean; detail: string }
export interface RequestRecord {
  url: string; status: number; duration_ms: number; headers: Record<string, string>;
  security_headers: Record<string, boolean>; body_preview: string; body_length: number;
}
export interface StepResult {
  id: string; name: string; role: string; requests: RequestRecord[]; expectations: AssertionResult[];
  assertions: AssertionResult[]; error: string | null; statuses?: number[];
}
export interface DiffStep {
  step: string; comparable: boolean; status?: { before: number; after: number; changed: boolean };
  auth_behavior?: { before: string; after: string }; structure?: { removed_fields: string[]; added_fields: string[] };
  security_headers?: { added: string[]; removed: string[] }; error_response?: { before: boolean; after: boolean };
  data_exposure?: { before: number; after: number }; timing_ms?: { before: number; after: number };
}
export interface Diff { steps: DiffStep[]; signals: string[]; status_only_change: boolean; meaningful_change: boolean }
export interface Execution {
  id: string; test_id: string; target_id: string; test_version: number; label: string; status: string;
  state: string | null; classification: Classification | null; is_baseline: boolean; created_at: string;
  finished_at: string | null; target_name: string | null; test_name: string | null;
  summary?: { assertions_passed: number; assertions_total: number } | null;
  result?: { state: string; error: string | null; steps: StepResult[]; log: string[]; request_count: number;
             summary: { assertions_passed: number; assertions_total: number } };
  comparison?: { baseline_id: string | null; reasons: string[]; diff: Diff | null };
}
export interface Dashboard {
  counts: Record<string, number>; latest_status_by_test: Record<string, number>;
  findings_by_severity: Record<string, number>; recent_executions: Execution[];
}
export interface AssistantAnswer {
  summary: string; verified_facts: string[]; hypotheses: string[]; suggested_tests: string[]; unknowns: string[];
  recommendations: string[]; confidence: string; provider: string; grounding_notes: string[];
}
export interface AppSettings {
  environment: string; allowed_hosts: string[]; max_upload_bytes: number; request_timeout_seconds: number;
  max_requests_per_execution: number; min_request_interval_ms: number; llm_enabled: boolean; llm_model: string | null;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

const TOKEN_KEY = 'vulnreplay.token';
export const tokenStore = {
  get: (): string | null => sessionStorage.getItem(TOKEN_KEY),
  set: (t: string) => sessionStorage.setItem(TOKEN_KEY, t),
  clear: () => sessionStorage.removeItem(TOKEN_KEY),
};

function detailToMessage(detail: unknown): string {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map((d) => (typeof d === 'object' && d && 'msg' in d ? String(d.msg) : String(d))).join('; ');
  return 'Request failed';
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = tokenStore.get();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  const res = await fetch(`/api/v1${path}`, { ...init, headers });
  if (res.status === 401 && token) tokenStore.clear();
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try { message = detailToMessage((await res.json()).detail); } catch { /* not JSON */ }
    throw new ApiError(res.status, message);
  }
  const type = res.headers.get('content-type') ?? '';
  return (type.includes('application/json') ? res.json() : res.text()) as Promise<T>;
}

export async function download(path: string, filename: string): Promise<void> {
  const token = tokenStore.get();
  const res = await fetch(`/api/v1${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!res.ok) throw new ApiError(res.status, 'Download failed');
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const post = <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
const patch = <T>(path: string, body: unknown) => request<T>(path, { method: 'PATCH', body: JSON.stringify(body) });

export const api = {
  login: (email: string, password: string) => post<{ access_token: string; user: User }>('/auth/login', { email, password }),
  me: () => request<User>('/auth/me'),
  dashboard: (projectId?: string) => request<Dashboard>(`/dashboard${projectId ? `?project_id=${projectId}` : ''}`),
  settings: () => request<AppSettings>('/settings'),
  projects: () => request<Project[]>('/projects'),
  createProject: (name: string, description: string) => post<Project>('/projects', { name, description }),
  targets: (pid: string) => request<Target[]>(`/projects/${pid}/targets`),
  createTarget: (pid: string, body: { name: string; base_url: string; environment: string }) => post<Target>(`/projects/${pid}/targets`, body),
  authorizeTarget: (tid: string, body: { authorized: boolean; authorization_note: string; allow_private_network: boolean }) =>
    post<Target>(`/targets/${tid}/authorization`, body),
  evidence: (pid: string) => request<Evidence[]>(`/projects/${pid}/evidence`),
  evidenceDetail: (id: string) => request<Evidence>(`/evidence/${id}`),
  uploadEvidence: (pid: string, file: File, format: string) => {
    const fd = new FormData();
    fd.append('file', file);
    fd.append('format', format);
    return request<Evidence>(`/projects/${pid}/evidence`, { method: 'POST', body: fd });
  },
  findings: (pid: string, params: { severity?: string; category?: string } = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v) as [string, string][]).toString();
    return request<Finding[]>(`/projects/${pid}/findings${qs ? `?${qs}` : ''}`);
  },
  finding: (id: string) => request<Finding>(`/findings/${id}`),
  createFinding: (pid: string, body: Partial<Finding>) => post<Finding>(`/projects/${pid}/findings`, body),
  updateFinding: (id: string, body: { status?: string }) => patch<Finding>(`/findings/${id}`, body),
  scenarios: (pid: string) => request<Scenario[]>(`/projects/${pid}/scenarios`),
  scenario: (id: string) => request<Scenario>(`/scenarios/${id}`),
  reconstruct: (pid: string, findingId: string, options: Record<string, unknown>) =>
    post<Scenario>(`/projects/${pid}/scenarios`, { finding_id: findingId, options }),
  generate: (pid: string, scenarioId: string, useAi: boolean) => post<RegressionTest>(`/projects/${pid}/tests/generate`, { scenario_id: scenarioId, use_ai: useAi }),
  tests: (pid: string, params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
    return request<RegressionTest[]>(`/projects/${pid}/tests${qs ? `?${qs}` : ''}`);
  },
  test: (id: string) => request<RegressionTest>(`/tests/${id}`),
  renderTest: (id: string, format: string) => request<string>(`/tests/${id}/render?format=${format}`),
  approveTest: (id: string) => post<RegressionTest>(`/tests/${id}/approve`),
  executions: (pid: string, testId?: string) => request<Execution[]>(`/projects/${pid}/executions${testId ? `?test_id=${testId}` : ''}`),
  execution: (id: string) => request<Execution>(`/executions/${id}`),
  execute: (body: { test_id: string; target_id: string; label: string }) => post<Execution>('/executions', body),
  cancel: (id: string) => post<{ cancel_requested: boolean }>(`/executions/${id}/cancel`),
  compare: (before: string, after: string) => request<{ before: Execution; after: Execution; diff: Diff }>(`/compare?before=${before}&after=${after}`),
  assistant: (body: { task: string; finding_id?: string; execution_id?: string }) => post<AssistantAnswer>('/assistant', body),
  users: () => request<User[]>('/users'),
  createUser: (body: { email: string; password: string; role: Role }) => post<User>('/users', body),
  audit: () => request<{ id: string; action: string; subject: string; actor_id: string | null; created_at: string }[]>('/audit?limit=50'),
};

import * as mock from '../mocks/data';
import { adaptAlarm, adaptCfg, adaptDetector, adaptDiagnostic, adaptEvaluation, adaptEvaluationCase, adaptEvaluationMatrix, adaptIr, adaptProject, adaptRulePack, adaptRun, adaptSourceFile, adaptStates, adaptTrace, mapPage } from './adapters';
import type { components } from '../types/openapi.generated';
import type { Alarm, AlarmSeverity, BlockState, Diagnostic, DetectorDescriptor, Evaluation, EvaluationCase, EvaluationMatrix, Page, Project, ProjectCreate, RulePackDescriptor, Run, RunCreate, RunIr, SourceFile, TraceEvent } from '../types/generated';

const useMock = import.meta.env.VITE_USE_MOCK !== 'false';
export const apiModeLabel = useMock ? 'Mock API' : '真实 API';
const apiBase = import.meta.env.VITE_API_BASE ?? '/api/v1';
export interface PageQuery { limit?: number; offset?: number }
export const normalizePageQuery = (query: PageQuery = {}) => ({ limit: Math.min(Math.max(Math.trunc(query.limit ?? 50), 1), 500), offset: Math.max(Math.trunc(query.offset ?? 0), 0) });
const page = <T,>(items: T[], query?: PageQuery): Page<T> => { const { limit, offset } = normalizePageQuery(query); return { items: items.slice(offset, offset + limit), total: items.length, limit, offset }; };
const queryParams = (query?: PageQuery) => { const { limit, offset } = normalizePageQuery(query); return `?limit=${limit}&offset=${offset}`; };
const filteredQueryParams = (query: Record<string, unknown> = {}, pageQuery?: PageQuery) => {
  const { limit, offset } = normalizePageQuery(pageQuery);
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value));
  });
  return `?${params.toString()}`;
};
export class ApiError extends Error { constructor(public readonly status: number, public readonly code: string, message: string, public readonly details: unknown = {}) { super(message); this.name = 'ApiError'; } }
async function parseError(response: Response): Promise<never> { let payload: unknown; try { payload = await response.json(); } catch { payload = undefined; } const body = payload as { error?: { code?: string; message?: string; details?: unknown }; detail?: string } | undefined; throw new ApiError(response.status, body?.error?.code ?? `HTTP_${response.status}`, body?.error?.message ?? body?.detail ?? `请求失败（${response.status}）`, body?.error?.details ?? {}); }
async function request<T, R = T>(path: string, fallback: R, map?: (value: T) => R): Promise<R> {
  if (useMock) return new Promise(resolve => setTimeout(() => resolve(fallback), 180));
  const response = await fetch(`${apiBase}${path}`);
  if (!response.ok) return parseError(response);
  const raw = await response.json() as T;
  return map ? map(raw) : raw as unknown as R;
}
export const api = {
  listProjects: (query?: PageQuery) => request<components['schemas']['Page_ProjectOut_'], Page<Project>>(`/projects${queryParams(query)}`, page(mock.projects, query), raw => mapPage(raw, adaptProject)),
  getProject: (id: string) => request<components['schemas']['ProjectOut'], Project>(`/projects/${id}`, mock.projects.find(p => p.id === id) ?? mock.projects[0], adaptProject),
  deleteProject: async (id: string) => {
    if (useMock) { const index = mock.projects.findIndex(project => project.id === id); if (index >= 0) mock.projects.splice(index, 1); return; }
    const response = await fetch(`${apiBase}/projects/${id}`, { method: 'DELETE' }); if (!response.ok) return parseError(response);
  },
  createProject: async (input: ProjectCreate) => {
    if (useMock) { const created: Project = { id: `proj-${Date.now()}`, name: input.name, description: input.description ?? '', file_count: 0, updated_at: new Date().toISOString() }; mock.projects.unshift(created); return created; }
    const response = await fetch(`${apiBase}/projects`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) }); if (!response.ok) return parseError(response); return adaptProject(await response.json() as components['schemas']['ProjectOut']);
  },
  uploadFile: async (projectId: string, file: File) => {
    if (useMock) return { id: `file-${Date.now()}`, project_id: projectId, path: file.name, language: file.name.endsWith('.h') ? 'c-header' : 'c', sha256: 'mock-sha256', size_bytes: file.size, created_at: new Date().toISOString() } satisfies SourceFile;
    const body = new FormData(); body.append('file', file); body.append('path', file.name); const response = await fetch(`${apiBase}/projects/${projectId}/files`, { method: 'POST', body }); if (!response.ok) return parseError(response); return adaptSourceFile(await response.json() as components['schemas']['SourceFileOut']);
  },
  listProjectFiles: (projectId: string, query?: PageQuery) => request<components['schemas']['Page_SourceFileOut_'], Page<SourceFile>>(`/projects/${projectId}/files${queryParams(query)}`, page([], query), raw => mapPage(raw, adaptSourceFile)),
  listProjectRuns: (id: string, query?: PageQuery) => request<components['schemas']['Page_RunOut_'], Page<Run>>(`/projects/${id}/runs${queryParams(query)}`, page(mock.runs.filter(r => r.project_id === id), query), raw => mapPage(raw, adaptRun)),
  getRun: async (id: string) => { if (useMock) return new Promise<Run>(resolve => setTimeout(() => resolve(mock.runs.find(r => r.id === id) ?? mock.runs[0]), 180)); const [runResponse, summaryResponse] = await Promise.all([fetch(`${apiBase}/runs/${id}`), fetch(`${apiBase}/runs/${id}/summary`)]); if (!runResponse.ok) return parseError(runResponse); if (!summaryResponse.ok) return parseError(summaryResponse); return adaptRun(await runResponse.json() as components['schemas']['RunOut'], await summaryResponse.json() as components['schemas']['SummaryOut']); },
  listDetectors: (query?: PageQuery) => request<components['schemas']['Page_DetectorDescriptor_'], Page<DetectorDescriptor>>(`/detectors${queryParams(query)}`, page(mock.detectors, query), raw => mapPage(raw, adaptDetector)),
  listRulePacks: (detectorId?: string, query?: PageQuery) => request<components['schemas']['Page_RulePackDescriptor_'], Page<RulePackDescriptor>>(`/rule-packs${detectorId ? `?detector_id=${detectorId}&limit=${normalizePageQuery(query).limit}&offset=${normalizePageQuery(query).offset}` : queryParams(query)}`, page(mock.rulePacks.filter(r => !detectorId || r.detector_id === detectorId), query), raw => mapPage(raw, adaptRulePack)),
  listAlarms: (runId: string, query?: { detector_id?: string; rule_pack_id?: string; cwe_id?: string; family?: string; violation_kind?: string; severity?: AlarmSeverity; function?: string; limit?: number; offset?: number }) => {
    let items = mock.alarms.filter(a => a.run_id === runId);
    if (query) Object.entries(query).forEach(([key, value]) => { if (value) items = items.filter(item => String(item[key as keyof Alarm]) === value); });
    const { limit, offset, ...filters } = query ?? {};
    return request<components['schemas']['Page_AlarmOut_'], Page<Alarm>>(`/runs/${runId}/alarms${filteredQueryParams(filters, { limit, offset })}`, page(items, { limit, offset }), raw => mapPage(raw, adaptAlarm));
  },
  listDiagnostics: (runId: string, query?: PageQuery & { severity?: Diagnostic['severity'] }) => request<components['schemas']['Page_DiagnosticOut_'], Page<Diagnostic>>(`/runs/${runId}/diagnostics${filteredQueryParams({ severity: query?.severity }, query)}`, page(mock.diagnostics.filter(d => d.run_id === runId && (!query?.severity || d.severity === query.severity)), query), raw => mapPage(raw, adaptDiagnostic)),
  getRunCfg: (runId: string, functionName?: string) => request<Record<string, unknown>, ReturnType<typeof adaptCfg>>(`/runs/${runId}/cfg${functionName ? `?function=${encodeURIComponent(functionName)}` : ''}`, adaptCfg({ nodes: mock.cfgNodes, edges: mock.cfgEdges }), adaptCfg),
  getBlockStates: (runId: string, functionName?: string, blockId?: string) => request<any, Page<BlockState>>(`/runs/${runId}/states${functionName || blockId ? `?${new URLSearchParams({ ...(functionName ? { function: functionName } : {}), ...(blockId ? { block_id: blockId } : {}) })}` : ''}`, page(mock.states), adaptStates),
  getRunIr: (runId: string, functionName?: string) => request<any, RunIr>(`/runs/${runId}/ir${functionName ? `?function=${encodeURIComponent(functionName)}` : ''}`, mock.ir, adaptIr),
  listTrace: (runId: string, functionName?: string, blockId?: string, after = -1) => request<any, TraceEvent[]>(`/runs/${runId}/trace?${new URLSearchParams({ ...(functionName ? { function: functionName } : {}), ...(blockId ? { block_id: blockId } : {}), after: String(after) })}`, mock.trace, adaptTrace),
  listProjectEvaluations: (projectId: string) => request<components['schemas']['Page_EvaluationOut_'], Page<Evaluation>>(`/projects/${projectId}/evaluations`, page([mock.evaluation]), raw => mapPage(raw, adaptEvaluation)),
  getEvaluation: (evaluationId: string) => request<components['schemas']['EvaluationOut'], Evaluation>(`/evaluations/${evaluationId}`, mock.evaluation, adaptEvaluation),
  listEvaluationCases: (evaluationId: string, query?: { detector_id?: string; rule_pack_id?: string; cwe_id?: string; family?: string; violation_kind?: string }) => { const params = new URLSearchParams(Object.entries(query ?? {}).filter(([, value]) => Boolean(value)) as [string, string][]); return request<components['schemas']['Page_EvaluationCaseOut_'], Page<EvaluationCase>>(`/evaluations/${evaluationId}/cases${params.size ? `?${params}` : ''}`, { items: [], total: 0, limit: 50, offset: 0 }, raw => mapPage(raw, adaptEvaluationCase)); },
  getEvaluationMatrix: (evaluationId: string, query?: { cwe_id?: string; family?: string }) => { const params = new URLSearchParams(Object.entries(query ?? {}).filter(([, value]) => Boolean(value)) as [string, string][]); return request<components['schemas']['MatrixOut'], EvaluationMatrix>(`/evaluations/${evaluationId}/matrix${params.size ? `?${params}` : ''}`, { detector_id: 'stack-bounds', rule_pack_id: 'cwe121-core', cwe_id: query?.cwe_id ?? null, family: query?.family ?? null, correct: mock.evaluation.matrix.correctly_classified, false_positive: mock.evaluation.matrix.false_positive, false_negative: mock.evaluation.matrix.false_negative, inverted: mock.evaluation.matrix.inverted, unsupported: 0, error: 0, total: 628, bad_recall: mock.evaluation.metrics.bad_recall / 100, good_specificity: mock.evaluation.metrics.good_silent_rate / 100, file_accuracy: mock.evaluation.metrics.file_accuracy / 100 }, adaptEvaluationMatrix); },
  createRun: async (projectId: string, input: RunCreate) => { if (useMock) return mock.runs[0]; const response = await fetch(`${apiBase}/projects/${projectId}/runs`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) }); if (!response.ok) return parseError(response); return adaptRun(await response.json() as components['schemas']['RunOut']); },
  cancelRun: async (runId: string) => { if (useMock) return { ok: true }; const response = await fetch(`${apiBase}/runs/${runId}/cancel`, { method: 'POST' }); if (!response.ok) return parseError(response); return adaptRun(await response.json() as components['schemas']['RunOut']); },
  rerun: async (run: Run) => api.createRun(run.project_id, { file_ids: run.file_ids, detector_id: run.detector_id, rule_pack_id: run.rule_pack_id, mode: run.mode }),
  subscribeRunEvents: (runId: string, onEvent: (event: { type: string; data: unknown }) => void) => {
    if (useMock) { const timer = window.setTimeout(() => onEvent({ type: 'run.completed', data: { run_id: runId } }), 2200); return () => window.clearTimeout(timer); }
    const source = new EventSource(`${apiBase}/runs/${runId}/events`);
    const eventTypes = ['run.started', 'trace.event', 'alarm.created', 'diagnostic.created', 'run.completed', 'run.failed', 'run.cancelled'] as const;
    const listeners = eventTypes.map(type => {
      const listener = (event: Event) => {
        const message = event as MessageEvent<string>;
        let data: unknown = message.data;
        try { data = JSON.parse(message.data); } catch { /* Preserve non-JSON event data. */ }
        onEvent({ type, data });
      };
      source.addEventListener(type, listener);
      return [type, listener] as const;
    });
    return () => { listeners.forEach(([type, listener]) => source.removeEventListener(type, listener)); source.close(); };
  }
};

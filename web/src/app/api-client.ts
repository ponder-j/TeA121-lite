import * as mock from '../mocks/data';
import { adaptAlarm, adaptCfg, adaptDetector, adaptDiagnostic, adaptEvaluation, adaptEvaluationCase, adaptEvaluationMatrix, adaptIr, adaptProject, adaptRulePack, adaptRun, adaptSourceFile, adaptSourceFileDetail, adaptStates, adaptTrace, mapPage } from './adapters';
import type { components } from '../types/openapi.generated';
import type { Alarm, AlarmSeverity, BlockState, Diagnostic, DetectorDescriptor, Evaluation, EvaluationCase, EvaluationMatrix, Page, Project, ProjectCreate, RulePackDescriptor, Run, RunCreate, RunIr, SourceFile, SourceFileDetail, TraceEvent } from '../types/generated';

const useMock = import.meta.env.VITE_USE_MOCK !== 'false';
export const apiModeLabel = useMock ? 'Mock API' : '真实 API';
const apiBase = import.meta.env.VITE_API_BASE ?? '/api/v1';
let mockSequence = 0;
const mockId = (prefix: string) => `${prefix}-${Date.now()}-${++mockSequence}`;
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
    if (useMock) { const id = mockId('proj'); const created: Project = { id, name: input.name, description: input.description ?? '', file_count: input.debug_mode ? 1 : 0, updated_at: new Date().toISOString(), debug_mode: Boolean(input.debug_mode) }; if (input.debug_mode) mock.sourceFiles.unshift({ id: mockId('file'), project_id: id, path: 'blank.c', language: 'c', sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', size_bytes: 0, created_at: new Date().toISOString(), content: '' }); mock.projects.unshift(created); return created; }
    const response = await fetch(`${apiBase}/projects`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) }); if (!response.ok) return parseError(response); return adaptProject(await response.json() as components['schemas']['ProjectOut']);
  },
  uploadFile: async (projectId: string, file: File) => {
    if (useMock) { const content = await file.text(); const uploaded: SourceFile = { id: mockId('file'), project_id: projectId, path: file.name, language: file.name.endsWith('.h') ? 'c-header' : 'c', sha256: `mock-sha-${file.name}-${file.size}`, size_bytes: file.size, created_at: new Date().toISOString() }; mock.sourceFiles.unshift({ ...uploaded, content }); const project = mock.projects.find(item => item.id === projectId); if (project) project.file_count += 1; return uploaded; }
    const body = new FormData(); body.append('file', file); body.append('path', file.name); const response = await fetch(`${apiBase}/projects/${projectId}/files`, { method: 'POST', body }); if (!response.ok) return parseError(response); return adaptSourceFile(await response.json() as components['schemas']['SourceFileOut']);
  },
  listProjectFiles: (projectId: string, query?: PageQuery) => request<components['schemas']['Page_SourceFileOut_'], Page<SourceFile>>(`/projects/${projectId}/files${queryParams(query)}`, page(mock.sourceFiles.filter(file => file.project_id === projectId), query), raw => mapPage(raw, adaptSourceFile)),
  getSourceFile: (projectId: string, fileId: string) => request<components['schemas']['SourceFileDetailOut'], SourceFileDetail>(`/projects/${projectId}/files/${fileId}`, mock.sourceFiles.find(file => file.project_id === projectId && file.id === fileId) ?? mock.sourceFiles[0], adaptSourceFileDetail),
  updateSourceFile: async (projectId: string, fileId: string, content: string) => {
    if (useMock) { const current = mock.sourceFiles.find(file => file.project_id === projectId && file.id === fileId) ?? mock.sourceFiles[0]; if (current.content === content) return current; const revision: SourceFileDetail = { ...current, id: mockId('file'), sha256: `mock-sha-${mockSequence}`, size_bytes: new Blob([content]).size, created_at: new Date().toISOString(), content }; mock.sourceFiles.unshift(revision); return revision; }
    const response = await fetch(`${apiBase}/projects/${projectId}/files/${fileId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content }) }); if (!response.ok) return parseError(response); return adaptSourceFileDetail(await response.json() as components['schemas']['SourceFileDetailOut']);
  },
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
  createRun: async (projectId: string, input: RunCreate) => { if (useMock) { const template = mock.runs.find(run => run.project_id === projectId) ?? mock.runs[0]; const created: Run = { ...template, id: mockId('run'), project_id: projectId, status: 'succeeded', progress: 100, created_at: new Date().toISOString(), completed_at: new Date().toISOString(), file_ids: input.file_ids ?? [], detector_id: input.detector_id, detector_version: input.detector_version ?? template.detector_version, rule_pack_id: input.rule_pack_id, rule_pack_version: input.rule_pack_version ?? template.rule_pack_version, mode: input.mode ?? 'normal', config: input.config ?? {}, cwe_scope: input.cwe_id ? [input.cwe_id] : [], summary: { alarm_count: 0, diagnostic_count: 0, unsupported_count: 0, error_count: 0 } }; mock.runs.unshift(created); return created; } const response = await fetch(`${apiBase}/projects/${projectId}/runs`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) }); if (!response.ok) return parseError(response); return adaptRun(await response.json() as components['schemas']['RunOut']); },
  cancelRun: async (runId: string) => { if (useMock) return { ok: true }; const response = await fetch(`${apiBase}/runs/${runId}/cancel`, { method: 'POST' }); if (!response.ok) return parseError(response); return adaptRun(await response.json() as components['schemas']['RunOut']); },
  rerun: async (run: Run) => api.createRun(run.project_id, { file_ids: run.file_ids, detector_id: run.detector_id, rule_pack_id: run.rule_pack_id, mode: run.mode, config: run.config }),
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

// UI-facing view models. The source-of-truth OpenAPI output is openapi.generated.ts;
// this file keeps the normalized fields used by the workbench while API adapters are added.
export type RunStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
export type AlarmSeverity = 'definite' | 'possible';
export type DiagnosticSeverity = 'unknown_effect' | 'unsupported' | 'error';
export interface Page<T> { items: T[]; total: number; limit: number; offset: number }
export interface DetectorDescriptor { id: string; version: string; name: string; supported_cwes: string[]; enabled: boolean }
export interface RulePackDescriptor { id: string; detector_id: string; version: string; name: string; supported_cwes: string[]; supported_families: string[]; supported_violation_kinds: string[] }
export interface Project { id: string; name: string; file_count: number; updated_at: string; last_run_id?: string; description: string }
export interface ProjectCreate { name: string; description?: string | null }
export interface SourceFile { id: string; project_id: string; path: string; language: string; sha256: string; size_bytes: number; created_at: string }
export interface RunCreate { file_ids?: string[]; detector_id: string; rule_pack_id: string; detector_version?: string | null; rule_pack_version?: string | null; variant?: string; mode?: 'normal' | 'trace'; config?: Record<string, unknown>; cwe_id?: string | null; family?: string | null; violation_kind?: string | null }
export interface Run { id: string; project_id: string; status: RunStatus; progress: number; duration_ms: number; created_at: string; completed_at?: string; analyzer_version: string; detector_id: string; detector_version: string; rule_pack_id: string; rule_pack_version: string; file_ids: string[]; mode: 'normal' | 'trace'; cwe_scope: string[]; summary: { alarm_count: number; diagnostic_count: number; unsupported_count: number; error_count: number } }
export interface Alarm { id: string; run_id: string; detector_id: string; rule_pack_id: string; cwe_id: string; family: string; violation_kind: string; severity: AlarmSeverity; function: string; message: string; location: { file: string; line: number; column: number }; memory_object_id: string; object_size: { lower: number; upper: number }; offset: { lower: number; upper: number }; access_size_bytes: number; safe_condition: string; reason: string[]; instruction: string; block_id: string }
export interface Diagnostic { id: string; run_id: string; code: string; severity: DiagnosticSeverity; message: string; location?: { file: string; line: number; column: number }; impact: string }
export interface CfgInstruction { id: string; text: string; op?: string; location?: { file?: string; line?: number; column?: number } | null }
export interface CfgTerminator { op?: string; target?: string; true?: string; false?: string; value?: string | number; condition?: string | { predicate?: string; left?: string | number; right?: string | number } }
export interface CfgNode { id: string; label: string; instructions: number; function?: string; kind?: string; displayIndex?: number; ir?: CfgInstruction[]; terminator?: CfgTerminator; sourceLines?: number[] }
export interface CfgEdge { source: string; target: string; function?: string; condition?: string; polarity?: 'true' | 'false' }
export interface RunArtifact { id: string; kind: string; source_file_id?: string; function_name?: string; sha256?: string; size_bytes?: number; content?: string }
export interface RunIr { file: string; source: string; instructions: { id: string; line: number; text: string; block_id: string }[]; artifacts: RunArtifact[] }
export interface BlockState { block_id: string; label: string; function?: string; entry_state: Record<string, string>; exit_state: Record<string, string>; trace_event_ids: string[] }
export interface TraceEvent { sequence: number; instruction_id: string; block_id: string; kind: string; detail: string; line: number }
export interface Evaluation { id: string; project_id: string; dataset: string; status: 'completed' | 'running' | 'failed'; created_at: string; detector_id: string; rule_pack_id: string; matrix: { correctly_classified: number; false_positive: number; false_negative: number; inverted: number }; metrics: { bad_recall: number; good_silent_rate: number; file_accuracy: number }; by_family: { family: string; tp: number; fp: number; fn: number }[]; trend: { version: string; accuracy: number }[] }
export interface EvaluationCase { id: string; evaluation_id: string; case_name: string; cwe_id: string | null; family: string | null; bad_run_id: string | null; good_run_id: string | null; bad_outcome: string; good_outcome: string; classification: string | null }
export interface EvaluationMatrix { detector_id: string; rule_pack_id: string; cwe_id: string | null; family: string | null; correct: number; false_positive: number; false_negative: number; inverted: number; unsupported: number; error: number; total: number; bad_recall: number | null; good_specificity: number | null; file_accuracy: number | null }

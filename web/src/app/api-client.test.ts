import { describe, expect, it } from 'vitest';
import { api } from './api-client';
import { adaptAlarm, adaptCfg, adaptEvaluation, adaptEvaluationMatrix, adaptIr, adaptProject } from './adapters';
import { normalizePageQuery } from './api-client';

describe('mock api contract flows', () => {
  it('filters alarms by every supported query dimension', async () => {
    const result = await api.listAlarms('run-001', { detector_id: 'stack-bounds', rule_pack_id: 'cwe121-core', cwe_id: 'CWE-121', family: 'CWE131_memcpy', violation_kind: 'copy_length_overflow', severity: 'definite', function: 'CWE131_memcpy_01_bad' });
    expect(result.total).toBe(1);
    expect(result.items[0].id).toBe('alarm-001');
  });

  it('creates a project and accepts uploaded files in mock mode', async () => {
    const project = await api.createProject({ name: 'API test project', description: 'contract flow' });
    const file = new File(['int main(void) { return 0; }'], 'test.c', { type: 'text/plain' });
    const uploaded = await api.uploadFile(project.id, file);
    expect(uploaded.project_id).toBe(project.id);
    expect(uploaded.path).toBe('test.c');
  });

  it('deletes a project in mock mode', async () => {
    const project = await api.createProject({ name: 'Delete API test project' });
    await api.deleteProject(project.id);
    const result = await api.listProjects({ limit: 500 });
    expect(result.items.some(item => item.id === project.id)).toBe(false);
  });

  it('normalizes nullable contract fields for the workbench', () => {
    const project = adaptProject({ id: 'p', name: 'demo', description: null, created_at: '2026-09-06T00:00:00Z' });
    expect(project.description).toBe('');
    expect(project.updated_at).toContain('2026-09-06');
    const alarm = adaptAlarm({ id: 'a', run_id: 'r', alarm_key: 'k', detector_id: 'd', detector_version: '1', rule_pack_id: 'rp', rule_pack_version: '1', cwe_id: 'CWE-121', family: null, violation_kind: 'copy_length_overflow', severity: 'possible', function_name: null, block_id: null, instruction_id: null, instruction_text: null, source_file_id: null, source_line: null, memory_object_id: 'obj', object_name: null, object_size: { lower: null, upper: null, is_bottom: false }, offset: { lower: null, upper: null, is_bottom: false }, access_size_bytes: 1, safe_condition: 'safe', message: 'm', reason: [] });
    expect(alarm.function).toBe('unknown');
    expect(alarm.location.line).toBe(0);
    expect(alarm.object_size.upper).toBe(Number.POSITIVE_INFINITY);
  });

  it('normalizes evaluation summary and matrix metrics', async () => {
    const evaluation = adaptEvaluation({ id: 'e', project_id: 'p', dataset_name: 'dataset', dataset_version: '1', detector_id: 'd', detector_version: '1', rule_pack_id: 'rp', rule_pack_version: '1', status: 'completed', filter: {}, summary: { correct: 8, false_positive: 2, false_negative: 1, inverted: 0, bad_recall: 0.8, good_specificity: 0.9, file_accuracy: 0.8 }, created_at: '2026-09-06T00:00:00Z', started_at: null, finished_at: null });
    expect(evaluation.matrix.correctly_classified).toBe(8);
    expect(evaluation.metrics.bad_recall).toBe(80);
    const matrix = await api.getEvaluationMatrix('eval-001', { family: 'CWE131_memcpy' });
    expect(adaptEvaluationMatrix({ detector_id: matrix.detector_id, rule_pack_id: matrix.rule_pack_id, cwe_id: null, family: matrix.family, correct: matrix.correct, false_positive: matrix.false_positive, false_negative: matrix.false_negative, inverted: matrix.inverted, unsupported: matrix.unsupported, error: matrix.error, total: matrix.total, bad_recall: matrix.bad_recall, good_specificity: matrix.good_specificity, file_accuracy: matrix.file_accuracy }).family).toBe('CWE131_memcpy');
  });

  it('clamps pagination values and preserves artifact metadata', async () => {
    expect(normalizePageQuery({ limit: 0, offset: -10 })).toEqual({ limit: 1, offset: 0 });
    expect(normalizePageQuery({ limit: 9999, offset: 2.8 })).toEqual({ limit: 500, offset: 2 });
    const ir = adaptIr({ source_file_path: 'main.c', items: [{ id: 'source-1', kind: 'source', content: 'int main() {}', source_file_id: 'file-1', source_file_path: 'main.c', function_name: null, sha256: 'abc' }, { id: 'ir-1', kind: 'normalized_ir', content: '; ModuleID = \'tmp\'\nsource_filename = "tmp.c"\n  call void @llvm.dbg.declare(metadata ptr %1, metadata !16, metadata !DIExpression()), !dbg !3\nret void, !dbg !3\n!llvm.dbg.cu = !{!0}', source_file_id: null, function_name: 'main', sha256: 'def' }] });
    expect(ir.artifacts).toHaveLength(2);
    expect(ir.artifacts[1].sha256).toBe('def');
    expect(ir.file).toBe('main.c');
    expect(ir.instructions[0].id).toBe('1');
    expect(ir.instructions[0].text).toBe('ret void');
    expect(ir.instructions).toHaveLength(1);
  });

  it('preserves CFG block IR, terminators, source lines, and branch metadata', () => {
    const cfg = adaptCfg({
      nodes: [
        {
          block_id: 'bb0',
          function_name: 'main',
          display_index: 1,
          instructions: [{ id: 'i1', op: 'icmp', text: '%cmp = icmp slt i32 %i, 10', location: { file: 'main.c', line: 7 } }],
          terminator: { op: 'br', condition: '%cmp', true: 'bb1', false: 'bb2' },
          source_lines: [7],
        },
      ],
      edges: [{ source: 'bb0', target: 'bb1', function: 'main', condition: '%cmp', polarity: 'true' }],
    });

    expect(cfg.nodes[0]).toMatchObject({
      id: 'bb0',
      displayIndex: 1,
      instructions: 1,
      sourceLines: [7],
      terminator: { op: 'br', true: 'bb1', false: 'bb2' },
    });
    expect(cfg.nodes[0].ir?.[0].text).toContain('icmp slt');
    expect(cfg.edges[0]).toEqual({ source: 'bb0', target: 'bb1', function: 'main', condition: '%cmp', polarity: 'true' });
  });
});

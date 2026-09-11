import { useEffect, useRef, useState } from 'react';
import { Link, NavLink, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
import { Activity, AlertOctagon, ArrowLeft, BarChart3, Check, ChevronRight, CircleHelp, Clock3, Code2, Database, FileCode2, Filter, GitBranch, LayoutDashboard, Menu, MoreHorizontal, Play, Plus, RefreshCw, RotateCcw, Search, Settings2, ShieldAlert, Square, Terminal, Trash2, Upload, X, Zap } from 'lucide-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api, apiModeLabel } from './app/api-client';
import { useRun } from './hooks/useRun';
import { useRunEvents } from './hooks/useRunEvents';
import { AlarmTable } from './components/AlarmTable';
import { CfgGraph } from './components/CfgGraph';
import { ResizablePanes } from './components/ResizablePanes';
import type { Alarm, AlarmSeverity, CfgNode, Diagnostic, Page, Project, RunStatus } from './types/generated';

const fmtDuration = (ms: number) => ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
const fmtDate = (value: string) => new Intl.DateTimeFormat('zh-CN', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(value));

function Shell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false); const location = useLocation();
  const nav = [{ to: '/', label: '项目', icon: LayoutDashboard }, { to: '/evaluation', label: '评估', icon: BarChart3 }];
  return <div className="app-shell">
    <aside className={`sidebar ${open ? 'sidebar-open' : ''}`}><div className="brand"><div className="brand-mark"><Zap size={17} /></div><div><strong>TeA121</strong><span>LITE ANALYZER</span></div></div><div className="workspace-label">WORKSPACE <span>LOCAL</span></div><nav>{nav.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => isActive || (to !== '/' && location.pathname.startsWith(to)) ? 'active' : ''} onClick={() => setOpen(false)}><Icon size={17} />{label}</NavLink>)}</nav><div className="sidebar-bottom"><div className="engine-card"><div className="status-dot" /><div><b>分析引擎在线</b><small>v0.1.0 · {apiModeLabel}</small></div></div><button className="icon-text subtle"><Settings2 size={15} />工作区设置</button><div className="user-chip"><div className="avatar">LY</div><div><b>Lab workspace</b><small>本地项目</small></div><ChevronRight size={15} /></div></div></aside>
    <main className="main"><header className="topbar"><button className="mobile-menu icon-btn" onClick={() => setOpen(v => !v)} aria-label="打开导航"><Menu size={20} /></button><div className="crumb">{location.pathname === '/' ? '项目总览' : location.pathname.includes('evaluation') ? '评估中心' : location.pathname.includes('/workbench') ? '分析工作台' : '运行详情'}</div><div className="top-actions"><span className="connection"><span className="status-dot" />{apiModeLabel}</span><button className="icon-btn" aria-label="帮助"><CircleHelp size={18} /></button><button className="avatar avatar-small" aria-label="账户">LY</button></div></header><div className="content">{children}</div></main>
  </div>;
}

function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: React.ReactNode }) { return <div className="page-header"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</div>; }
export function StatusBadge({ status }: { status: RunStatus }) { const map: Record<RunStatus, [string, string]> = { queued: ['排队中', 'queued'], running: ['分析中', 'running'], succeeded: ['已完成', 'succeeded'], failed: ['失败', 'failed'], cancelled: ['已取消', 'cancelled'] }; const [label, cls] = map[status]; return <span className={`status-badge ${cls}`}><span className="status-dot" />{label}</span>; }
function SeverityBadge({ severity }: { severity: AlarmSeverity }) { return <span className={`severity ${severity}`}><ShieldAlert size={13} />{severity === 'definite' ? 'DEFINITE' : 'POSSIBLE'}</span>; }

function ProjectCard({ project, menuOpen, onMenuToggle, onDelete }: { project: Project; menuOpen: boolean; onMenuToggle: () => void; onDelete: () => void }) {
  return <article className="project-card">
    <div className="card-top">
      <div className="project-icon"><FileCode2 size={20} /></div>
      <div className="project-menu">
        <button type="button" className="kebab" aria-label={`项目 ${project.name} 操作`} aria-haspopup="menu" aria-expanded={menuOpen} onClick={event => { event.stopPropagation(); onMenuToggle(); }}><MoreHorizontal size={18} /></button>
        {menuOpen && <div className="project-menu-popover" role="menu"><button type="button" role="menuitem" onClick={event => { event.stopPropagation(); onDelete(); }}><Trash2 size={14} />删除</button></div>}
      </div>
    </div>
    <Link className="project-card-body" to={`/projects/${project.id}`}>
      <h2>{project.name}</h2>
      <p>{project.description}</p>
      <div className="project-stats"><span><FileCode2 size={14} />{project.file_count} 个文件</span><span><Clock3 size={14} />{fmtDate(project.updated_at)}</span></div>
      <div className="card-footer"><span>最近运行</span><span className="run-ref"><span className="status-dot succeeded" />{project.last_run_id ? 'run-' + project.last_run_id.slice(-3) : '暂无'}<ChevronRight size={15} /></span></div>
    </Link>
  </article>;
}

function DeleteProjectDialog({ project, deleting, error, onCancel, onConfirm }: { project: Project; deleting: boolean; error: string; onCancel: () => void; onConfirm: () => void }) {
  return <div className="modal-backdrop" onClick={() => { if (!deleting) onCancel(); }}>
    <div className="modal confirm-modal" role="dialog" aria-modal="true" aria-labelledby="delete-project-title" onClick={event => event.stopPropagation()}>
      <div className="modal-header">
        <div><div className="eyebrow danger-eyebrow">DELETE PROJECT</div><h2 id="delete-project-title">确认删除项目？</h2></div>
        <button className="icon-btn" onClick={onCancel} aria-label="关闭" disabled={deleting}><X size={18} /></button>
      </div>
      <div className="delete-warning"><AlertOctagon size={19} /><div><b>{project.name}</b><span>删除后不可恢复。项目的源代码、运行结果、告警、诊断和评估数据都会被永久删除。</span></div></div>
      {error && <div className="form-error" role="alert"><AlertOctagon size={14} />{error}</div>}
      <div className="modal-actions"><button className="secondary-btn" onClick={onCancel} disabled={deleting} autoFocus>取消</button><button className="danger-btn" onClick={onConfirm} disabled={deleting}><Trash2 size={14} />{deleting ? '删除中...' : '确认删除'}</button></div>
    </div>
  </div>;
}

function ProjectsPage() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery({ queryKey: ['projects'], queryFn: () => api.listProjects() });
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [openMenuId, setOpenMenuId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Project | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  const projects = data?.items.filter(p => p.name.toLowerCase().includes(query.toLowerCase())) ?? [];

  useEffect(() => {
    const closeMenu = () => setOpenMenuId(null);
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      setOpenMenuId(null);
      if (!deleting) setPendingDelete(null);
    };
    window.addEventListener('click', closeMenu);
    window.addEventListener('keydown', handleKeyDown);
    return () => { window.removeEventListener('click', closeMenu); window.removeEventListener('keydown', handleKeyDown); };
  }, [deleting]);

  const openDeleteDialog = (project: Project) => {
    setOpenMenuId(null);
    setDeleteError('');
    setPendingDelete(project);
  };

  const confirmDelete = async () => {
    if (!pendingDelete || deleting) return;
    const project = pendingDelete;
    setDeleting(true);
    setDeleteError('');
    try {
      await api.deleteProject(project.id);
      queryClient.setQueryData<Page<Project>>(['projects'], current => current ? { ...current, items: current.items.filter(item => item.id !== project.id), total: Math.max(0, current.total - 1) } : current);
      setPendingDelete(null);
      await queryClient.invalidateQueries({ queryKey: ['projects'] });
    } catch (error) {
      setDeleteError(error instanceof Error ? error.message : '删除失败，请稍后重试。');
    } finally {
      setDeleting(false);
    }
  };

  return <><PageHeader eyebrow="PROJECTS / 01" title="项目总览" description="管理源代码、分析运行和可复现的检测配置。" action={<button className="primary-btn" onClick={() => navigate('/projects/new')}><Plus size={17} />创建项目</button>} />
    <div className="toolbar"><div className="search-box"><Search size={16} /><input value={query} onChange={e => setQuery(e.target.value)} placeholder="搜索项目" /></div><span className="toolbar-meta">{data?.total ?? 0} 个项目</span></div>
    {isLoading ? <Loading /> : isError ? <EmptyState icon={<AlertOctagon />} title="暂时无法加载项目" detail="请检查 API 连接后重试。" action={<button className="secondary-btn"><RefreshCw size={15} />重试</button>} /> : projects.length === 0 ? <EmptyState icon={<Database />} title="还没有匹配的项目" detail="调整搜索条件或创建一个新项目。" /> : <div className="project-grid">{projects.map(project => <ProjectCard key={project.id} project={project} menuOpen={openMenuId === project.id} onMenuToggle={() => setOpenMenuId(current => current === project.id ? null : project.id)} onDelete={() => openDeleteDialog(project)} />)}</div>}
    <div className="baseline-strip"><div className="baseline-icon"><Activity size={17} /></div><div><b>参考基线已就绪</b><span>TeA 完整版 · 506 / 112 / 10 / 0 · 仅作为对照，不代表 lite 实测</span></div><Link to="/evaluation">查看评估 <ChevronRight size={14} /></Link></div>
    {pendingDelete && <DeleteProjectDialog project={pendingDelete} deleting={deleting} error={deleteError} onCancel={() => { setPendingDelete(null); setDeleteError(''); }} onConfirm={() => void confirmDelete()} />}
  </>;
}

function NewProjectPage() {
  const navigate = useNavigate(); const [name, setName] = useState(''); const [description, setDescription] = useState(''); const [files, setFiles] = useState<File[]>([]); const [created, setCreated] = useState(false); const [error, setError] = useState('');
  const submit = async () => { setCreated(true); setError(''); try { const project = await api.createProject({ name, description }); await Promise.all(files.map(file => api.uploadFile(project.id, file))); navigate(`/projects/${project.id}`); } catch { setCreated(false); setError('项目创建失败，请检查 API 连接后重试。'); } };
  return <><Link className="back-link" to="/"><ArrowLeft size={15} />返回项目</Link><PageHeader eyebrow="PROJECTS / NEW" title="创建项目" description="上传 C 源文件，开始一次可复现的 CWE-121 分析。" /><section className="form-card"><label>项目名称<input value={name} onChange={e => setName(e.target.value)} placeholder="例如：我的栈边界实验" /></label><label>项目描述<textarea value={description} onChange={e => setDescription(e.target.value)} placeholder="可选，描述数据集或实验目的" rows={3} /></label><label>源文件<span className="upload-drop"><Upload size={20} /><b>{files.length ? `${files.length} 个文件已选择` : '选择 .c / .h 文件'}</b><small>支持多文件上传，单文件不超过 10 MB</small><input type="file" accept=".c,.h,.cpp" multiple onChange={e => setFiles(Array.from(e.target.files ?? []))} /></span></label>{error && <div className="form-error"><AlertOctagon size={14} />{error}</div>}<div className="form-actions"><button className="secondary-btn" onClick={() => navigate('/')}>取消</button><button className="primary-btn" disabled={!name || !files.length || created} onClick={() => void submit()}><Plus size={16} />{created ? '创建中...' : '创建项目'}</button></div></section></>;
}

function ProjectRunsPage() { const { projectId = 'proj-001' } = useParams(); const projectQ = useQuery({ queryKey: ['project', projectId], queryFn: () => api.getProject(projectId) }); const runsQ = useQuery({ queryKey: ['runs', projectId], queryFn: () => api.listProjectRuns(projectId) }); const filesQ = useQuery({ queryKey: ['files', projectId], queryFn: () => api.listProjectFiles(projectId) }); const navigate = useNavigate(); const [showModal, setShowModal] = useState(false); const [detector, setDetector] = useState('stack-bounds'); const [creating, setCreating] = useState(false); const [createError, setCreateError] = useState(''); const detectorsQ = useQuery({ queryKey: ['detectors'], queryFn: () => api.listDetectors() }); const packsQ = useQuery({ queryKey: ['packs', detector], queryFn: () => api.listRulePacks(detector) }); const project = projectQ.data;
  const startRun = async () => { const pack = packsQ.data?.items[0]; if (!pack || !filesQ.data?.items.length) return; setCreating(true); setCreateError(''); try { const run = await api.createRun(projectId, { file_ids: filesQ.data.items.map(file => file.id), detector_id: detector, rule_pack_id: pack.id }); navigate(`/runs/${run.id}`); } catch (error) { setCreateError(error instanceof Error ? error.message : '启动分析失败，请稍后重试。'); } finally { setCreating(false); } };
  return <><Link className="back-link" to="/"><ArrowLeft size={15} />所有项目</Link><PageHeader eyebrow="PROJECT / RUNS" title={project?.name ?? '项目'} description={project?.description} action={<button className="primary-btn" onClick={() => setShowModal(true)}><Play size={16} />新建运行</button>} />
    <div className="project-overview"><div><span className="label">源文件</span><strong>{filesQ.data?.total ?? '--'}</strong></div><div><span className="label">最近更新</span><strong>{project ? fmtDate(project.updated_at) : '--'}</strong></div><div><span className="label">检测器</span><strong>stack-bounds</strong></div><div><span className="label">规则包</span><strong>cwe121-core</strong></div></div>
    <section className="section"><div className="section-heading"><div><h2>运行历史</h2><span>保留每次运行的版本快照和分析结果</span></div><button className="secondary-btn"><Filter size={15} />筛选</button></div><div className="run-list">{runsQ.data?.items.map(run => <button className="run-row" key={run.id} onClick={() => navigate(`/runs/${run.id}`)}><div className="run-main"><StatusBadge status={run.status} /><b>{run.id}</b><span>{fmtDate(run.created_at)}</span></div><div className="run-config"><span>{run.detector_id}</span><span>/</span><span>{run.rule_pack_id}</span></div><div className="run-counts"><span className="alarm-count"><ShieldAlert size={14} />{run.summary.alarm_count}</span><span className="diag-count">{run.summary.diagnostic_count} diagnostics</span></div><ChevronRight size={17} /></button>)}</div></section>
    {showModal && <div className="modal-backdrop" onClick={() => setShowModal(false)}><div className="modal" onClick={e => e.stopPropagation()}><div className="modal-header"><div><div className="eyebrow">NEW RUN</div><h2>配置分析运行</h2></div><button className="icon-btn" onClick={() => setShowModal(false)} aria-label="关闭"><X size={18} /></button></div><label>检测器<select value={detector} onChange={e => setDetector(e.target.value)}>{detectorsQ.data?.items.map(d => <option key={d.id} value={d.id}>{d.name} · {d.version}</option>)}</select></label><label>规则包<select><option>{packsQ.data?.items[0]?.name ?? '加载中...'}</option></select></label><label>CWE 范围<div className="selection-chip"><Check size={13} />{(packsQ.data?.items[0]?.supported_cwes ?? ['CWE-121']).join(' / ')}</div></label>{filesQ.isError ? <div className="form-error"><AlertOctagon size={14} />无法读取项目文件，请刷新后重试。</div> : filesQ.data?.total === 0 ? <div className="form-error"><AlertOctagon size={14} />项目中没有可分析的源文件。</div> : null}{createError && <div className="form-error"><AlertOctagon size={14} />{createError}</div>}<button className="primary-btn full" disabled={creating || filesQ.isLoading || !filesQ.data?.total || !packsQ.data?.items[0]} onClick={() => void startRun()}><Play size={16} />{creating ? '启动中...' : filesQ.isLoading ? '读取文件中...' : '启动分析'}</button></div></div>}
  </>;
}

function RunPage() { const { runId = 'run-001' } = useParams(); const { data: run } = useRun(runId); useRunEvents(runId, run?.status === 'queued' || run?.status === 'running'); const navigate = useNavigate(); const [cancelled, setCancelled] = useState(false); if (!run) return <Loading />; const currentStatus = cancelled ? 'cancelled' : run.status; return <><Link className="back-link" to={`/projects/${run.project_id}`}><ArrowLeft size={15} />返回运行列表</Link><PageHeader eyebrow={`RUN / ${run.id}`} title="运行详情" description={`${fmtDate(run.created_at)} 开始 · ${fmtDuration(run.duration_ms)}`} action={<div className="header-actions"><button className="secondary-btn" onClick={() => { void api.rerun(run).then(next => navigate(`/runs/${next.id}`)); }}><RefreshCw size={15} />重新运行</button>{(currentStatus === 'queued' || currentStatus === 'running') && <button className="danger-btn" onClick={() => { setCancelled(true); void api.cancelRun(run.id); }}><Square size={14} />取消运行</button>}</div>} />
    <div className="run-hero"><div className="run-status-large"><StatusBadge status={currentStatus} /><strong>{currentStatus === 'succeeded' ? '分析已完成' : currentStatus === 'cancelled' ? '分析已取消' : '正在准备分析环境'}</strong><span>{currentStatus === 'succeeded' ? '所有输入文件均已处理' : `已完成 ${run.progress}%`}</span></div><div className="progress-track"><div style={{ width: `${currentStatus === 'succeeded' ? 100 : run.progress}%` }} /></div></div>
    <div className="metric-grid"><Metric label="漏洞告警" value={run.summary.alarm_count} icon={<ShieldAlert />} tone="red" /><Metric label="Diagnostics" value={run.summary.diagnostic_count} icon={<Terminal />} /><Metric label="Unsupported" value={run.summary.unsupported_count} icon={<CircleHelp />} tone="amber" /><Metric label="Errors" value={run.summary.error_count} icon={<AlertOctagon />} tone="red" /></div>
    <div className="run-detail-grid"><section className="section"><div className="section-heading"><div><h2>版本与配置</h2><span>运行创建时固化的快照</span></div></div><dl className="detail-list"><dt>Analyzer version</dt><dd>{run.analyzer_version}</dd><dt>Detector</dt><dd><code>{run.detector_id}</code> <em>{run.detector_version}</em></dd><dt>Rule pack</dt><dd><code>{run.rule_pack_id}</code> <em>{run.rule_pack_version}</em></dd><dt>CWE 范围</dt><dd>{run.cwe_scope.map(c => <span className="tag" key={c}>{c}</span>)}</dd></dl></section><section className="section next-actions"><div className="section-heading"><div><h2>继续分析</h2><span>从结果进入可解释工作流</span></div></div><button onClick={() => navigate(`/runs/${run.id}/workbench`)}><div className="action-icon purple"><GitBranch size={18} /></div><div><b>打开分析工作台</b><span>源码 · CFG · 状态</span></div><ChevronRight size={17} /></button><button onClick={() => navigate(`/projects/${run.project_id}/evaluations`)}><div className="action-icon teal"><BarChart3 size={18} /></div><div><b>查看评估结果</b><span>矩阵和 family 细分</span></div><ChevronRight size={17} /></button></section></div>
  </>; }
function Metric({ label, value, icon, tone = '' }: { label: string; value: number; icon: React.ReactNode; tone?: string }) { return <div className={`metric ${tone}`}><div className="metric-icon">{icon}</div><div><span>{label}</span><strong>{value}</strong></div></div>; }

function WorkbenchPage() {
  const { runId = 'run-001' } = useParams();
  const alarmQ = useQuery({ queryKey: ['alarms', runId], queryFn: () => api.listAlarms(runId) });
  const diagQ = useQuery({ queryKey: ['diagnostics', runId], queryFn: () => api.listDiagnostics(runId) });
  const stateQ = useQuery({ queryKey: ['states', runId], queryFn: () => api.getBlockStates(runId) });
  const irQ = useQuery({ queryKey: ['ir', runId], queryFn: () => api.getRunIr(runId) });
  const cfgQ = useQuery({ queryKey: ['cfg', runId], queryFn: () => api.getRunCfg(runId) });
  const [selectedAlarm, setSelectedAlarm] = useState<Alarm | null>(null);
  const [selectedBlock, setSelectedBlock] = useState('');
  const [selectedFunction, setSelectedFunction] = useState('');
  const [selectedLine, setSelectedLine] = useState<number | null>(null);
  const [selectedDiagnosticId, setSelectedDiagnosticId] = useState<string | null>(null);
  const [tab, setTab] = useState<'alarms' | 'diagnostics'>('alarms');
  const sourceRef = useRef<HTMLDivElement>(null);
  const alarms = alarmQ.data?.items ?? [];
  const cfgFunctions = [...new Set((cfgQ.data?.nodes ?? []).map(node => node.function).filter((name): name is string => Boolean(name)))];
  const activeFunction = cfgFunctions.includes(selectedFunction) ? selectedFunction : cfgFunctions[0] ?? '';
  const cfgNodes = cfgQ.data?.nodes?.filter(node => !node.function || node.function === activeFunction).map(node => ({ ...node, kind: alarms.some(alarm => alarm.block_id === node.id && alarm.function === activeFunction) ? 'alarm' : node.kind })) ?? [];
  const cfgEdges = cfgQ.data?.edges?.filter(edge => !edge.function || edge.function === activeFunction) ?? [];
  const selectedState = stateQ.data?.items.find(s => s.block_id === selectedBlock && (!s.function || s.function === activeFunction));
  const highlightedLine = selectedLine ?? selectedAlarm?.location.line ?? null;
  useEffect(() => {
    if (!selectedBlock && cfgNodes[0]) setSelectedBlock(cfgNodes[0].id);
  }, [cfgNodes, selectedBlock]);
  useEffect(() => {
    if (highlightedLine) sourceRef.current?.querySelector<HTMLElement>(`[data-line="${highlightedLine}"]`)?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }, [highlightedLine]);
  const chooseNode = (node: CfgNode) => { setSelectedBlock(node.id); setSelectedLine(node.sourceLines?.[0] ?? null); };
  const chooseAlarm = (alarm: Alarm) => { setSelectedAlarm(alarm); setSelectedDiagnosticId(null); setSelectedBlock(alarm.block_id); setSelectedFunction(alarm.function); setSelectedLine(alarm.location.line || null); };
  const chooseDiagnostic = (diagnostic: Diagnostic) => { setSelectedDiagnosticId(diagnostic.id); setSelectedLine(diagnostic.location?.line || null); };
  const selectFunction = (name: string) => { setSelectedFunction(name); const first = cfgQ.data?.nodes?.find(node => !node.function || node.function === name); setSelectedBlock(first?.id ?? ''); setSelectedLine(first?.sourceLines?.[0] ?? null); };
  return <div className="workbench"><div className="workbench-toolbar"><Link className="back-link" to={`/runs/${runId}`}><ArrowLeft size={15} />运行详情</Link><div className="workbench-title"><Code2 size={17} /><b>分析工作台</b><span>/{irQ.data?.file}</span></div><div className="workbench-tools"><button className="icon-btn" aria-label="刷新" onClick={() => { void Promise.all([cfgQ.refetch(), irQ.refetch(), alarmQ.refetch(), stateQ.refetch()]); }}><RefreshCw size={16} /></button><button className="secondary-btn"><Upload size={15} />导出结果</button></div></div><ResizablePanes storageKey="tea121.workbench.pane-sizes"><section className="pane source-pane"><div className="pane-heading"><span><FileCode2 size={15} />源代码</span><small>{irQ.data?.file}</small></div><div className="code-view" ref={sourceRef}>{(irQ.data?.source ?? '').split('\n').map((line, index) => <div className={`code-line ${index + 1 === highlightedLine ? 'line-active' : ''}`} data-line={index + 1} key={index}><span className="line-no">{index + 1}</span><code>{line || ' '}</code></div>)}</div><div className="ir-block"><div className="pane-heading"><span><Terminal size={15} />LLVM IR</span><small>normalized.ll</small></div>{irQ.data?.instructions.map(i => <div className={`ir-line ${i.line === highlightedLine ? 'ir-active' : ''}`} key={i.id}><span>{i.id}</span><code>{i.text}</code></div>)}</div></section><section className="pane cfg-pane"><div className="pane-heading"><span><GitBranch size={15} />控制流图 <small>{cfgNodes.length} 个基本块</small></span>{cfgFunctions.length > 0 && <select className="mini-select" aria-label="选择函数" value={activeFunction} onChange={event => selectFunction(event.target.value)}>{cfgFunctions.map(name => <option key={name}>{name}</option>)}</select>}</div><CfgGraph nodes={cfgNodes} edges={cfgEdges} selected={selectedBlock} onSelect={chooseNode} /><div className="edge-legend"><span><i className="edge true" />true</span><span><i className="edge false" />false</span><span><i className="edge" />fallthrough</span><span><RotateCcw size={11} />回边 = 循环</span></div></section><section className="pane inspector-pane"><div className="inspector-tabs"><button className={tab === 'alarms' ? 'active' : ''} onClick={() => setTab('alarms')}><ShieldAlert size={15} />告警 <b>{alarms.length}</b></button><button className={tab === 'diagnostics' ? 'active' : ''} onClick={() => setTab('diagnostics')}><Terminal size={15} />诊断 <b>{diagQ.data?.total ?? 0}</b></button></div>{tab === 'alarms' ? <><AlarmTable alarms={alarms} onSelect={chooseAlarm} />{selectedAlarm ? <AlarmDetail alarm={selectedAlarm} /> : <EmptyState icon={<ShieldAlert />} title="选择一个告警" detail="从列表选择告警，查看边界证据和路径原因。" compact />}</> : <DiagnosticList items={diagQ.data?.items ?? []} selectedId={selectedDiagnosticId} onSelect={chooseDiagnostic} />}</section></ResizablePanes><details className="state-strip"><summary aria-label="切换 block state"><ChevronRight size={15} /></summary><div className="state-content"><div className="state-title"><Database size={15} /><b>{selectedState?.label ?? (selectedBlock || '未选择基本块')}</b><span>block state</span></div><div><small>ENTRY</small>{Object.entries(selectedState?.entry_state ?? {}).map(([key, value]) => <code key={key}>{key} = {value}</code>)}</div><ChevronRight size={16} /><div><small>EXIT</small>{Object.entries(selectedState?.exit_state ?? {}).map(([key, value]) => <code key={key}>{key} = {value}</code>)}</div></div></details></div>;
}

export function AlarmDetail({ alarm }: { alarm: Alarm }) { return <div className="alarm-detail"><div className="detail-title"><SeverityBadge severity={alarm.severity} /><span>{alarm.cwe_id}</span></div><h3>{alarm.message}</h3><div className="alarm-meta"><span><b>Detector</b>{alarm.detector_id}</span><span><b>Rule pack</b>{alarm.rule_pack_id}</span><span><b>Family</b>{alarm.family}</span><span><b>Violation kind</b>{alarm.violation_kind}</span><span><b>Function</b>{alarm.function}</span></div><div className="evidence-grid"><div><small>OBJECT SIZE</small><strong>[{alarm.object_size.lower}, {alarm.object_size.upper}] bytes</strong></div><div><small>OFFSET RANGE</small><strong>[{alarm.offset.lower}, {alarm.offset.upper}] bytes</strong></div><div><small>ACCESS WIDTH</small><strong>{alarm.access_size_bytes} bytes</strong></div></div><div className="condition"><small>SAFE CONDITION</small><code>{alarm.safe_condition}</code></div><div className="reasons"><small>WHY THIS IS A VIOLATION</small>{alarm.reason.map((reason, i) => <div key={reason}><span>{i + 1}</span>{reason}</div>)}</div><div className="raw-ir"><small>RAW IR</small><code>{alarm.instruction}</code><span>{alarm.location.file}:{alarm.location.line}:{alarm.location.column}</span></div></div>; }
export function DiagnosticList({ items, selectedId, onSelect }: { items: Diagnostic[]; selectedId?: string | null; onSelect?: (diagnostic: Diagnostic) => void }) { return <div className="diagnostic-list">{items.map(item => { const line = item.location?.line; const actionable = Boolean(line && onSelect); return <button type="button" className={`diagnostic ${actionable ? 'actionable' : ''} ${selectedId === item.id ? 'selected' : ''}`} key={item.id} disabled={!actionable} onClick={() => onSelect?.(item)} title={actionable ? `定位到第 ${line} 行` : '该诊断没有可用的源码位置'}><span className={`diagnostic-icon ${item.severity}`}><AlertOctagon size={14} /></span><div><div><b>{item.code}</b><span className={`diag-label ${item.severity}`}>{item.severity.replace('_', ' ')}</span></div><p>{item.message}</p><small>{item.impact}</small>{line ? <small className="diagnostic-location">第 {line} 行</small> : null}</div></button>; })}{items.length === 0 && <EmptyState icon={<Check />} title="没有诊断信息" detail="该运行未产生 unsupported 或 error。" compact />}</div>; }

function EvaluationPage() { const { projectId } = useParams(); const projectsQ = useQuery({ queryKey: ['projects', 'evaluation-context'], queryFn: () => api.listProjects(), enabled: !projectId }); const activeProjectId = projectId ?? projectsQ.data?.items[0]?.id; const q = useQuery({ queryKey: ['evaluation', activeProjectId], queryFn: () => api.listProjectEvaluations(activeProjectId!), enabled: Boolean(activeProjectId) }); const evaluation = q.data?.items[0]; const [family, setFamily] = useState('all'); if (q.isLoading || (!activeProjectId && projectsQ.isLoading)) return <Loading />; if (!activeProjectId) return <EmptyState icon={<Database />} title="还没有项目" detail="先创建项目并运行分析，再查看评估结果。" />; if (!evaluation) return <><PageHeader eyebrow="EVALUATION" title="评估中心" description="查看项目的 Juliet CWE-121 评估结果。" /><EmptyState icon={<BarChart3 />} title="尚无评估结果" detail="该项目还没有已创建的评估任务。" /></>; const matrix = [{ label: '正确区分', value: evaluation.matrix.correctly_classified, cls: 'good' }, { label: '误报', value: evaluation.matrix.false_positive, cls: 'warn' }, { label: '漏报', value: evaluation.matrix.false_negative, cls: 'bad' }, { label: '倒置', value: evaluation.matrix.inverted, cls: 'muted' }]; const max = Math.max(1, ...evaluation.by_family.map(f => f.tp + f.fp + f.fn)); return <><PageHeader eyebrow="EVALUATION / 01" title="评估中心" description="在 Juliet CWE-121 s01 上观察检测器的准确性和边界。" action={<div className="header-actions"><select className="compact-select"><option>stack-bounds · 0.1.0</option></select><select className="compact-select"><option>cwe121-core · 0.1.0</option></select></div>} /><div className="evaluation-meta"><span><Database size={15} />{evaluation.dataset}</span><span><Clock3 size={15} />{fmtDate(evaluation.created_at)}完成</span><span className="reference-label"><span className="dot" />含参考基线</span></div><section className="matrix-section"><div className="section-heading"><div><h2>结果矩阵</h2><span>仅对 Bad/Good 均可判定的案例统计</span></div><span className="sample-count">628 个案例</span></div><div className="matrix-grid">{matrix.map(item => <div className={`matrix-card ${item.cls}`} key={item.label}><span>{item.label}</span><strong>{item.value}</strong><small>{item.label === '正确区分' ? 'TP + TN' : item.label === '误报' ? 'Good → alarm' : item.label === '漏报' ? 'Bad → clean' : 'Bad/Good 倒置'}</small></div>)}</div></section><div className="evaluation-grid"><section className="section"><div className="section-heading"><div><h2>关键指标</h2><span>当前 lite 实测</span></div></div><div className="metric-list"><div><span>Bad 侧召回率</span><strong>{evaluation.metrics.bad_recall}%</strong><div className="metric-bar"><i style={{ width: `${evaluation.metrics.bad_recall}%` }} /></div></div><div><span>Good 侧静默率</span><strong>{evaluation.metrics.good_silent_rate}%</strong><div className="metric-bar"><i style={{ width: `${evaluation.metrics.good_silent_rate}%` }} /></div></div><div><span>文件级一致率</span><strong>{evaluation.metrics.file_accuracy}%</strong><div className="metric-bar"><i style={{ width: `${evaluation.metrics.file_accuracy}%` }} /></div></div></div><div className="reference-note"><Activity size={15} /><span>参考基线：506 / 112 / 10 / 0 · Bad recall 98.4% · file accuracy 90.29%</span></div></section><section className="section"><div className="section-heading"><div><h2>按 family 分布</h2><span>点击柱体可进入对应 evaluation case</span></div><select className="mini-select" value={family} onChange={e => setFamily(e.target.value)}><option value="all">全部 family</option>{evaluation.by_family.map(f => <option key={f.family}>{f.family}</option>)}</select></div><div className="bar-chart">{evaluation.by_family.filter(f => family === 'all' || family === f.family).map(f => <div className="bar-row" key={f.family}><div className="bar-label">{f.family}</div><div className="bars" style={{ maxWidth: `${(f.tp + f.fp + f.fn) / max * 100}%` }}><i className="tp" style={{ width: `${f.tp / (f.tp + f.fp + f.fn) * 100}%` }} /><i className="fp" style={{ width: `${f.fp / (f.tp + f.fp + f.fn) * 100}%` }} /><i className="fn" style={{ width: `${f.fn / (f.tp + f.fp + f.fn) * 100}%` }} /></div><span>{f.tp + f.fp + f.fn}</span></div>)}</div><div className="chart-legend"><span><i className="tp" />正确</span><span><i className="fp" />误报</span><span><i className="fn" />漏报</span></div></section></div><section className="section trend-section"><div className="section-heading"><div><h2>Analyzer 版本趋势</h2><span>文件级一致率 · 参考基线以虚线表示</span></div></div><div className="trend-chart"><svg viewBox="0 0 760 150" preserveAspectRatio="none"><line x1="35" y1="20" x2="735" y2="20" /><line x1="35" y1="75" x2="735" y2="75" /><line x1="35" y1="130" x2="735" y2="130" /><path d="M80 115 L380 77 L680 49" /><line className="baseline" x1="35" y1="38" x2="735" y2="38" /></svg><div className="trend-labels"><span>0.0.1</span><span>0.0.2</span><span>0.1.0</span></div></div></section></>; }

function Loading() { return <div className="loading"><span className="spinner" />加载中</div>; }
function EmptyState({ icon, title, detail, action, compact = false }: { icon: React.ReactNode; title: string; detail: string; action?: React.ReactNode; compact?: boolean }) { return <div className={`empty-state ${compact ? 'compact' : ''}`}><div className="empty-icon">{icon}</div><h3>{title}</h3><p>{detail}</p>{action}</div>; }
export function App() { return <Shell><Routes><Route path="/" element={<ProjectsPage />} /><Route path="/projects/new" element={<NewProjectPage />} /><Route path="/projects/:projectId" element={<ProjectRunsPage />} /><Route path="/projects/:projectId/evaluations" element={<EvaluationPage />} /><Route path="/runs/:runId" element={<RunPage />} /><Route path="/runs/:runId/workbench" element={<WorkbenchPage />} /><Route path="/evaluation" element={<EvaluationPage />} /><Route path="*" element={<ProjectsPage />} /></Routes></Shell>; }

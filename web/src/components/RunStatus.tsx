import type { RunStatus as RunStatusValue } from '../types/generated';
export function RunStatus({ status }: { status: RunStatusValue }) { const labels: Record<RunStatusValue, string> = { queued: '排队中', running: '分析中', succeeded: '已完成', failed: '失败', cancelled: '已取消' }; return <span className={`status-badge ${status}`}><span className="status-dot" />{labels[status]}</span>; }

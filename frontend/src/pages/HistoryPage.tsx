import { History } from 'lucide-react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { Pagination } from '@/components/ui/pagination'
import { Card, EmptyState, ErrorState, PageHeader, Select, TableSkeleton } from '@/components/ui/primitives'
import { useAnalyses } from '@/hooks/queries'
import { dateTime } from '@/utils/format'

export default function HistoryPage() {
  const [sp, setSp] = useSearchParams()
  const nav = useNavigate()
  const status = sp.get('status') ?? '', page = Number(sp.get('page') ?? 1)
  const { data, isLoading, error, refetch } = useAnalyses({ status, page, page_size: 20 })
  const set = (k: string, v: string) => setSp((p) => { const n = new URLSearchParams(p); v ? n.set(k, v) : n.delete(k); if (k !== 'page') n.delete('page'); return n }, { replace: true })
  return (
    <div className="fade-in">
      <PageHeader title="Analysis history" description="All analyses, including failed and cancelled runs. Each records the rule-set version it used." />
      <Card>
        <div className="p-4 border-b border-line"><Select aria-label="Filter by status" value={status} onChange={(e) => set('status', e.target.value)}><option value="">All statuses</option>{['completed', 'running', 'queued', 'failed', 'cancelled'].map((s) => <option key={s}>{s}</option>)}</Select></div>
        {isLoading ? <TableSkeleton cols={7} /> : error ? <ErrorState error={error} onRetry={refetch} /> : !data?.items.length ? <EmptyState icon={<History className="size-5" />} title="No analyses" description="Run an analysis to build history." /> : (
          <div className="table-wrap"><table className="data"><thead><tr><th>Capture</th><th>Analysis</th><th>Started</th><th>Rule-set</th><th>Sessions</th><th>Findings</th><th>Highest</th><th>Status</th></tr></thead><tbody>
            {data.items.map((a) => (
              <tr key={a.id} className="clickable" tabIndex={0} onClick={() => nav(a.status === 'completed' ? `/analysis/${a.id}/results` : `/analysis/${a.id}`)} onKeyDown={(e) => e.key === 'Enter' && nav(a.status === 'completed' ? `/analysis/${a.id}/results` : `/analysis/${a.id}`)}>
                <td className="max-w-56 truncate font-medium">{a.capture?.filename}</td><td className="font-mono text-xs text-mute">{a.id.slice(0, 8)}</td><td className="whitespace-nowrap text-mute">{dateTime(a.started_at ?? a.created_at)}</td>
                <td className="font-mono text-xs">{a.ruleset_version ?? '-'}</td><td className="tabular-nums">{a.counters.email_sessions ?? '-'}</td><td className="tabular-nums">{a.counters.findings ?? '-'}</td>
                <td>{a.highest_severity ? <SeverityBadge severity={a.highest_severity} /> : '-'}</td><td><StatusBadge status={a.status} />{a.error && <div className="mt-1 max-w-60 truncate text-xs text-crit" title={a.error}>{a.error}</div>}</td></tr>))}</tbody></table></div>)}
        {data && data.total > 0 && <Pagination page={data.page} pages={data.pages} total={data.total} onPage={(p) => set('page', String(p))} />}
      </Card>
    </div>
  )
}

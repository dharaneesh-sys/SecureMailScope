import { Search, ShieldCheck } from 'lucide-react'
import { useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { ObservationBadge, ScoreChip, SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { Pagination } from '@/components/ui/pagination'
import { Card, EmptyState, ErrorState, Input, Select, TableSkeleton } from '@/components/ui/primitives'
import { useFindings } from '@/hooks/queries'
import { OBS_LABEL, SEVERITIES, SEV_LABEL, STATUS_LABEL } from '@/utils/format'
import { FindingDrawer } from './FindingDrawer'

const CATS = ['Deprecated TLS', 'Legacy cipher suites', 'Weak cryptographic algorithms', 'Certificate issues', 'STARTTLS/STLS observations', 'Incomplete TLS evidence', 'Secure configuration']

/** URL-driven filter state so filtered views are shareable and survive reloads. */
export function FindingsTable({ analysisId, compact }: { analysisId?: string; compact?: boolean }) {
  const [sp, setSp] = useSearchParams()
  const get = (k: string) => sp.get(k) ?? ''
  const set = (k: string, v: string) => setSp((p) => { const n = new URLSearchParams(p); if (v) n.set(k, v); else n.delete(k); if (k !== 'page' && k !== 'open') n.delete('page'); return n }, { replace: true })
  const page = Number(get('page') || 1)
  const params = { severity: get('severity'), protocol: get('protocol'), category: get('category'), status: get('status'), observation_type: get('obs'), q: get('q'), sort: get('sort') || 'severity', order: get('order') || 'desc', page, page_size: compact ? 10 : 20 }
  const { data, isLoading, error, refetch, isFetching } = useFindings(params, analysisId)
  const open = get('open') || null
  useEffect(() => { /* keep deep link `open` */ }, [open])
  const filtered = !!(params.severity || params.protocol || params.category || params.status || params.observation_type || params.q)

  return (
    <>
      <Card>
        <div className="flex flex-wrap items-center gap-2 p-4 border-b border-line">
          <div className="relative min-w-48 flex-1"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-mute" aria-hidden /><Input aria-label="Search findings" className="pl-9" placeholder="Search title, rule ID, description…" value={get('q')} onChange={(e) => set('q', e.target.value)} /></div>
          <Select aria-label="Severity" value={get('severity')} onChange={(e) => set('severity', e.target.value)}><option value="">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{SEV_LABEL[s]}</option>)}</Select>
          <Select aria-label="Protocol" value={get('protocol')} onChange={(e) => set('protocol', e.target.value)}><option value="">All protocols</option><option value="smtp">SMTP</option><option value="imap">IMAP</option><option value="pop3">POP3</option></Select>
          <Select aria-label="Category" value={get('category')} onChange={(e) => set('category', e.target.value)}><option value="">All categories</option>{CATS.map((c) => <option key={c}>{c}</option>)}</Select>
          <Select aria-label="Status" value={get('status')} onChange={(e) => set('status', e.target.value)}><option value="">All statuses</option>{Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</Select>
          <Select aria-label="Observation type" value={get('obs')} onChange={(e) => set('obs', e.target.value)}><option value="">All observation types</option>{Object.entries(OBS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</Select>
          <Select aria-label="Sort by" value={`${params.sort}:${params.order}`} onChange={(e) => { const [s, o] = e.target.value.split(':'); setSp((p) => { const n = new URLSearchParams(p); n.set('sort', s); n.set('order', o); n.delete('page'); return n }, { replace: true }) }}>
            <option value="severity:desc">Severity (high → low)</option><option value="severity:asc">Severity (low → high)</option><option value="risk:desc">Risk score</option><option value="created:desc">Newest</option><option value="rule:asc">Rule ID</option><option value="status:asc">Status</option></Select>
        </div>
        {isLoading ? <TableSkeleton cols={6} /> : error ? <ErrorState error={error} onRetry={refetch} /> : !data?.items.length ? (
          <EmptyState icon={<ShieldCheck className="size-5" />} title={filtered ? 'No findings match these filters' : 'No findings yet'} description={filtered ? 'Clear a filter or broaden the search.' : 'Findings appear here after an analysis completes.'} />
        ) : (
          <div className={`table-wrap ${isFetching ? 'opacity-70' : ''}`}><table className="data"><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Observation</th><th>Rule</th><th>Protocol</th><th>Risk</th><th>Status</th>{!analysisId && <th>Capture</th>}</tr></thead><tbody>
            {data.items.map((f) => (
              <tr key={f.id} className="clickable" onClick={() => set('open', f.id)} onKeyDown={(e) => e.key === 'Enter' && set('open', f.id)} tabIndex={0} aria-label={`Open ${f.title}`}>
                <td className="font-mono text-xs text-mute">{f.ref}</td><td className="max-w-80 font-medium">{f.title}</td><td><SeverityBadge severity={f.severity} /></td><td><ObservationBadge type={f.observation_type} /></td>
                <td className="font-mono text-xs">{f.rule_id}</td><td className="text-xs uppercase">{f.protocol ?? '-'}</td><td><ScoreChip score={f.risk_score} /></td><td><StatusBadge status={f.status} /></td>
                {!analysisId && <td className="max-w-40 truncate text-xs text-mute">{f.capture}</td>}</tr>))}</tbody></table></div>
        )}
        {data && data.total > 0 && <Pagination page={data.page} pages={data.pages} total={data.total} onPage={(p) => set('page', String(p))} />}
      </Card>
      <FindingDrawer id={open} onClose={() => set('open', '')} />
    </>
  )
}

import { Download, FolderArchive, Play, Plus, Search, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { ConfirmDialog } from '@/components/ui/dialog'
import { Pagination } from '@/components/ui/pagination'
import { Button, Card, CopyButton, EmptyState, ErrorState, Input, PageHeader, Select, TableSkeleton } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { useCaptures, useCreateReport, useDeleteCapture, useRerun } from '@/hooks/queries'
import type { Capture } from '@/types/api'
import { bytes, dateTime, download, shortHash } from '@/utils/format'

export default function CapturesPage() {
  const [sp, setSp] = useSearchParams()
  const nav = useNavigate()
  const toast = useToast()
  const q = sp.get('q') ?? '', sort = sp.get('sort') ?? 'uploaded_at', order = sp.get('order') ?? 'desc', page = Number(sp.get('page') ?? 1)
  const { data, isLoading, error, refetch } = useCaptures({ q, sort, order, page, page_size: 15 })
  const del = useDeleteCapture(), rerun = useRerun(), mkReport = useCreateReport()
  const [target, setTarget] = useState<Capture | null>(null)
  const set = (k: string, v: string) => setSp((p) => { const n = new URLSearchParams(p); v ? n.set(k, v) : n.delete(k); if (k !== 'page') n.delete('page'); return n }, { replace: true })
  return (
    <div className="fade-in">
      <PageHeader title="Capture library" description="Every uploaded capture with its SHA-256, retention state and latest analysis." actions={<Button variant="primary" onClick={() => nav('/analysis/new')}><Plus className="size-4" />New analysis</Button>} />
      <Card>
        <div className="flex flex-wrap gap-2 p-4 border-b border-line">
          <div className="relative min-w-52 flex-1"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-mute" /><Input aria-label="Search captures" className="pl-9" placeholder="Search filename or SHA-256…" value={q} onChange={(e) => set('q', e.target.value)} /></div>
          <Select aria-label="Sort" value={`${sort}:${order}`} onChange={(e) => { const [s, o] = e.target.value.split(':'); setSp((p) => { const n = new URLSearchParams(p); n.set('sort', s); n.set('order', o); return n }, { replace: true }) }}>
            <option value="uploaded_at:desc">Newest first</option><option value="uploaded_at:asc">Oldest first</option><option value="filename:asc">Filename A–Z</option><option value="size:desc">Largest</option><option value="packets:desc">Most packets</option></Select>
        </div>
        {isLoading ? <TableSkeleton cols={7} /> : error ? <ErrorState error={error} onRetry={refetch} /> : !data?.items.length ? (
          <EmptyState icon={<FolderArchive className="size-5" />} title={q ? 'No captures match your search' : 'No captures yet'} description="Upload an authorised PCAP or load the demo dataset from the Overview page." action={<Link to="/analysis/new"><Button variant="primary">Upload a PCAP</Button></Link>} />
        ) : (
          <div className="table-wrap"><table className="data"><thead><tr><th>Filename</th><th>SHA-256</th><th>Size</th><th>Uploaded</th><th>Protocols</th><th>Status</th><th>Findings</th><th>Actions</th></tr></thead><tbody>
            {data.items.map((c) => (
              <tr key={c.id}>
                <td className="max-w-56 font-medium"><span className="truncate block">{c.filename}</span>{c.is_demo && <span className="text-[10px] font-semibold text-warn">SYNTHETIC DEMO</span>}{!c.retained && <span className="text-[10px] text-mute block">original not retained</span>}</td>
                <td><span className="font-mono text-xs">{shortHash(c.sha256, 8)}</span><CopyButton value={c.sha256} label="Copy SHA-256" /></td>
                <td className="whitespace-nowrap text-mute">{bytes(c.size_bytes)}</td><td className="whitespace-nowrap text-mute">{dateTime(c.uploaded_at)}</td>
                <td className="text-xs uppercase">{c.latest_analysis?.protocols.join(', ') || '-'}</td>
                <td>{c.latest_analysis ? <StatusBadge status={c.latest_analysis.status} /> : <span className="text-mute text-xs">not analysed</span>}</td>
                <td className="tabular-nums">{c.latest_analysis ? <span className="inline-flex items-center gap-2">{c.latest_analysis.findings}{c.latest_analysis.highest_severity && <SeverityBadge severity={c.latest_analysis.highest_severity} compact />}</span> : '-'}</td>
                <td><div className="flex gap-1">
                  {c.latest_analysis && <Button size="sm" variant="ghost" title="View analysis" onClick={() => nav(c.latest_analysis!.status === 'completed' ? `/analysis/${c.latest_analysis!.id}/results` : `/analysis/${c.latest_analysis!.id}`)}>View</Button>}
                  <Button size="sm" variant="ghost" title="Re-analyse" disabled={!c.retained} aria-label={`Re-analyse ${c.filename}`} onClick={() => rerun.mutate(c.latest_analysis?.id ?? '', { onSuccess: (a) => nav(`/analysis/${a.id}`), onError: (e) => toast({ tone: 'err', title: 'Re-analysis failed', body: e.message }) })}><Play className="size-3.5" /></Button>
                  <Button size="sm" variant="ghost" title="Download original" disabled={!c.retained} aria-label={`Download ${c.filename}`} onClick={() => download(`/api/captures/${c.id}/download`)}><Download className="size-3.5" /></Button>
                  {c.latest_analysis?.status === 'completed' && <Button size="sm" variant="ghost" title="Download report (PDF)" onClick={() => mkReport.mutate({ analysisId: c.latest_analysis!.id, format: 'pdf' }, { onSuccess: (r) => download(`/api/reports/${r.id}/download`), onError: (e) => toast({ tone: 'err', title: 'Report failed', body: e.message }) })}>Report</Button>}
                  <Button size="sm" variant="ghost" title="Delete" aria-label={`Delete ${c.filename}`} onClick={() => setTarget(c)}><Trash2 className="size-3.5 text-crit" /></Button></div></td>
              </tr>))}</tbody></table></div>
        )}
        {data && data.total > 0 && <Pagination page={data.page} pages={data.pages} total={data.total} onPage={(p) => set('page', String(p))} />}
      </Card>
      <ConfirmDialog open={!!target} onOpenChange={(o) => !o && setTarget(null)} danger title="Delete this capture permanently?" confirmLabel="Delete permanently" loading={del.isPending}
        description={<>This removes <b>{target?.filename}</b>, its stored file, all analyses, findings, evidence and generated reports. <b>This cannot be undone.</b></>}
        onConfirm={() => del.mutate(target!.id, { onSuccess: () => { toast({ tone: 'ok', title: 'Capture deleted' }); setTarget(null) }, onError: (e) => toast({ tone: 'err', title: 'Delete failed', body: e.message }) })} />
    </div>
  )
}

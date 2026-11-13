import { FileSearch, X } from 'lucide-react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { AnalysisPicker, ScopeGate, useScopedAnalysis } from '@/components/analysis/Scope'
import { CompletenessBadge, SeverityBadge } from '@/components/ui/badges'
import { Pagination } from '@/components/ui/pagination'
import { Button, Card, CardHeader, CopyButton, EmptyState, ErrorState, Input, KV, Notice, PageHeader, Spinner, TableSkeleton } from '@/components/ui/primitives'
import { useEvidenceDetail, useEvidenceList } from '@/hooks/queries'
import { hexDump, preciseTime } from '@/utils/format'

function Tree({ node, depth = 0 }: { node: unknown; depth?: number }) {
  if (node === null || typeof node !== 'object') return <span className="text-fg">{String(node)}</span>
  return <ul className={depth ? 'ml-4 border-l border-line pl-3' : ''}>{Object.entries(node as Record<string, unknown>).map(([k, v]) => <li key={k} className="py-0.5 text-xs font-mono"><span className="text-accent2">{k}</span>{typeof v === 'object' && v ? <Tree node={v} depth={depth + 1} /> : <>: <Tree node={v} /></>}</li>)}</ul>
}

function Detail({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, isLoading, error, refetch } = useEvidenceDetail(id)
  if (isLoading) return <Card className="p-6"><Spinner /></Card>
  if (error || !data) return <Card><ErrorState error={error} onRetry={refetch} /></Card>
  const e = data.evidence
  return (
    <Card elevated>
      <CardHeader title={<span className="font-mono">{e.ref}</span>} subtitle={e.description} action={<Button size="sm" variant="ghost" aria-label="Close evidence detail" onClick={onClose}><X className="size-4" /></Button>} />
      <div className="space-y-5 px-5 pb-5">
        <div className="flex flex-wrap items-center gap-2 text-sm"><SeverityBadge severity={data.finding.severity} /><Link className="text-accent2 underline" to={`/findings?open=${data.finding.id}`}>{data.finding.ref} · {data.finding.title}</Link><CompletenessBadge value={e.completeness} /></div>
        <KV items={[['Capture', `${data.capture.filename}`], ['SHA-256', <span className="font-mono text-xs break-all">{data.capture.sha256}</span>], ['Frame', e.frame ? `#${e.frame}` : '-'], ['Stream', e.stream_id ?? '-'], ['Direction', e.direction ?? '-'], ['Timestamp', preciseTime(e.timestamp)], ['Protocol', e.protocol.toUpperCase()], ['Parser', e.parser]]} />
        {Object.keys(e.fields).length > 0 && <div><h3 className="mb-2 text-sm font-semibold">Extracted fields</h3><div className="rounded-lg border border-line bg-bg/50 p-3"><Tree node={e.fields} /></div></div>}
        {data.packet?.tree && <div><h3 className="mb-2 text-sm font-semibold">Decoded packet (TShark) · frame #{data.packet.frame}</h3><div className="max-h-72 overflow-auto rounded-lg border border-line bg-bg/50 p-3"><Tree node={data.packet.tree} /></div></div>}
        {data.packet?.raw_hex ? <div><h3 className="mb-2 flex items-center gap-2 text-sm font-semibold">Raw bytes<CopyButton value={data.packet.raw_hex} label="Copy hex" /></h3>
          <div className="max-h-64 overflow-auto rounded-lg border border-line bg-bg/50 p-3 font-mono text-[11px] leading-5" role="region" aria-label="Hex view" tabIndex={0}>{hexDump(data.packet.raw_hex).map((r) => <div key={r.off}><span className="text-mute">{r.off}</span>  <span>{r.bytes.join(' ')}</span>  <span className="text-accent2">{r.ascii}</span></div>)}</div></div>
          : <Notice tone="info">Raw bytes are not retained for plaintext email protocol frames (to avoid storing credentials or content). Only TLS handshake frames keep raw bytes.</Notice>}
        <div className="flex flex-wrap gap-2 text-sm">{data.session && <Link className="text-accent2 underline" to={`/analysis/${data.analysis_id}/protocols`}>Open protocol session</Link>}{data.tls_session && <Link className="text-accent2 underline" to={`/analysis/${data.analysis_id}/tls`}>Open TLS session</Link>}</div>
      </div>
    </Card>
  )
}

export default function EvidencePage() {
  const { id, list, fromUrl } = useScopedAnalysis()
  const [sp, setSp] = useSearchParams()
  const nav = useNavigate()
  const q = sp.get('q') ?? '', page = Number(sp.get('page') ?? 1), open = sp.get('open')
  const { data, isLoading, error, refetch } = useEvidenceList(id, { q, page, page_size: 20 })
  const set = (k: string, v: string | null) => setSp((p) => { const n = new URLSearchParams(p); v ? n.set(k, v) : n.delete(k); if (k === 'q') n.delete('page'); return n }, { replace: true })
  return (
    <div className="fade-in">
      <PageHeader title="Evidence explorer" description="Every finding points to the packet-level evidence that supports it: Finding → Evidence → Packet → Session." actions={<AnalysisPicker current={id} suffix="evidence" />} />
      <ScopeGate id={id} loading={!fromUrl && list.isLoading}>
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
          <Card>
            <div className="p-4 border-b border-line"><Input aria-label="Search evidence" placeholder="Search description, protocol, reference…" value={q} onChange={(e) => set('q', e.target.value)} /></div>
            {isLoading ? <TableSkeleton cols={4} /> : error ? <ErrorState error={error} onRetry={refetch} /> : !data?.items.length ? <EmptyState icon={<FileSearch className="size-5" />} title="No evidence" description="No evidence items match." /> : (
              <div className="table-wrap"><table className="data"><thead><tr><th>Ref</th><th>Finding</th><th>Frame</th><th>Protocol</th><th>Description</th></tr></thead><tbody>
                {data.items.map((e) => <tr key={e.id} className="clickable" tabIndex={0} aria-selected={open === e.id} onClick={() => set('open', e.id)} onKeyDown={(k) => k.key === 'Enter' && set('open', e.id)}>
                  <td className="font-mono text-xs whitespace-nowrap">{e.ref}</td><td>{e.finding && <span className="inline-flex items-center gap-2"><SeverityBadge severity={e.finding.severity} compact /><span className="font-mono text-xs">{e.finding.ref}</span></span>}</td><td>{e.frame ? `#${e.frame}` : '-'}</td><td className="uppercase text-xs">{e.protocol}</td><td className="max-w-64 truncate text-mute" title={e.description}>{e.description}</td></tr>)}</tbody></table></div>)}
            {data && data.total > 0 && <Pagination page={data.page} pages={data.pages} total={data.total} onPage={(p) => set('page', String(p))} />}
          </Card>
          <div>{open ? <Detail id={open} onClose={() => { set('open', null); void nav }} /> : <Card className="p-8"><EmptyState icon={<FileSearch className="size-5" />} title="Select an evidence item" description="Choose a row to see its extracted fields, decoded packet and raw bytes." /></Card>}</div>
        </div>
      </ScopeGate>
    </div>
  )
}

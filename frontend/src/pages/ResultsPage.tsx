import { Download, FileCheck2, Lock, Mail, Network, ShieldAlert, Waypoints } from 'lucide-react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { FindingsTable } from '@/components/findings/FindingsTable'
import { StatusBadge } from '@/components/ui/badges'
import { Button, Card, CardHeader, CopyButton, ErrorState, KV, Notice, PageHeader, Skeleton, Stat } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { useCreateReport, useSummary } from '@/hooks/queries'
import { SEVERITIES, SEV_COLOR, SEV_LABEL, dateTime, download } from '@/utils/format'

export default function ResultsPage() {
  const { analysisId } = useParams()
  const nav = useNavigate()
  const toast = useToast()
  const { data, isLoading, error, refetch } = useSummary(analysisId)
  const mk = useCreateReport()
  if (isLoading) return <div className="space-y-4"><Skeleton className="h-20" /><Skeleton className="h-28" /><Skeleton className="h-64" /></div>
  if (error || !data) return <ErrorState error={error} onRetry={refetch} />
  const a = data.analysis, c = data.counters
  const report = (format: string) => mk.mutate({ analysisId: analysisId!, format }, {
    onSuccess: (r) => { download(`/api/reports/${r.id}/download`); toast({ tone: 'ok', title: `${format.toUpperCase()} report generated`, body: r.filename }) },
    onError: (e) => toast({ tone: 'err', title: 'Report failed', body: e.message }),
  })
  return (
    <div className="space-y-6 fade-in">
      <PageHeader title={a.capture?.filename ?? 'Analysis results'} description={<span className="flex flex-wrap items-center gap-x-4 gap-y-1"><span className="inline-flex items-center gap-1 font-mono text-xs">{a.id}<CopyButton value={a.id} label="Copy analysis ID" /></span><span>{dateTime(a.finished_at)}</span><StatusBadge status={a.status} /></span>}
        actions={<><Button onClick={() => nav(`/reports?analysis=${a.id}`)}>Preview report</Button><Button variant="primary" loading={mk.isPending} onClick={() => report('pdf')}><Download className="size-4" />Download report (PDF)</Button></>} />
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
        <Stat label="Packets analysed" value={c.packets ?? 0} icon={<Network className="size-4" />} /><Stat label="TCP streams" value={c.streams ?? 0} icon={<Waypoints className="size-4" />} />
        <Stat label="Email sessions" value={c.email_sessions ?? 0} icon={<Mail className="size-4" />} /><Stat label="TLS handshakes" value={c.tls_handshakes ?? 0} icon={<Lock className="size-4" />} />
        <Stat label="Certificates observed" value={data.certificates_observed} icon={<FileCheck2 className="size-4" />} /><Stat label="Total findings" value={c.findings ?? 0} icon={<ShieldAlert className="size-4" />} tone={(data.severity.critical + data.severity.high) > 0 ? 'crit' : 'accent'} />
      </div>
      {data.engine_errors.length > 0 && <Notice tone="crit" title="Engine errors (some checks did not run)">{data.engine_errors.map((e) => <div key={e}>{e}</div>)}</Notice>}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card><CardHeader title="Protocol summary" action={<Link className="text-xs text-accent2 hover:underline" to={`/analysis/${a.id}/protocols`}>Explore</Link>} />
          <div className="px-5 pb-5"><KV cols={1} items={[['Protocols detected', a.protocols.map((p) => p.toUpperCase()).join(', ') || 'none'], ['Email sessions', c.email_sessions ?? 0], ['TCP streams in capture', c.streams ?? 0]]} /></div></Card>
        <Card><CardHeader title="TLS posture" action={<Link className="text-xs text-accent2 hover:underline" to={`/analysis/${a.id}/tls`}>Inspect</Link>} />
          <div className="px-5 pb-5"><KV cols={1} items={[['Negotiated versions', Object.entries(data.tls_versions).map(([v, n]) => `${v} ×${n}`).join(', ') || 'none observed'], ['Handshakes parsed', c.tls_handshakes ?? 0]]} /></div></Card>
        <Card><CardHeader title="Certificate summary" action={<Link className="text-xs text-accent2 hover:underline" to={`/analysis/${a.id}/certificates`}>Inspect</Link>} />
          <div className="px-5 pb-5"><KV cols={1} items={[['Certificates extracted', data.certificates_observed], ['Trust validation', 'Not performed (metadata only)']]} /></div></Card>
      </div>
      <Card><CardHeader title="Findings by severity" subtitle="Status" />
        <div className="flex flex-wrap gap-3 px-5 pb-5">{SEVERITIES.map((s) => <div key={s} className="rounded-lg border border-line bg-bg/60 px-4 py-2.5 min-w-28"><div className="text-2xl font-semibold tabular-nums" style={{ color: data.severity[s] ? SEV_COLOR[s] : undefined }}>{data.severity[s]}</div><div className="text-xs text-mute">{SEV_LABEL[s]}</div></div>)}
          <div className="ml-auto text-xs text-mute self-end">{Object.entries(data.status).map(([k, v]) => `${k.replace('_', ' ')}: ${v}`).join(' · ')}</div></div></Card>
      <div><h2 className="mb-3 text-sm font-semibold">Security findings</h2><FindingsTable analysisId={a.id} compact /></div>
      <Card><CardHeader title="Evidence overview" action={<Link className="text-xs text-accent2 hover:underline" to={`/analysis/${a.id}/evidence`}>Open Evidence Explorer</Link>} />
        <p className="px-5 pb-5 text-sm text-mute">{c.evidence ?? 0} evidence record(s) link findings to packet frames, TCP streams and parser observations. Click a finding to inspect its evidence.</p></Card>
      <Card><CardHeader title="Analysis limitations" subtitle="What this assessment could not see" />
        <ul className="px-5 pb-5 list-disc pl-9 space-y-1 text-sm text-mute marker:text-accent">{data.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
        <div className="px-5 pb-4 text-xs text-mute">Rule-set {a.ruleset_version} · {String(data.tool.version ?? 'TShark')} · {String(data.tool.duration_s ?? '?')}s</div></Card>
      {a.ai_summary?.status === 'generated' && <Card elevated><CardHeader title="AI-generated explanation" subtitle={a.ai_summary.label} /><p className="px-5 pb-5 text-sm">{a.ai_summary.executive_summary}</p></Card>}
    </div>
  )
}

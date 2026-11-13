import { CheckCircle2, Circle, Loader2, XCircle } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { StatusBadge } from '@/components/ui/badges'
import { ConfirmDialog } from '@/components/ui/dialog'
import { Button, Card, CardHeader, ErrorState, Notice, PageHeader, Progress, Spinner, Stat } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { useAnalysis, useAnalysisStatus, useCancelAnalysis } from '@/hooks/queries'
import { cn } from '@/utils/format'

export default function AnalysisProgressPage() {
  const { analysisId } = useParams()
  const nav = useNavigate()
  const toast = useToast()
  const st = useAnalysisStatus(analysisId)
  const an = useAnalysis(analysisId)
  const cancel = useCancelAnalysis()
  const [confirm, setConfirm] = useState(false)
  const s = st.data
  useEffect(() => { if (s?.status === 'completed') { const t = setTimeout(() => nav(`/analysis/${analysisId}/results`), 900); return () => clearTimeout(t) } }, [s?.status, analysisId, nav])
  if (st.error) return <ErrorState error={st.error} onRetry={() => st.refetch()} />
  if (!s) return <Spinner label="Loading analysis" />
  const done = new Map(s.stage_log.map((x) => [x.key, x]))
  const active = s.status === 'running' || s.status === 'queued'
  return (
    <div className="fade-in">
      <PageHeader title="Analysis in progress" description={<>{an.data?.capture?.filename} · <span className="font-mono text-xs">{analysisId}</span></>}
        actions={<>{<StatusBadge status={s.status} />}{active && <Button variant="danger" onClick={() => setConfirm(true)}>Cancel analysis</Button>}</>} />
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 mb-5">
        <Stat label="Packets processed" value={s.counters.packets ?? 0} /><Stat label="TCP streams" value={s.counters.streams ?? 0} /><Stat label="Email sessions" value={s.counters.email_sessions ?? 0} />
        <Stat label="TLS handshakes parsed" value={s.counters.tls_handshakes ?? 0} /><Stat label="Findings generated" value={s.counters.findings ?? 0} />
      </div>
      {s.status === 'failed' && <div className="mb-5"><Notice tone="crit" title={`Analysis failed${s.failed_stage ? ` at stage: ${s.stages.find((x) => x.key === s.failed_stage)?.label ?? s.failed_stage}` : ''}`}>{s.error}</Notice></div>}
      {s.status === 'cancelled' && <div className="mb-5"><Notice tone="warn" title="Analysis cancelled">{s.error}</Notice></div>}
      <div className="grid gap-5 lg:grid-cols-[1fr_1.1fr]">
        <Card><CardHeader title="Pipeline" subtitle="Each stage reports real work performed by the backend." />
          <div className="px-5 pb-4"><div className="mb-1 flex justify-between text-xs text-mute"><span>Overall</span><span>{s.status === 'completed' ? 100 : s.progress}%</span></div><Progress value={s.status === 'completed' ? 100 : s.progress} tone={s.status === 'failed' ? 'crit' : 'accent'} /></div>
          <ol className="px-5 pb-5 space-y-2">
            {s.stages.map((x, i) => {
              const e = done.get(x.key)
              const state = e?.status ?? 'pending'
              return (
                <li key={x.key} className="flex items-start gap-3">
                  <span className="mt-0.5">{state === 'done' ? <CheckCircle2 className="size-4 text-accent" /> : state === 'running' ? <Loader2 className="size-4 animate-spin text-accent2" /> : state === 'failed' ? <XCircle className="size-4 text-crit" /> : <Circle className="size-4 text-line" />}</span>
                  <div className="min-w-0"><div className={cn('text-sm', state === 'pending' ? 'text-mute' : 'text-ink')}>{i + 1}. {x.label}</div>{e?.message && <div className="text-xs text-mute break-words">{e.message}</div>}</div>
                </li>
              )
            })}
          </ol></Card>
        <Card><CardHeader title="Processing messages" />
          <div className="px-5 pb-5 max-h-[520px] overflow-y-auto font-mono text-xs space-y-1.5" aria-live="polite">
            {s.messages.length === 0 && <div className="text-mute">Waiting for the worker to pick up the job…</div>}
            {s.messages.map((m, i) => <div key={i}><span className="text-mute">{m.t.slice(11)}</span> <span className="text-accent2">[{m.stage}]</span> {m.message}</div>)}
          </div></Card>
      </div>
      {s.status === 'completed' && <div className="mt-5"><Link to={`/analysis/${analysisId}/results`}><Button variant="primary">View results</Button></Link></div>}
      <ConfirmDialog open={confirm} onOpenChange={setConfirm} title="Cancel this analysis?" description="TShark will be stopped and no results will be saved." confirmLabel="Cancel analysis" danger loading={cancel.isPending}
        onConfirm={() => cancel.mutate(analysisId!, { onSuccess: () => { setConfirm(false); toast({ tone: 'info', title: 'Cancellation requested' }) }, onError: (e) => toast({ tone: 'err', title: 'Could not cancel', body: e.message }) })} />
    </div>
  )
}

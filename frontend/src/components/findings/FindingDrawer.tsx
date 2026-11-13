import { ArrowRight } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { CompletenessBadge, ObservationBadge, ScoreChip, SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { Drawer } from '@/components/ui/dialog'
import { Button, Input, KV, Label, Mono, Select, Spinner } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { useFinding, useFindingStatus } from '@/hooks/queries'
import { STATUS_LABEL, dateTime, preciseTime } from '@/utils/format'

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return <div className="mb-5"><h3 className="text-xs font-semibold uppercase tracking-wider text-mute mb-1.5">{title}</h3><div className="text-sm leading-relaxed">{children}</div></div>
}

export function FindingDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data: f, isLoading } = useFinding(id ?? undefined)
  const mut = useFindingStatus()
  const toast = useToast()
  const [note, setNote] = useState('')
  return (
    <Drawer open={!!id} onOpenChange={(o) => !o && onClose()} wide title={f ? f.title : 'Finding'}
      subtitle={f && <span className="flex flex-wrap items-center gap-2"><span className="font-mono">{f.ref}</span><span className="font-mono">{f.rule_id}</span><SeverityBadge severity={f.severity} /><StatusBadge status={f.status} /></span>}>
      {isLoading || !f ? <Spinner /> : (
        <div>
          <div className="mb-5 flex flex-wrap gap-x-5 gap-y-2"><ObservationBadge type={f.observation_type} /><CompletenessBadge value={f.completeness} /><span className="text-xs text-mute">Risk <ScoreChip score={f.risk_score} /></span></div>
          <Block title="Description">{f.description}</Block>
          <Block title="Technical explanation">{f.technical}</Block>
          <Block title="Risk impact">{f.impact}</Block>
          <Block title="Recommended remediation">{f.remediation}</Block>
          <Block title="Details"><KV items={[['Category', f.category], ['Protocol', f.protocol ?? '-'], ['Session (TCP stream)', f.stream_id ?? '-'], ['Capture', f.capture], ['Timestamp', dateTime(f.created_at)], ['Rule version', `v${f.rule_version} · rule-set ${f.ruleset_version}`]]} /></Block>
          <Block title={`Supporting evidence (${f.evidence?.length ?? 0})`}>
            <ul className="space-y-2">{f.evidence?.map((e) => (
              <li key={e.id} className="rounded-lg border border-line bg-bg/60 p-3">
                <div className="flex items-center justify-between gap-2"><span className="font-mono text-xs text-accent">{e.ref}</span>
                  <Link to={`/analysis/${f.analysis_id}/evidence?open=${e.id}`} className="inline-flex items-center gap-1 text-xs text-accent2 hover:underline">Open packet evidence <ArrowRight className="size-3" /></Link></div>
                <div className="mt-1 text-sm">{e.description}</div>
                <div className="mt-1 text-xs text-mute">{e.protocol} · frame {e.frame ?? 'n/a'} · stream {e.stream_id ?? '-'} · {e.direction ?? '-'} · {preciseTime(e.timestamp)}</div>
              </li>))}</ul>
            <div className="mt-3 flex flex-wrap gap-3 text-xs">
              {f.session && <Link className="text-accent2 hover:underline" to={`/analysis/${f.analysis_id}/protocols`}>Open session in Protocol Explorer</Link>}
              {f.tls_session && <Link className="text-accent2 hover:underline" to={`/analysis/${f.analysis_id}/tls`}>Open in TLS Inspector</Link>}
            </div>
          </Block>
          <Block title="Triage status">
            <p className="text-xs text-mute mb-2">Triage state is separate from the evidence: changing it never alters captured data or the original observation.</p>
            <div className="flex flex-wrap items-end gap-2">
              <div><Label htmlFor="st">Status</Label><Select id="st" value={f.status} disabled={mut.isPending} onChange={(e) => mut.mutate({ id: f.id, status: e.target.value, note }, { onSuccess: () => { setNote(''); toast({ tone: 'ok', title: 'Status updated' }) }, onError: (er) => toast({ tone: 'err', title: 'Update failed', body: er.message }) })}>
                {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</Select></div>
              <div className="flex-1 min-w-48"><Label htmlFor="note">Note for next change (optional)</Label><Input id="note" value={note} maxLength={400} onChange={(e) => setNote(e.target.value)} placeholder="e.g. ticket reference" /></div>
            </div>
            {f.history && f.history.length > 0 && <ul className="mt-3 space-y-1 text-xs text-mute">{f.history.map((h, i) => <li key={i}>{dateTime(h.at)}: {STATUS_LABEL[h.old_status ?? ''] ?? h.old_status} → <b className="text-ink">{STATUS_LABEL[h.new_status]}</b>{h.note && ` (${h.note})`}</li>)}</ul>}
          </Block>
          <Block title="Risk score breakdown">
            <p className="text-xs text-mute mb-2">{f.risk.explanation}</p>
            <table className="data"><thead><tr><th>Factor</th><th>Value</th><th>Effect</th></tr></thead><tbody>{f.risk.factors.map((x, i) => <tr key={i}><td>{x.factor}</td><td className="text-mute">{x.value}</td><td className="tabular-nums">{x.effect > 0 ? '+' : ''}{x.effect}</td></tr>)}</tbody></table>
            <p className="mt-2 text-xs text-mute">Recommended: {f.risk.recommended_action} · Model {f.risk.model} (not CVSS)</p>
          </Block>
          <Mono>{f.id}</Mono>
          <div className="mt-4"><Button variant="ghost" size="sm" onClick={onClose}>Close</Button></div>
        </div>
      )}
    </Drawer>
  )
}

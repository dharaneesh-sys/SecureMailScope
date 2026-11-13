import { Network } from 'lucide-react'
import { AnalysisPicker, ScopeGate, useScopedAnalysis } from '@/components/analysis/Scope'
import { StateBadge, CompletenessBadge } from '@/components/ui/badges'
import { Card, CardHeader, ErrorState, KV, Notice, PageHeader, Spinner, EmptyState } from '@/components/ui/primitives'
import { TabbedPanel } from '@/components/ui/tabs'
import { useProtocols } from '@/hooks/queries'
import type { EmailSession } from '@/types/api'
import { preciseTime } from '@/utils/format'

const LABEL: Record<string, string> = { greeting: 'Server greeting', capabilities: 'Capability list', starttls_command: 'STARTTLS command', stls_command: 'STLS command', starttls_response: 'Server response to STARTTLS', stls_response: 'Server response to STLS', tls_transition: 'TLS transition', content_after_tls: 'Content after TLS' }

function SessionView({ s }: { s: EmailSession }) {
  const proto = s.protocol.toUpperCase()
  return (
    <div className="space-y-4">
      <Card><CardHeader title={`${proto} session · ${s.client} → ${s.server}`} subtitle={`TCP stream ${s.stream_id} · detected by ${s.detected_by}`} action={<CompletenessBadge value={s.completeness} />} />
        <div className="px-5 pb-5 space-y-4"><KV items={[['Banner / greeting', s.banner ?? 'not observed'], ['First packet', preciseTime(s.first_ts)], ['Capabilities', s.capabilities.join(', ') || 'not observed'], ['Implicit TLS', s.implicit_tls ? 'Yes - connection starts with TLS' : 'No']]} />
          {s.notes.map((n) => <Notice key={n} tone="info">{n}</Notice>)}</div></Card>
      <Card><CardHeader title="Negotiation checklist" subtitle="Absence of an event is reported as “not observed”, never as proof of an insecure configuration." />
        <div className="grid gap-2 px-5 pb-5 sm:grid-cols-2">{Object.entries(s.states).map(([k, v]) => <div key={k} className="flex items-center justify-between rounded-lg border border-line bg-bg/50 px-3 py-2 text-sm"><span>{LABEL[k] ?? k.replace(/_/g, ' ')}</span><StateBadge state={v} /></div>)}</div></Card>
      <Card><CardHeader title="Event timeline" subtitle="Credentials, mail addresses and message bodies are never stored." />
        {s.events.length === 0 ? <div className="px-5 pb-5 text-sm text-mute">No decodable protocol events.</div> : (
          <ol className="px-5 pb-5 relative border-l border-line ml-5">{s.events.map((e, i) => (
            <li key={i} className="pb-3 pl-5 relative"><span className={`absolute -left-[5px] top-1.5 size-2.5 rounded-full ${e.kind === 'tls_transition' ? 'bg-accent' : e.direction.startsWith('client') ? 'bg-accent2' : 'bg-mute'}`} />
              <div className="text-sm"><span className="font-mono text-xs text-mute">#{e.frame}</span> <span className="text-xs text-mute">{e.direction === 'client->server' ? 'C → S' : 'S → C'}</span> <span className="font-mono text-[13px]">{e.summary}</span></div>
              <div className="text-[11px] text-mute">{preciseTime(e.ts)} · {e.kind.replace('_', ' ')}</div></li>))}</ol>)}</Card>
    </div>
  )
}

export default function ProtocolsPage() {
  const { id, list, fromUrl } = useScopedAnalysis()
  const { data, isLoading, error, refetch } = useProtocols(id)
  return (
    <div className="fade-in">
      <PageHeader title="Protocol explorer" description="SMTP, IMAP and POP3 sessions with their STARTTLS/STLS negotiation, in capture order." actions={<AnalysisPicker current={id} suffix="protocols" />} />
      <ScopeGate id={id} loading={!fromUrl && list.isLoading}>
        {isLoading ? <Spinner /> : error || !data ? <ErrorState error={error} onRetry={refetch} /> : data.sessions.length === 0 ? (
          <EmptyState icon={<Network className="size-5" />} title="No email sessions identified" description="No SMTP, IMAP or POP3 traffic was recognised in this capture (check the analysis options and limitations)." />
        ) : (
          <TabbedPanel tabs={['smtp', 'imap', 'pop3'].map((p) => { const ss = data.sessions.filter((s) => s.protocol === p); return { value: p, label: `${p.toUpperCase()} (${ss.length})`, content: ss.length ? <div className="space-y-6">{ss.map((s) => <SessionView key={s.stream_id} s={s} />)}</div> : <div className="text-sm text-mute py-6">No {p.toUpperCase()} sessions in this capture.</div> } })} defaultValue={data.sessions[0].protocol} />
        )}
        {data && data.streams.length > 0 && (
          <Card className="mt-6"><CardHeader title="TCP streams" subtitle="Reassembly quality as reported by TShark" />
            <div className="table-wrap"><table className="data"><thead><tr><th>Stream</th><th>Client → server</th><th>Protocol</th><th>Frames</th><th>Retrans.</th><th>Out-of-order</th><th>Missing</th><th>Handshake / close</th></tr></thead><tbody>
              {data.streams.map((s) => <tr key={s.stream_id}><td>{s.stream_id}</td><td className="font-mono text-xs">{s.client} → {s.server}</td><td className="uppercase text-xs">{s.protocol ?? 'not email'}</td><td>{s.frames}</td><td>{s.quality.retransmissions}</td><td>{s.quality.out_of_order}</td><td>{s.quality.lost_segments}</td><td className="text-xs text-mute">{s.quality.syn ? 'SYN seen' : 'mid-stream start'} · {s.quality.fin || s.quality.rst ? 'closed' : 'no close seen'}</td></tr>)}</tbody></table></div></Card>)}
      </ScopeGate>
    </div>
  )
}

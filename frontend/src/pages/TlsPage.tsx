import { Lock } from 'lucide-react'
import { Link } from 'react-router-dom'
import { AnalysisPicker, ScopeGate, useScopedAnalysis } from '@/components/analysis/Scope'
import { CompletenessBadge } from '@/components/ui/badges'
import { Card, CardHeader, EmptyState, ErrorState, KV, Notice, PageHeader, Spinner } from '@/components/ui/primitives'
import { useTls } from '@/hooks/queries'
import type { TlsSession } from '@/types/api'
import { preciseTime } from '@/utils/format'

const WEAK: Record<string, string> = { null: 'NULL encryption', export: 'EXPORT-grade', rc4: 'RC4', des: 'DES / 3DES', anon: 'Anonymous key exchange', cbc: 'CBC mode', no_pfs: 'No forward secrecy' }

function Session({ s }: { s: TlsSession }) {
  const ch = s.client_hello, sh = s.server_hello
  return (
    <Card>
      <CardHeader title={`TLS session · ${s.client} → ${s.server}`} subtitle={`TCP stream ${s.stream_id}${s.carrier_protocol ? ` · carried by ${s.carrier_protocol.toUpperCase()}` : ''}${s.via_starttls ? ' · after STARTTLS/STLS' : ' · implicit TLS'}`} action={<CompletenessBadge value={s.completeness} />} />
      <div className="space-y-5 px-5 pb-5">
        <KV items={[['Negotiated version', s.selected_version ?? 'not observed'], ['Selected cipher suite', s.selected_cipher ?? 'not observed'], ['SNI', ch?.sni ?? 'not observed'], ['ALPN', ch?.alpn.join(', ') || 'not observed'], ['Version source', sh?.version_source ?? '-'], ['Alerts', s.flags.alerts.join(', ') || 'none observed']]} />
        {s.notes.map((n) => <Notice key={n} tone="info">{n}</Notice>)}
        <div className="grid gap-3 sm:grid-cols-4 text-sm">
          {([['ServerHello', !!sh], ['Certificate visible', s.flags.certificate_visible], ['ChangeCipherSpec', s.flags.change_cipher_spec], ['Encrypted after hello', s.flags.encrypted_after_hello]] as const).map(([l, v]) => <div key={l} className="rounded-lg border border-line bg-bg/50 px-3 py-2"><div className="text-xs text-mute">{l}</div><div className={v ? 'text-accent' : 'text-mute'}>{v ? 'Observed' : 'Not observed'}</div></div>)}
        </div>
        {ch && (
          <div>
            <h3 className="mb-2 text-sm font-semibold">Client-offered cipher suites ({ch.cipher_suites.length}) <span className="font-normal text-mute">· frame #{ch.frame} · {preciseTime(ch.ts)}</span></h3>
            <div className="table-wrap max-h-72 overflow-auto"><table className="data"><thead><tr><th>ID</th><th>Name</th><th>Classification</th></tr></thead><tbody>
              {ch.cipher_suites.map((c, i) => <tr key={`${c.id}${i}`}><td className="font-mono text-xs">{c.id}</td><td className="font-mono text-xs">{c.name}</td><td>{c.weak_class ? <span className="text-warn text-xs">{WEAK[c.weak_class] ?? c.weak_class}</span> : <span className="text-mute text-xs">{c.known ? 'no weakness class' : 'not in catalogue'}</span>}</td></tr>)}</tbody></table></div>
            <p className="mt-2 text-xs text-mute">A weak suite in this list is an <b>offer</b> by the client, not proof the server accepted it. Offered ≠ negotiated.</p>
            <div className="mt-3 grid gap-3 sm:grid-cols-2"><KV cols={1} items={[['Supported versions', ch.supported_versions.join(', ') || '-'], ['Legacy version field', ch.legacy_version ?? '-']]} /><KV cols={1} items={[['Supported groups', ch.supported_groups.join(', ') || '-'], ['Signature algorithms', ch.signature_algorithms.join(', ') || '-']]} /></div>
          </div>)}
        <div className="text-xs text-mute">Evidence frames: {s.flags.frames.map((f) => `#${f}`).join(', ') || '-'} · <Link className="text-accent2 underline" to="../evidence">open Evidence Explorer</Link></div>
      </div>
    </Card>
  )
}

export default function TlsPage() {
  const { id, list, fromUrl } = useScopedAnalysis()
  const { data, isLoading, error, refetch } = useTls(id)
  return (
    <div className="fade-in">
      <PageHeader title="TLS inspector" description="Handshake metadata: versions, offered vs selected cipher suites, extensions. Encrypted content is never decrypted." actions={<AnalysisPicker current={id} suffix="tls" />} />
      <ScopeGate id={id} loading={!fromUrl && list.isLoading}>
        {isLoading ? <Spinner /> : error || !data ? <ErrorState error={error} onRetry={refetch} /> : data.sessions.length === 0 ? <EmptyState icon={<Lock className="size-5" />} title="No TLS handshakes observed" description="This capture contains no TLS handshake (for example, plaintext-only or incomplete capture)." /> : <div className="space-y-6">{data.sessions.map((s) => <Session key={s.stream_id} s={s} />)}</div>}
      </ScopeGate>
    </div>
  )
}

import { ShieldCheck } from 'lucide-react'
import { AnalysisPicker, ScopeGate, useScopedAnalysis } from '@/components/analysis/Scope'
import { Card, CardHeader, CopyButton, EmptyState, ErrorState, KV, Notice, PageHeader, Spinner } from '@/components/ui/primitives'
import { useCertificates } from '@/hooks/queries'
import type { CertCheck } from '@/types/api'

const TONE: Record<CertCheck['result'], string> = { pass: 'text-accent', fail: 'text-crit', info: 'text-accent2', unknown: 'text-warn', not_performed: 'text-mute' }
const LABEL: Record<CertCheck['result'], string> = { pass: 'Pass', fail: 'Fail', info: 'Info', unknown: 'Unknown', not_performed: 'Not performed' }

export default function CertificatesPage() {
  const { id, list, fromUrl } = useScopedAnalysis()
  const { data, isLoading, error, refetch } = useCertificates(id)
  return (
    <div className="fade-in">
      <PageHeader title="Certificate inspector" description="Parsed certificate metadata and local checks. This tool does not validate trust chains, revocation or hostname identity." actions={<AnalysisPicker current={id} suffix="certificates" />} />
      <ScopeGate id={id} loading={!fromUrl && list.isLoading}>
        {isLoading ? <Spinner /> : error || !data ? <ErrorState error={error} onRetry={refetch} /> : (
          <div className="space-y-6">
            {data.notice && <Notice tone="info">{data.notice}</Notice>}
            {data.unavailable.map((u) => <Notice key={u.stream_id} tone="warn" title={`Stream ${u.stream_id}: certificates unavailable`}>{u.reason}</Notice>)}
            {data.certificates.length === 0 && data.unavailable.length === 0 && <EmptyState icon={<ShieldCheck className="size-5" />} title="No certificates observed" description="No certificate message was visible in this capture." />}
            {data.certificates.map((c) => (
              <Card key={c.id}>
                <CardHeader title={c.subject} subtitle={`Stream ${c.stream_id} · chain position ${c.position}${c.frame ? ` · frame #${c.frame}` : ''}${c.self_signed ? ' · self-signed' : ''}`} />
                <div className="space-y-4 px-5 pb-5">
                  <KV items={[['Issuer', c.issuer], ['Serial', <span className="font-mono text-xs break-all">{c.serial}</span>], ['Valid from', c.not_before], ['Valid until', c.not_after], ['Signature algorithm', c.sig_algorithm], ['Public key', `${c.key_algorithm}${c.key_size ? ` ${c.key_size}-bit` : ''}`], ['Subject alt. names', c.san.join(', ') || 'none'], ['SHA-256 fingerprint', <span className="font-mono text-xs break-all">{c.sha256}<CopyButton value={c.sha256} label="Copy fingerprint" /></span>]]} />
                  <div className="table-wrap"><table className="data"><thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>{c.checks.map((k) => <tr key={k.check}><td>{k.check}</td><td className={`font-semibold ${TONE[k.result]}`}>{LABEL[k.result]}</td><td className="text-mute">{k.detail}</td></tr>)}</tbody></table></div>
                </div>
              </Card>))}
          </div>)}
      </ScopeGate>
    </div>
  )
}

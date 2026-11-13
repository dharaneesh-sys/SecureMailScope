import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis } from 'recharts'
import { Link } from 'react-router-dom'
import { AnalysisPicker, ScopeGate, useScopedAnalysis } from '@/components/analysis/Scope'
import { ScoreChip, SeverityBadge } from '@/components/ui/badges'
import { Card, CardHeader, ErrorState, Notice, PageHeader, Spinner } from '@/components/ui/primitives'
import { useFindings } from '@/hooks/queries'
import { SEV_COLOR } from '@/utils/format'

export default function RiskPage() {
  const { id, list, fromUrl } = useScopedAnalysis()
  const { data, isLoading, error, refetch } = useFindings({ sort: 'risk', order: 'desc', page_size: 100 }, id)
  const top = (data?.items ?? []).slice(0, 10).map((f) => ({ name: f.ref, score: f.risk_score, sev: f.severity, title: f.title }))
  return (
    <div className="fade-in">
      <PageHeader title="Risk" description="Findings ranked by the SMRS-1 score. This is a transparent prioritisation aid, not CVSS and not a probability of compromise." actions={<AnalysisPicker current={id} suffix="results" />} />
      <Notice tone="info" title="How the score is built">
        Score = base(severity: critical 90 · high 70 · medium 45 · low 20 · info 5) × observation factor (weakness observed 1.0 · weak option offered 0.6 · protocol feature 0.5 · insufficient evidence 0.4 · secure configuration 0.2) × evidence-completeness factor (complete 1.0 · partial 0.85 · incomplete 0.6), plus min(10, 3×(n−1)) for n affected sessions (non-informational rules) and 5 for plaintext authentication (SMS-STL-004). Every factor is shown per finding.
      </Notice>
      <ScopeGate id={id} loading={!fromUrl && list.isLoading}>
        {isLoading ? <Spinner /> : error || !data ? <ErrorState error={error} onRetry={refetch} /> : (
          <div className="mt-6 grid gap-6 lg:grid-cols-[1fr_1.2fr]">
            <Card><CardHeader title="Top findings by score" />
              <div className="h-72 px-3 pb-4" role="img" aria-label="Bar chart of top finding risk scores">
                {top.length === 0 ? <p className="p-4 text-sm text-mute">No findings.</p> : <ResponsiveContainer><BarChart data={top} layout="vertical" margin={{ left: 10 }}><CartesianGrid stroke="#26364B" horizontal={false} /><XAxis type="number" domain={[0, 100]} stroke="#8a9bb3" fontSize={11} /><YAxis type="category" dataKey="name" stroke="#8a9bb3" fontSize={11} width={70} /><RTooltip contentStyle={{ background: '#172438', border: '1px solid #26364B', borderRadius: 8 }} formatter={(v) => [String(v), 'Score']} /><Bar dataKey="score" radius={4}>{top.map((t, i) => <Cell key={i} fill={SEV_COLOR[t.sev]} />)}</Bar></BarChart></ResponsiveContainer>}
              </div></Card>
            <Card><CardHeader title="Prioritised findings" />
              <div className="table-wrap"><table className="data"><thead><tr><th>Score</th><th>Severity</th><th>Finding</th><th>Recommended action</th></tr></thead><tbody>
                {data.items.map((f) => <tr key={f.id}><td><ScoreChip score={f.risk_score} /></td><td><SeverityBadge severity={f.severity} compact /></td><td className="max-w-56"><Link className="text-accent2 hover:underline" to={`/findings?open=${f.id}`}>{f.ref} · {f.title}</Link></td><td className="max-w-64 text-xs text-mute">{f.risk.recommended_action}</td></tr>)}</tbody></table></div></Card>
          </div>)}
      </ScopeGate>
    </div>
  )
}

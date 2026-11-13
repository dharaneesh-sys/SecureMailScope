import { ChevronDown, Search } from 'lucide-react'
import { useState } from 'react'
import { SeverityBadge } from '@/components/ui/badges'
import { Card, CardHeader, ErrorState, Input, Notice, PageHeader, Select, Spinner, Switch } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { useRules, useToggleRule } from '@/hooks/queries'
import { dateTime } from '@/utils/format'

export default function RulesPage() {
  const { data, isLoading, error, refetch } = useRules()
  const toggle = useToggleRule(), toast = useToast()
  const [q, setQ] = useState(''), [cat, setCat] = useState(''), [open, setOpen] = useState<string | null>(null)
  if (isLoading) return <Spinner />
  if (error || !data) return <ErrorState error={error} onRetry={refetch} />
  const cats = [...new Set(data.items.map((r) => r.category))]
  const rows = data.items.filter((r) => (!cat || r.category === cat) && (!q || `${r.rule_id} ${r.name} ${r.description}`.toLowerCase().includes(q.toLowerCase())))
  return (
    <div className="fade-in">
      <PageHeader title="Rules" description={<>Deterministic detection rules. Current rule-set version: <span className="font-mono">{data.current_ruleset}</span></>} />
      <Notice tone="info">{data.note}</Notice>
      <Card className="mt-6">
        <div className="flex flex-wrap gap-2 border-b border-line p-4"><div className="relative min-w-52 flex-1"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-mute" /><Input aria-label="Search rules" className="pl-9" placeholder="Search rules…" value={q} onChange={(e) => setQ(e.target.value)} /></div><Select aria-label="Category" value={cat} onChange={(e) => setCat(e.target.value)}><option value="">All categories</option>{cats.map((c) => <option key={c}>{c}</option>)}</Select></div>
        <ul>{rows.map((r) => (
          <li key={r.rule_id} className="border-b border-line last:border-0">
            <div className="flex items-center gap-3 px-4 py-3">
              <button className="flex flex-1 items-center gap-3 text-left" aria-expanded={open === r.rule_id} onClick={() => setOpen(open === r.rule_id ? null : r.rule_id)}><ChevronDown className={`size-4 text-mute transition ${open === r.rule_id ? 'rotate-180' : ''}`} /><span className="font-mono text-xs text-accent w-24 shrink-0">{r.rule_id}</span><span className="text-sm font-medium">{r.name}</span></button>
              <span className="hidden sm:inline text-xs text-mute">{r.findings_total} findings</span><SeverityBadge severity={r.severity} compact />
              <Switch checked={r.enabled} label={`${r.enabled ? 'Disable' : 'Enable'} ${r.rule_id}`} onChange={(v) => toggle.mutate({ id: r.rule_id, enabled: v }, { onSuccess: () => toast({ tone: 'ok', title: `${r.rule_id} ${v ? 'enabled' : 'disabled'}`, body: 'Applies to new analyses; creates a new rule-set version.' }), onError: (e) => toast({ tone: 'err', title: 'Update failed', body: e.message }) })} />
            </div>
            {open === r.rule_id && <div className="space-y-3 bg-bg/40 px-5 py-4 text-sm"><p>{r.description}</p><p><b className="text-mute">Detection logic:</b> {r.detection}</p><p><b className="text-mute">Evidence required:</b> {r.evidence_requirements}</p><p><b className="text-mute">Remediation:</b> {r.remediation}</p>{r.references.length > 0 && <p className="text-xs text-mute">References: {r.references.join(' · ')}</p>}<p className="text-xs text-mute">Category {r.category} · rule version {r.version}</p></div>}
          </li>))}
          {rows.length === 0 && <li className="p-6 text-center text-sm text-mute">No rules match.</li>}</ul>
      </Card>
      <Card className="mt-6"><CardHeader title="Rule-set history" subtitle="A new version is recorded whenever rules change or are toggled; each analysis stores the version it used." />
        <div className="table-wrap"><table className="data"><thead><tr><th>Version</th><th>Recorded</th><th>Enabled</th><th>Note</th></tr></thead><tbody>{data.history.map((h) => <tr key={h.signature}><td className="font-mono text-xs">{h.signature}</td><td className="text-mute">{dateTime(h.created_at)}</td><td>{h.enabled_count}/{h.total}</td><td className="text-mute">{h.note ?? '-'}</td></tr>)}</tbody></table></div></Card>
    </div>
  )
}

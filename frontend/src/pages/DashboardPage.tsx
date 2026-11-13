import { Activity, AlertOctagon, Database, FileSearch, Lock, Mail, Plus, ShieldCheck, Wand2 } from 'lucide-react'
import { Link, useNavigate } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { SeverityBadge, StatusBadge } from '@/components/ui/badges'
import { Button, Card, CardHeader, EmptyState, ErrorState, PageHeader, Skeleton, Stat } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { useDashboard, useLoadDemo } from '@/hooks/queries'
import { SEVERITIES, SEV_COLOR, SEV_LABEL, dateTime, relTime } from '@/utils/format'

const tip = { contentStyle: { background: '#172438', border: '1px solid #26364b', borderRadius: 8, fontSize: 12 }, itemStyle: { color: '#e8eef7' }, labelStyle: { color: '#91a0b5' } }

function ChartCard({ title, subtitle, children, empty }: { title: string; subtitle?: string; children: React.ReactNode; empty: boolean }) {
  return (
    <Card><CardHeader title={title} subtitle={subtitle} />
      <div className="h-60 px-3 pb-4">{empty ? <div className="h-full grid place-items-center text-sm text-mute">No data yet</div> : children}</div></Card>
  )
}

export default function DashboardPage() {
  const { data, isLoading, error, refetch } = useDashboard()
  const nav = useNavigate()
  const toast = useToast()
  const demo = useLoadDemo()
  if (isLoading) return <div className="space-y-4"><Skeleton className="h-24" /><div className="grid grid-cols-2 lg:grid-cols-6 gap-3">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-24" />)}</div><Skeleton className="h-64" /></div>
  if (error || !data) return <ErrorState error={error} onRetry={refetch} />
  const m = data.metrics
  const loadDemo = () => demo.mutate(undefined, {
    onSuccess: (r) => toast({ tone: 'ok', title: r.created.length ? 'Demo dataset loading' : 'Demo dataset already loaded', body: 'Synthetic captures are analysed with the real engine.' }),
    onError: (e) => toast({ tone: 'err', title: 'Could not load demo data', body: e.message }),
  })
  const sevData = SEVERITIES.map((s) => ({ name: SEV_LABEL[s], value: data.severity[s], key: s })).filter((d) => d.value > 0)

  return (
    <div className="space-y-6 fade-in">
      <div className="hero-grad card px-6 py-6 flex flex-wrap items-center justify-between gap-4">
        <div className="max-w-2xl">
          <div className="flex items-center gap-2 text-xs text-accent mb-2"><Activity className="size-3.5" />{data.recent_analyses[0] ? `Last activity ${relTime(data.recent_analyses[0].created_at)}` : 'No activity yet'}</div>
          <h1 className="text-2xl font-semibold tracking-tight">SecureMailScope</h1>
          <p className="mt-1 text-sm text-mute">Passive, evidence-linked assessment of email cryptographic posture. Upload an authorised PCAP; SMTP, IMAP and POP3 sessions, STARTTLS/STLS transitions, TLS handshakes and certificate metadata are checked by deterministic rules, each tied to packet evidence.</p>
        </div>
        <div className="flex gap-2"><Button variant="primary" onClick={() => nav('/analysis/new')}><Plus className="size-4" />New analysis</Button></div>
      </div>

      {m.captures === 0 ? (
        <Card><EmptyState icon={<FileSearch className="size-5" />} title="Welcome - no captures analysed yet" description="Upload an authorised PCAP to begin, or explore with the clearly-labelled synthetic demonstration dataset."
          action={<div className="flex flex-wrap gap-2 justify-center"><Button variant="primary" onClick={() => nav('/analysis/new')}>Upload a PCAP</Button><Button onClick={loadDemo} loading={demo.isPending}><Wand2 className="size-4" />Load SecureMailScope Demo Dataset</Button></div>} /></Card>
      ) : (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
            <Stat label="Captures analysed" value={m.analyses_completed} hint={`${m.captures} uploaded`} icon={<Database className="size-4" />} />
            <Stat label="Email sessions" value={m.email_sessions} icon={<Mail className="size-4" />} />
            <Stat label="Security findings" value={m.findings} hint="incl. informational" icon={<ShieldCheck className="size-4" />} />
            <Stat label="Critical / high" value={m.critical_high} tone={m.critical_high ? 'crit' : 'accent'} icon={<AlertOctagon className="size-4" />} />
            <Stat label="TLS sessions inspected" value={m.tls_sessions} hint={`${m.certificates} certificates`} icon={<Lock className="size-4" />} />
            <Stat label="Analysis success rate" value={m.success_rate === null ? '-' : `${m.success_rate}%`} icon={<Activity className="size-4" />} />
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            <ChartCard title="Findings by severity" empty={!sevData.length}>
              <ResponsiveContainer><PieChart><Pie data={sevData} dataKey="value" nameKey="name" innerRadius={52} outerRadius={82} paddingAngle={2} stroke="none">{sevData.map((d) => <Cell key={d.key} fill={SEV_COLOR[d.key]} />)}</Pie><Tooltip {...tip} /><Legend iconType="circle" wrapperStyle={{ fontSize: 12 }} /></PieChart></ResponsiveContainer>
            </ChartCard>
            <ChartCard title="Findings over time" subtitle="by day of analysis" empty={!data.findings_over_time.length}>
              <ResponsiveContainer><LineChart data={data.findings_over_time}><CartesianGrid stroke="#26364b" strokeDasharray="3 3" /><XAxis dataKey="date" stroke="#91a0b5" fontSize={11} /><YAxis allowDecimals={false} stroke="#91a0b5" fontSize={11} /><Tooltip {...tip} />
                {SEVERITIES.filter((s) => data.findings_over_time.some((d) => d[s] > 0)).map((s) => <Line key={s} type="monotone" dataKey={s} name={SEV_LABEL[s]} stroke={SEV_COLOR[s]} strokeWidth={2} dot />)}</LineChart></ResponsiveContainer>
            </ChartCard>
            <ChartCard title="Protocol distribution" subtitle="email sessions" empty={!data.protocols.length}>
              <ResponsiveContainer><BarChart data={data.protocols}><CartesianGrid stroke="#26364b" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="name" stroke="#91a0b5" fontSize={11} /><YAxis allowDecimals={false} stroke="#91a0b5" fontSize={11} /><Tooltip {...tip} cursor={{ fill: '#1d2d45' }} /><Bar dataKey="value" name="Sessions" fill="#68a7ff" radius={[6, 6, 0, 0]} /></BarChart></ResponsiveContainer>
            </ChartCard>
            <ChartCard title="TLS version distribution" subtitle="negotiated" empty={!data.tls_versions.length}>
              <ResponsiveContainer><BarChart data={data.tls_versions}><CartesianGrid stroke="#26364b" strokeDasharray="3 3" vertical={false} /><XAxis dataKey="name" stroke="#91a0b5" fontSize={10} /><YAxis allowDecimals={false} stroke="#91a0b5" fontSize={11} /><Tooltip {...tip} cursor={{ fill: '#1d2d45' }} /><Bar dataKey="value" name="Sessions" radius={[6, 6, 0, 0]}>{data.tls_versions.map((d, i) => <Cell key={i} fill={/1\.[01]$|SSL/.test(d.name) ? '#f06b75' : d.name.startsWith('Unknown') ? '#8a9bb3' : '#36d6b0'} />)}</Bar></BarChart></ResponsiveContainer>
            </ChartCard>
            <div className="lg:col-span-2"><ChartCard title="Selected cipher suites" empty={!data.ciphers.length}>
              <ResponsiveContainer><BarChart data={data.ciphers} layout="vertical" margin={{ left: 40 }}><CartesianGrid stroke="#26364b" strokeDasharray="3 3" horizontal={false} /><XAxis type="number" allowDecimals={false} stroke="#91a0b5" fontSize={11} /><YAxis type="category" dataKey="name" width={260} stroke="#91a0b5" fontSize={10} /><Tooltip {...tip} cursor={{ fill: '#1d2d45' }} /><Bar dataKey="value" name="Sessions" fill="#36d6b0" radius={[0, 6, 6, 0]} /></BarChart></ResponsiveContainer>
            </ChartCard></div>
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <Card><CardHeader title="Recent analyses" action={<Link to="/history" className="text-xs text-accent2 hover:underline">View all</Link>} />
              <div className="table-wrap"><table className="data"><thead><tr><th>Capture</th><th>Date</th><th>Protocols</th><th>Findings</th><th>Highest</th><th>Status</th><th /></tr></thead><tbody>
                {data.recent_analyses.map((a) => (
                  <tr key={a.id}><td className="max-w-48 truncate font-medium">{a.capture?.filename}</td><td className="whitespace-nowrap text-mute">{dateTime(a.created_at)}</td><td className="uppercase text-xs">{a.protocols.join(', ') || '-'}</td>
                    <td className="tabular-nums">{a.counters.findings ?? '-'}</td><td>{a.highest_severity ? <SeverityBadge severity={a.highest_severity} /> : '-'}</td><td><StatusBadge status={a.status} /></td>
                    <td><Link className="text-accent2 hover:underline text-xs" to={a.status === 'completed' ? `/analysis/${a.id}/results` : `/analysis/${a.id}`}>Details</Link></td></tr>
                ))}</tbody></table></div></Card>
            <Card><CardHeader title="Recent security findings" subtitle="excluding informational" action={<Link to="/findings" className="text-xs text-accent2 hover:underline">View all</Link>} />
              {data.recent_findings.length === 0 ? <div className="px-5 pb-6 text-sm text-mute">No weaknesses recorded.</div> : (
                <ul className="divide-y divide-line/60">{data.recent_findings.map((f) => (
                  <li key={f.id} className="flex items-center gap-3 px-5 py-3"><SeverityBadge severity={f.severity} />
                    <div className="min-w-0 flex-1"><div className="truncate text-sm font-medium">{f.title}</div><div className="text-xs text-mute truncate"><span className="font-mono">{f.rule_id}</span> · {f.capture} · {relTime(f.created_at)}</div></div>
                    <Link className="text-xs text-accent2 hover:underline whitespace-nowrap" to={`/findings?open=${f.id}`}>View evidence</Link></li>))}</ul>)}
            </Card>
          </div>
        </>
      )}
    </div>
  )
}
export { PageHeader }

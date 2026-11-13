import { zodResolver } from '@hookform/resolvers/zod'
import { forwardRef, useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { Button, Card, CardHeader, ErrorState, Input, KV, Label, Notice, PageHeader, Select, Spinner } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { useAppLogs, useAuditLog, useDependencies, useRunRetention, useSaveSettings, useSettings } from '@/hooks/queries'
import { dateTime } from '@/utils/format'

const schema = z.object({
  local_only_mode: z.boolean(), retain_original_captures: z.boolean(), report_include_hex: z.boolean(),
  retention_days: z.coerce.number().int().min(1, 'At least 1 day').max(3650),
  cert_reference: z.enum(['capture', 'analysis']), ai_provider: z.enum(['none', 'ollama', 'openai_compatible']),
  ai_endpoint: z.string().max(300), ai_model: z.string().max(100), report_organisation: z.string().max(120), analyst_name: z.string().max(120),
})
type Form = z.infer<typeof schema>

const Check = forwardRef<HTMLInputElement, { id: string; label: string; hint?: string } & React.InputHTMLAttributes<HTMLInputElement>>(function Check({ id, label, hint, ...r }, ref) {
  return <div className="flex items-start gap-3"><input ref={ref} id={id} type="checkbox" className="mt-1 size-4 accent-[#36D6B0]" {...r} /><label htmlFor={id} className="text-sm">{label}{hint && <span className="block text-xs text-mute">{hint}</span>}</label></div>
})

export default function SettingsPage() {
  const s = useSettings(), deps = useDependencies(), logs = useAppLogs(), audit = useAuditLog()
  const save = useSaveSettings(), retention = useRunRetention(), toast = useToast()
  const { register, handleSubmit, reset, formState: { errors, isDirty } } = useForm({ resolver: zodResolver(schema) })
  useEffect(() => { if (s.data) reset(s.data.settings as Form) }, [s.data, reset])
  if (s.isLoading) return <Spinner />
  if (s.error || !s.data) return <ErrorState error={s.error} onRetry={s.refetch} />
  const t = deps.data?.tshark
  return (
    <div className="fade-in">
      <PageHeader title="Settings" description="Local configuration. Nothing leaves this machine unless you enable an AI provider and turn off local-only mode." />
      <div className="grid gap-6 xl:grid-cols-2">
        <Card><CardHeader title="Environment" />
          <div className="px-5 pb-5 space-y-3">
            {t && (t.available ? <Notice tone="ok" title="TShark available">{t.version}</Notice> : <Notice tone="crit" title="TShark not found">{t.error ?? deps.data?.guidance}</Notice>)}
            <KV items={[['TShark path', t?.path ?? 'not found'], ['editcap', t?.editcap ?? 'not found'], ['Python', deps.data?.python ?? '-'], ['Max upload', `${deps.data?.limits.max_upload_mb ?? '-'} MB`], ['Analysis timeout', `${deps.data?.limits.analysis_timeout_s ?? '-'} s`], ['Max packets', deps.data?.limits.max_packets ?? '-']]} />
          </div></Card>
        <form onSubmit={handleSubmit((v) => save.mutate(v as Partial<Form>, { onSuccess: () => toast({ tone: 'ok', title: 'Settings saved' }), onError: (e) => toast({ tone: 'err', title: 'Save failed', body: e.message }) }))} noValidate>
          <Card><CardHeader title="Preferences" />
            <div className="space-y-4 px-5 pb-5">
              <Check id="lo" label="Local-only mode" hint="Blocks any network call by the AI layer to non-loopback addresses." {...register('local_only_mode')} />
              <Check id="roc" label="Keep original capture files" hint="If off, only derived metadata is kept after analysis." {...register('retain_original_captures')} />
              <Check id="rih" label="Include raw hex of TLS handshake frames in reports" {...register('report_include_hex')} />
              <div><Label htmlFor="rd">Retention (days)</Label><Input id="rd" type="number" {...register('retention_days')} aria-invalid={!!errors.retention_days} />{errors.retention_days && <p role="alert" className="mt-1 text-xs text-crit">{errors.retention_days.message as string}</p>}</div>
              <div><Label htmlFor="cr">Certificate validity reference time</Label><Select id="cr" {...register('cert_reference')}><option value="capture">Capture time (recommended)</option><option value="analysis">Analysis time (now)</option></Select></div>
              <div className="grid gap-3 sm:grid-cols-2"><div><Label htmlFor="org">Report organisation</Label><Input id="org" {...register('report_organisation')} /></div><div><Label htmlFor="an">Analyst name</Label><Input id="an" {...register('analyst_name')} /></div></div>
              <h3 className="pt-2 text-sm font-semibold">Optional AI explanations</h3>
              <p className="text-xs text-mute">AI only explains findings the rule engine already established, from structured metadata. It never decides facts or sees packet payloads.</p>
              <div className="grid gap-3 sm:grid-cols-3"><div><Label htmlFor="ap">Provider</Label><Select id="ap" {...register('ai_provider')}><option value="none">Disabled</option><option value="ollama">Ollama (local)</option><option value="openai_compatible">OpenAI-compatible</option></Select></div><div><Label htmlFor="ae">Endpoint</Label><Input id="ae" placeholder="http://127.0.0.1:11434" {...register('ai_endpoint')} /></div><div><Label htmlFor="am">Model</Label><Input id="am" {...register('ai_model')} /></div></div>
              <div className="flex gap-2"><Button type="submit" variant="primary" loading={save.isPending} disabled={!isDirty}>Save settings</Button><Button type="button" onClick={() => retention.mutate(undefined, { onSuccess: (r) => toast({ tone: 'ok', title: 'Retention run complete', body: `${r.original_captures_removed} original file(s) removed (${r.retention_days}-day policy)` }) })} loading={retention.isPending}>Run retention now</Button></div>
            </div></Card>
        </form>
        <Card><CardHeader title="Application log" subtitle="Last lines" />
          <pre className="max-h-72 overflow-auto px-5 pb-5 text-[11px] leading-5 text-mute whitespace-pre-wrap" tabIndex={0}>{logs.data?.lines.join('\n') || 'No log lines.'}</pre></Card>
        <Card><CardHeader title="Audit log" subtitle="Security-relevant actions (no sensitive values)" />
          <div className="table-wrap max-h-72 overflow-auto"><table className="data"><thead><tr><th>When</th><th>Action</th><th>Subject</th></tr></thead><tbody>{audit.data?.items.map((a) => <tr key={a.id}><td className="whitespace-nowrap text-mute">{dateTime(a.at)}</td><td className="font-mono text-xs">{a.action}</td><td className="max-w-48 truncate text-xs text-mute">{a.subject ?? '-'}</td></tr>)}</tbody></table></div></Card>
      </div>
    </div>
  )
}

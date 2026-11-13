import { zodResolver } from '@hookform/resolvers/zod'
import { FileUp, ShieldCheck, Trash2 } from 'lucide-react'
import { useCallback, useRef, useState } from 'react'
import { Controller, useForm } from 'react-hook-form'
import { useNavigate } from 'react-router-dom'
import { z } from 'zod'
import { Button, Card, CardHeader, Checkbox, KV, Mono, Notice, PageHeader, Progress, Switch } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { useDependencies, useSettings, useStartAnalysis } from '@/hooks/queries'
import { uploadCapture } from '@/services/api'
import type { UploadResult } from '@/types/api'
import { bytes, cn, dateTime } from '@/utils/format'

const schema = z.object({
  authorised: z.literal(true, { errorMap: () => ({ message: 'You must confirm you are authorised to analyse this capture.' }) }),
  detect_smtp: z.boolean(), detect_imap: z.boolean(), detect_pop3: z.boolean(), inspect_tls: z.boolean(), inspect_certificates: z.boolean(), apply_rules: z.boolean(), generate_report: z.boolean(),
})
type FormValues = z.infer<typeof schema>
const OPTIONS: [keyof Omit<FormValues, 'authorised'>, string, string][] = [
  ['detect_smtp', 'Detect SMTP', 'Identify SMTP sessions (ports 25/465/587 and by banner/EHLO on any port).'],
  ['detect_imap', 'Detect IMAP', 'Identify IMAP sessions and STARTTLS.'],
  ['detect_pop3', 'Detect POP3', 'Identify POP3 sessions and STLS.'],
  ['inspect_tls', 'Inspect TLS', 'Parse ClientHello / ServerHello, versions, cipher suites and extensions.'],
  ['inspect_certificates', 'Inspect available certificates', 'Extract certificate metadata when visible (not for TLS 1.3, where it is encrypted).'],
  ['apply_rules', 'Apply security rules', 'Evaluate the deterministic rule set. Off = observations only, no findings.'],
  ['generate_report', 'Generate evidence-linked report', 'Create JSON and HTML reports automatically after analysis.'],
]

async function sha256(file: File): Promise<string | null> {
  try {
    const d = await crypto.subtle.digest('SHA-256', await file.arrayBuffer())
    return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('')
  } catch { return null }
}

export default function NewAnalysisPage() {
  const nav = useNavigate()
  const toast = useToast()
  const deps = useDependencies()
  const settings = useSettings()
  const start = useStartAnalysis()
  const input = useRef<HTMLInputElement>(null)
  const [drag, setDrag] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [clientHash, setClientHash] = useState<string | null>(null)
  const [pct, setPct] = useState(0)
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<UploadResult | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const { control, handleSubmit, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(schema), defaultValues: { authorised: false as unknown as true, detect_smtp: true, detect_imap: true, detect_pop3: true, inspect_tls: true, inspect_certificates: true, apply_rules: true, generate_report: true },
  })
  const maxMb = settings.data?.settings.max_upload_mb ?? 50

  const pick = useCallback(async (f: File | undefined) => {
    setErr(null); setResult(null); setPct(0); setClientHash(null)
    if (!f) return
    if (!/\.(pcap|pcapng|cap)$/i.test(f.name)) return setErr('Only .pcap and .pcapng files are accepted.')
    if (f.size > maxMb * 1024 * 1024) return setErr(`This file is ${bytes(f.size)}; the limit is ${maxMb} MB.`)
    setFile(f); setUploading(true)
    sha256(f).then(setClientHash)
    try { setResult(await uploadCapture(f, setPct)) } catch (e) { setErr(e instanceof Error ? e.message : 'Upload failed'); setFile(null) } finally { setUploading(false) }
  }, [maxMb])

  const onSubmit = handleSubmit((v) => {
    if (!result) return
    const { authorised: _a, ...options } = v
    start.mutate({ capture_id: result.capture.id, options }, {
      onSuccess: (a) => nav(`/analysis/${a.id}`),
      onError: (e) => toast({ tone: 'err', title: 'Could not start analysis', body: e.message }),
    })
  })
  const c = result?.capture
  const mismatch = clientHash && c && clientHash !== c.sha256

  return (
    <div className="fade-in">
      <PageHeader title="New analysis" description="Upload an authorised capture. It is validated by content, hashed, and kept only on this machine; nothing is sent to external services." />
      {deps.data && !deps.data.tshark.available && <div className="mb-4"><Notice tone="crit" title="TShark missing">{deps.data.guidance}</Notice></div>}
      <div className="grid gap-5 xl:grid-cols-[1.1fr_1fr]">
        <div className="space-y-5">
          <Card>
            <CardHeader title="1. Capture file" subtitle={`.pcap or .pcapng, up to ${maxMb} MB`} />
            <div className="px-5 pb-5">
              <div role="button" tabIndex={0} aria-label="Drop a PCAP file here or press Enter to browse"
                onClick={() => input.current?.click()} onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
                onDragOver={(e) => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)} onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files[0]) }}
                className={cn('cursor-pointer rounded-xl border-2 border-dashed px-6 py-10 text-center transition', drag ? 'border-accent bg-accent/10' : 'border-line hover:border-accent2/60 bg-bg/40')}>
                <FileUp className="mx-auto size-9 text-accent" aria-hidden />
                <p className="mt-3 text-sm font-medium">Drag and drop a PCAP here, or click to browse</p>
                <p className="mt-1 text-xs text-mute">Format is checked from the file's content, not just its extension.</p>
                <input ref={input} data-testid="file-input" type="file" accept=".pcap,.pcapng,.cap" className="sr-only" onChange={(e) => { pick(e.target.files?.[0]); e.target.value = '' }} />
              </div>
              {file && uploading && <div className="mt-4"><div className="mb-1 flex justify-between text-xs text-mute"><span className="truncate">{file.name}</span><span>{pct}%</span></div><Progress value={pct} /></div>}
              {err && <div className="mt-4"><Notice tone="crit" title="File rejected">{err}</Notice></div>}
            </div>
          </Card>
          {c && (
            <Card className="fade-in">
              <CardHeader title="Capture summary" action={<Button size="sm" variant="ghost" onClick={() => { setResult(null); setFile(null); setClientHash(null) }}><Trash2 className="size-3.5" />Clear</Button>} />
              <div className="px-5 pb-5 space-y-4">
                {result.duplicate && <Notice tone="warn" title="Duplicate capture">{result.message}</Notice>}
                {c.warnings.map((w) => <Notice key={w} tone="warn">{w}</Notice>)}
                <KV items={[['Filename', c.filename], ['Size', bytes(c.size_bytes)], ['Format', `${c.format.toUpperCase()} · ${c.linktype ?? 'unknown link type'}`], ['Packets', c.packet_count],
                  ['Uploaded', dateTime(c.uploaded_at)], ['SHA-256 (server)', <Mono key="h" copy>{c.sha256}</Mono>],
                  ['SHA-256 (your browser)', clientHash ? <span key="ch" className={mismatch ? 'text-crit' : 'text-accent'}>{mismatch ? 'MISMATCH' : 'matches'}</span> : 'calculating…']]} />
              </div>
            </Card>
          )}
        </div>
        <form onSubmit={onSubmit} className={cn('space-y-5', !c && 'opacity-50 pointer-events-none')} aria-disabled={!c}>
          <Card>
            <CardHeader title="2. Analysis scope" subtitle="Everything here changes what the engine actually runs." />
            <div className="px-5 pb-5 space-y-3">
              {OPTIONS.map(([k, label, help]) => (
                <Controller key={k} control={control} name={k} render={({ field }) => (
                  <div className="flex items-start justify-between gap-4"><div><div className="text-sm">{label}</div><div className="text-xs text-mute">{help}</div></div><Switch label={label} checked={field.value} onChange={field.onChange} /></div>
                )} />
              ))}
            </div>
          </Card>
          <Card>
            <CardHeader title="3. Authorisation" />
            <div className="px-5 pb-5 space-y-4">
              <Controller control={control} name="authorised" render={({ field }) => (
                <Checkbox id="authorised" checked={!!field.value} onChange={field.onChange}>I confirm that this capture was obtained from a system or network that I am authorised to analyse.</Checkbox>
              )} />
              {errors.authorised && <p role="alert" className="text-xs text-crit">{errors.authorised.message}</p>}
              <Notice tone="info"><ShieldCheck className="inline size-4 mr-1 text-accent" />Analysis is passive. No traffic is sent, encryption is never bypassed, and credentials and message bodies are never stored.</Notice>
              <Button type="submit" variant="primary" className="w-full" loading={start.isPending} disabled={!c || !!deps.data && !deps.data.tshark.available}>Start analysis</Button>
            </div>
          </Card>
        </form>
      </div>
    </div>
  )
}

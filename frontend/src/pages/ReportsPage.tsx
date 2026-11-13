import { Download, Eye, FileText } from 'lucide-react'
import { useState } from 'react'
import { AnalysisPicker, useScopedAnalysis } from '@/components/analysis/Scope'
import { Button, Card, CardHeader, EmptyState, ErrorState, Label, PageHeader, Select, TableSkeleton } from '@/components/ui/primitives'
import { useToast } from '@/components/ui/toast'
import { useAnalyses, useCreateReport, useReports } from '@/hooks/queries'
import { bytes, dateTime, download, shortHash } from '@/utils/format'

export default function ReportsPage() {
  const toast = useToast()
  const { id: latest } = useScopedAnalysis()
  const analyses = useAnalyses({ status: 'completed', page_size: 100 })
  const [sel, setSel] = useState<string>('')
  const [format, setFormat] = useState('pdf')
  const [preview, setPreview] = useState(false)
  const reports = useReports({ page_size: 50 })
  const mk = useCreateReport()
  const analysisId = sel || latest
  void AnalysisPicker
  return (
    <div className="fade-in">
      <PageHeader title="Reports" description="Generate evidence-linked reports. Reports contain metadata only: no credentials, message bodies or addresses." />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,22rem)_1fr]">
        <Card><CardHeader title="Generate a report" />
          <div className="space-y-4 px-5 pb-5">
            <div><Label htmlFor="rep-an">Analysis</Label><Select id="rep-an" value={analysisId ?? ''} onChange={(e) => setSel(e.target.value)} disabled={!analyses.data?.items.length}>{analyses.data?.items.length ? analyses.data.items.map((a) => <option key={a.id} value={a.id}>{a.capture?.filename} · {a.id.slice(0, 6)}</option>) : <option>No completed analyses</option>}</Select></div>
            <div><Label htmlFor="rep-fmt">Format</Label><Select id="rep-fmt" value={format} onChange={(e) => setFormat(e.target.value)}><option value="pdf">PDF</option><option value="html">HTML</option><option value="json">JSON</option><option value="csv">CSV (findings)</option></Select></div>
            <div className="flex gap-2">
              <Button variant="primary" disabled={!analysisId} loading={mk.isPending} onClick={() => mk.mutate({ analysisId: analysisId!, format }, { onSuccess: (r) => { toast({ tone: 'ok', title: 'Report generated', body: r.filename }); download(`/api/reports/${r.id}/download`) }, onError: (e) => toast({ tone: 'err', title: 'Report failed', body: e.message }) })}><FileText className="size-4" />Generate &amp; download</Button>
              <Button disabled={!analysisId} onClick={() => setPreview((p) => !p)}><Eye className="size-4" />{preview ? 'Hide preview' : 'Preview'}</Button>
            </div>
          </div></Card>
        <Card><CardHeader title="Generated reports" />
          {reports.isLoading ? <TableSkeleton cols={5} /> : reports.error ? <ErrorState error={reports.error} onRetry={reports.refetch} /> : !reports.data?.items.length ? <EmptyState icon={<FileText className="size-5" />} title="No reports yet" description="Generate one from a completed analysis." /> : (
            <div className="table-wrap"><table className="data"><thead><tr><th>File</th><th>Format</th><th>Size</th><th>SHA-256</th><th>Created</th><th /></tr></thead><tbody>
              {reports.data.items.map((r) => <tr key={r.id}><td className="max-w-56 truncate font-medium">{r.filename}</td><td className="uppercase text-xs">{r.format}</td><td className="text-mute">{bytes(r.size_bytes)}</td><td className="font-mono text-xs">{shortHash(r.sha256, 6)}</td><td className="whitespace-nowrap text-mute">{dateTime(r.created_at)}</td><td><Button size="sm" variant="ghost" aria-label={`Download ${r.filename}`} onClick={() => download(`/api/reports/${r.id}/download`)}><Download className="size-3.5" /></Button></td></tr>)}</tbody></table></div>)}
        </Card>
      </div>
      {preview && analysisId && (
        <Card className="mt-6"><CardHeader title="Report preview" subtitle="Rendered in a sandboxed frame (scripts disabled)." />
          <iframe title="Report preview" sandbox="" src={`/api/analyses/${analysisId}/report-preview`} className="h-[70vh] w-full rounded-b-xl bg-white" /></Card>)}
    </div>
  )
}

import { useNavigate, useParams } from 'react-router-dom'
import { Upload } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useAnalyses } from '@/hooks/queries'
import { EmptyState, Select, Spinner } from '@/components/ui/primitives'

/** Resolves the analysis from the URL, or falls back to the newest completed one (sidebar entry points). */
export function useScopedAnalysis() {
  const { analysisId } = useParams()
  const list = useAnalyses({ status: 'completed', page_size: 100 })
  return { id: analysisId ?? list.data?.items[0]?.id, list, fromUrl: !!analysisId }
}

export function AnalysisPicker({ current, suffix }: { current?: string; suffix: string }) {
  const nav = useNavigate()
  const { data } = useAnalyses({ status: 'completed', page_size: 100 })
  if (!data?.items.length) return null
  return (
    <Select aria-label="Choose analysis" value={current ?? ''} onChange={(e) => nav(`/analysis/${e.target.value}/${suffix}`)} className="max-w-xs">
      {data.items.map((a) => <option key={a.id} value={a.id}>{a.capture?.filename} · {a.id.slice(0, 6)}</option>)}
    </Select>
  )
}

export function ScopeGate({ id, loading, children }: { id?: string; loading: boolean; children: ReactNode }) {
  if (loading) return <Spinner label="Loading analyses" />
  if (!id) return <EmptyState title="No completed analysis yet" description="Upload a PCAP and run an analysis (or load the synthetic demo dataset) to see results here."
    action={<Link to="/analysis/new" className="inline-flex items-center gap-2 rounded-lg bg-accent px-3.5 py-2 text-sm font-semibold text-[#04201a]"><Upload className="size-4" />New analysis</Link>} />
  return <>{children}</>
}

import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { del, get, patch, post, put, qs } from '@/services/api'
import type { Analysis, AnalysisStatusResp, AppSettings, Capture, Certificate, Dashboard, Dependencies, EmailSession, EvidenceDetail, Evidence, Finding, Page, Report, RulesResp, Summary, TcpStream, TlsSession } from '@/types/api'

export const useDashboard = () => useQuery({ queryKey: ['dashboard'], queryFn: () => get<Dashboard>('/dashboard'), refetchInterval: 8000 })
export const useDependencies = () => useQuery({ queryKey: ['deps'], queryFn: () => get<Dependencies>('/system/dependencies'), refetchInterval: 30000 })
export const useDemoStatus = () => useQuery({ queryKey: ['demo'], queryFn: () => get<{ available: string[]; loaded: number; label: string }>('/demo/status'), refetchInterval: 8000 })
export const useSettings = () => useQuery({ queryKey: ['settings'], queryFn: () => get<{ settings: AppSettings; env: Record<string, unknown> }>('/settings') })

export const useCaptures = (p: Record<string, string | number | undefined>) =>
  useQuery({ queryKey: ['captures', p], queryFn: () => get<Page<Capture>>(`/captures${qs(p)}`), placeholderData: keepPreviousData, refetchInterval: 6000 })
export const useAnalyses = (p: Record<string, string | number | undefined>) =>
  useQuery({ queryKey: ['analyses', p], queryFn: () => get<Page<Analysis>>(`/analyses${qs(p)}`), placeholderData: keepPreviousData, refetchInterval: 6000 })
export const useAnalysis = (id?: string) => useQuery({ queryKey: ['analysis', id], queryFn: () => get<Analysis>(`/analyses/${id}`), enabled: !!id })

export const useAnalysisStatus = (id?: string) =>
  useQuery({
    queryKey: ['analysis-status', id], enabled: !!id,
    queryFn: () => get<AnalysisStatusResp>(`/analyses/${id}/status`),
    refetchInterval: (q) => (q.state.data && ['completed', 'failed', 'cancelled'].includes(q.state.data.status) ? false : 600),
  })

export const useSummary = (id?: string) => useQuery({ queryKey: ['summary', id], queryFn: () => get<Summary>(`/analyses/${id}/summary`), enabled: !!id, retry: false })
export const useProtocols = (id?: string) => useQuery({ queryKey: ['protocols', id], queryFn: () => get<{ sessions: EmailSession[]; streams: TcpStream[] }>(`/analyses/${id}/protocols`), enabled: !!id, retry: false })
export const useTls = (id?: string) => useQuery({ queryKey: ['tls', id], queryFn: () => get<{ sessions: TlsSession[] }>(`/analyses/${id}/tls`), enabled: !!id, retry: false })
export const useCertificates = (id?: string) =>
  useQuery({ queryKey: ['certs', id], queryFn: () => get<{ certificates: Certificate[]; unavailable: { stream_id: number; reason: string }[]; notice: string }>(`/analyses/${id}/certificates`), enabled: !!id, retry: false })

export const useFindings = (p: Record<string, string | number | undefined>, analysisId?: string) =>
  useQuery({
    queryKey: ['findings', analysisId ?? 'all', p],
    queryFn: () => get<Page<Finding>>(analysisId ? `/analyses/${analysisId}/findings${qs(p)}` : `/findings${qs(p)}`),
    placeholderData: keepPreviousData,
  })
export const useFinding = (id?: string) => useQuery({ queryKey: ['finding', id], queryFn: () => get<Finding>(`/findings/${id}`), enabled: !!id })
export const useEvidenceList = (analysisId: string | undefined, p: Record<string, string | number | undefined>) =>
  useQuery({ queryKey: ['evidence', analysisId, p], queryFn: () => get<Page<Evidence>>(`/analyses/${analysisId}/evidence${qs(p)}`), enabled: !!analysisId, placeholderData: keepPreviousData, retry: false })
export const useEvidenceDetail = (id?: string) => useQuery({ queryKey: ['evidence-detail', id], queryFn: () => get<EvidenceDetail>(`/evidence/${id}`), enabled: !!id })

export const useRules = () => useQuery({ queryKey: ['rules'], queryFn: () => get<RulesResp>('/rules') })
export const useReports = (p: Record<string, string | number | undefined> = {}) => useQuery({ queryKey: ['reports', p], queryFn: () => get<Page<Report>>(`/reports${qs(p)}`), placeholderData: keepPreviousData })
export const useAuditLog = () => useQuery({ queryKey: ['audit'], queryFn: () => get<{ items: { id: number; at: string; action: string; subject: string | null; detail: Record<string, unknown> }[] }>('/system/audit?limit=50') })
export const useAppLogs = () => useQuery({ queryKey: ['logs'], queryFn: () => get<{ lines: string[] }>('/system/logs?lines=120'), refetchInterval: 10000 })

function useInvalidating<TVars, TData>(fn: (v: TVars) => Promise<TData>, keys: string[][]) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: fn, onSuccess: () => keys.forEach((k) => qc.invalidateQueries({ queryKey: k })) })
}

export const useStartAnalysis = () =>
  useInvalidating((v: { capture_id: string; options: Record<string, boolean> }) => post<Analysis>('/analyses', { ...v, authorised_confirmation: true }), [['analyses'], ['captures'], ['dashboard']])
export const useCancelAnalysis = () => useInvalidating((id: string) => post(`/analyses/${id}/cancel`), [['analysis-status'], ['analyses']])
export const useRerun = () => useInvalidating((id: string) => post<Analysis>(`/analyses/${id}/rerun`), [['analyses'], ['captures'], ['dashboard']])
export const useDeleteCapture = () => useInvalidating((id: string) => del(`/captures/${id}`), [['captures'], ['analyses'], ['dashboard'], ['findings'], ['reports'], ['demo']])
export const useFindingStatus = () => useInvalidating((v: { id: string; status: string; note?: string }) => patch<Finding>(`/findings/${v.id}/status`, { status: v.status, note: v.note || null }), [['findings'], ['finding'], ['summary']])
export const useToggleRule = () => useInvalidating((v: { id: string; enabled: boolean }) => patch(`/rules/${v.id}`, { enabled: v.enabled }), [['rules']])
export const useCreateReport = () => useInvalidating((v: { analysisId: string; format: string }) => post<Report>(`/analyses/${v.analysisId}/reports`, { format: v.format }), [['reports']])
export const useSaveSettings = () => useInvalidating((v: Partial<AppSettings>) => put('/settings', v), [['settings'], ['audit']])
export const useLoadDemo = () => useInvalidating(() => post<{ created: { capture_id: string; analysis_id: string; filename: string }[] }>('/demo/load'), [['demo'], ['captures'], ['analyses'], ['dashboard']])
export const useRemoveDemo = () => useInvalidating(() => del('/demo'), [['demo'], ['captures'], ['analyses'], ['dashboard'], ['findings'], ['reports']])
export const useRunRetention = () => useInvalidating(() => post<{ original_captures_removed: number; retention_days: number }>('/system/retention/run'), [['captures'], ['audit']])

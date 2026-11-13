import type { Completeness, ItemState, ObservationType, Severity } from '@/types/api'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
export const SEV_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Informational' }
export const SEV_COLOR: Record<Severity, string> = { critical: '#f06b75', high: '#f58a63', medium: '#f5b942', low: '#68a7ff', info: '#8a9bb3' }
export const STATUS_LABEL: Record<string, string> = { open: 'Open', under_review: 'Under review', resolved: 'Resolved', accepted_risk: 'Accepted risk' }
export const OBS_LABEL: Record<ObservationType, string> = {
  weakness_observed: 'Weakness observed', weak_option_offered: 'Weak option offered', secure_configuration: 'Secure configuration',
  protocol_feature: 'Protocol feature', insufficient_evidence: 'Insufficient evidence',
}
export const OBS_HELP: Record<ObservationType, string> = {
  weakness_observed: 'A weakness is positively present in the observed data.',
  weak_option_offered: 'A weak option was offered by one side; it was not (known to be) selected.',
  secure_configuration: 'A modern, secure configuration was positively observed.',
  protocol_feature: 'Neutral protocol behaviour that was observed.',
  insufficient_evidence: 'The capture does not contain enough evidence to assess this. This is NOT a confirmed vulnerability.',
}
export const COMPLETE_LABEL: Record<Completeness, string> = { complete: 'Complete evidence', partial: 'Partial evidence', incomplete: 'Incomplete evidence' }
export const STATE_LABEL: Record<ItemState, string> = { observed: 'Observed', not_observed: 'Not observed', incomplete: 'Incomplete evidence', undecodable: 'Undecodable / encrypted' }

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 ** 2).toFixed(2)} MB`
}
export function dateTime(iso?: string | null): string {
  if (!iso) return '-'
  const d = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z')
  return isNaN(+d) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}
export function preciseTime(iso?: string | null): string {
  if (!iso) return '-'
  const d = new Date(iso)
  return isNaN(+d) ? iso : d.toISOString().replace('T', ' ').replace('Z', ' UTC')
}
export function relTime(iso?: string | null): string {
  if (!iso) return '-'
  const d = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z')
  const s = Math.round((Date.now() - +d) / 1000)
  if (s < 45) return 'just now'
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} d ago`
}
export function shortHash(h: string, n = 10): string { return h.length > n * 2 ? `${h.slice(0, n)}…${h.slice(-6)}` : h }
export function hexDump(hex: string): { off: string; bytes: string[]; ascii: string }[] {
  const b = hex.replace(/[^0-9a-fA-F]/g, '').match(/../g) ?? []
  const rows = []
  for (let i = 0; i < b.length; i += 16) {
    const chunk = b.slice(i, i + 16)
    rows.push({ off: i.toString(16).padStart(4, '0'), bytes: chunk, ascii: chunk.map((x) => { const c = parseInt(x, 16); return c >= 32 && c < 127 ? String.fromCharCode(c) : '.' }).join('') })
  }
  return rows
}
export function download(url: string) {
  const a = document.createElement('a')
  a.href = url
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
}
export function cn(...c: (string | false | null | undefined)[]): string { return c.filter(Boolean).join(' ') }

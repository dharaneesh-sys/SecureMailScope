import { AlertOctagon, AlertTriangle, CheckCircle2, CircleDashed, Info, ShieldAlert, ShieldCheck } from 'lucide-react'
import type { Completeness, ItemState, ObservationType, Severity } from '@/types/api'
import { COMPLETE_LABEL, OBS_HELP, OBS_LABEL, SEV_COLOR, SEV_LABEL, STATE_LABEL, STATUS_LABEL, cn } from '@/utils/format'
import { Tip } from './tooltip'

const sevIcon: Record<Severity, typeof Info> = { critical: AlertOctagon, high: ShieldAlert, medium: AlertTriangle, low: Info, info: Info }
export function SeverityBadge({ severity, compact }: { severity: Severity; compact?: boolean }) {
  const c = SEV_COLOR[severity]
  const Icon = sevIcon[severity]
  return (
    <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold border whitespace-nowrap" style={{ color: c, borderColor: `${c}66`, background: `${c}18` }}>
      <Icon className="size-3" aria-hidden />{compact ? severity.toUpperCase().slice(0, 4) : SEV_LABEL[severity]}
    </span>
  )
}

export function StatusBadge({ status }: { status: string }) {
  const tone: Record<string, string> = {
    completed: 'text-accent border-accent/40 bg-accent/10', running: 'text-accent2 border-accent2/40 bg-accent2/10', queued: 'text-mute border-line bg-elevated',
    failed: 'text-crit border-crit/40 bg-crit/10', cancelled: 'text-warn border-warn/40 bg-warn/10',
    open: 'text-warn border-warn/40 bg-warn/10', under_review: 'text-accent2 border-accent2/40 bg-accent2/10', resolved: 'text-accent border-accent/40 bg-accent/10', accepted_risk: 'text-mute border-line bg-elevated',
  }
  return <span className={cn('inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium border whitespace-nowrap capitalize', tone[status] ?? tone.queued)}>{STATUS_LABEL[status] ?? status.replace('_', ' ')}</span>
}

export function ObservationBadge({ type }: { type: ObservationType }) {
  const tone: Record<ObservationType, string> = {
    weakness_observed: 'text-crit', weak_option_offered: 'text-warn', secure_configuration: 'text-accent', protocol_feature: 'text-accent2', insufficient_evidence: 'text-mute',
  }
  const Icon = type === 'secure_configuration' ? ShieldCheck : type === 'insufficient_evidence' ? CircleDashed : type === 'weakness_observed' ? ShieldAlert : Info
  return (
    <Tip text={OBS_HELP[type]}>
      <span className={cn('inline-flex items-center gap-1 text-xs', tone[type])}><Icon className="size-3.5" aria-hidden />{OBS_LABEL[type]}</span>
    </Tip>
  )
}

export function CompletenessBadge({ value }: { value: Completeness }) {
  const tone = value === 'complete' ? 'text-accent' : value === 'partial' ? 'text-warn' : 'text-crit'
  return <span className={cn('inline-flex items-center gap-1 text-xs', tone)}><CheckCircle2 className="size-3.5" aria-hidden />{COMPLETE_LABEL[value]}</span>
}

export function StateBadge({ state }: { state: ItemState }) {
  const tone: Record<ItemState, string> = { observed: 'text-accent border-accent/40 bg-accent/10', not_observed: 'text-mute border-line bg-elevated', incomplete: 'text-warn border-warn/40 bg-warn/10', undecodable: 'text-accent2 border-accent2/40 bg-accent2/10' }
  const help: Record<ItemState, string> = {
    observed: 'Seen in the capture.', not_observed: 'Not seen. Absence alone does not prove an insecure configuration.',
    incomplete: 'Partly seen: the capture ends before this could be confirmed.', undecodable: 'Present but encrypted or not decodable without key material.',
  }
  return <Tip text={help[state]}><span className={cn('inline-flex rounded-full px-2 py-0.5 text-[11px] font-medium border whitespace-nowrap', tone[state])}>{STATE_LABEL[state]}</span></Tip>
}

export function ScoreChip({ score }: { score: number }) {
  const c = score >= 80 ? SEV_COLOR.critical : score >= 60 ? SEV_COLOR.high : score >= 35 ? SEV_COLOR.medium : score >= 15 ? SEV_COLOR.low : SEV_COLOR.info
  return <span className="inline-flex items-center justify-center min-w-9 rounded-md px-1.5 py-0.5 text-xs font-semibold tabular-nums" style={{ color: c, background: `${c}1f` }}>{score}</span>
}

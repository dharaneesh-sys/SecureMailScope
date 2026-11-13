import { AlertTriangle, Check, Copy, Inbox, Loader2 } from 'lucide-react'
import { useState, type ButtonHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type InputHTMLAttributes, forwardRef } from 'react'
import { cn } from '@/utils/format'
import { Tip } from './tooltip'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger'
const variants: Record<Variant, string> = {
  primary: 'bg-accent text-[#04201a] hover:brightness-110 font-semibold glow-accent',
  secondary: 'bg-elevated text-ink border border-line hover:border-accent2/60 hover:bg-[#1c2c44]',
  ghost: 'text-mute hover:text-ink hover:bg-elevated',
  danger: 'bg-crit/10 text-crit border border-crit/40 hover:bg-crit/20',
}
export function Button({ variant = 'secondary', size = 'md', loading, className, children, disabled, ...p }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: 'sm' | 'md'; loading?: boolean }) {
  return (
    <button
      {...p}
      disabled={disabled || loading}
      className={cn('inline-flex items-center justify-center gap-2 rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap', size === 'sm' ? 'px-2.5 py-1.5 text-xs' : 'px-3.5 py-2 text-sm', variants[variant], className)}
    >
      {loading && <Loader2 className="size-4 animate-spin" aria-hidden />}
      {children}
    </button>
  )
}

export function Card({ className, children, elevated }: { className?: string; children: ReactNode; elevated?: boolean }) {
  return <section className={cn(elevated ? 'card-elevated' : 'card', className)}>{children}</section>
}
export function CardHeader({ title, subtitle, action, help }: { title: ReactNode; subtitle?: ReactNode; action?: ReactNode; help?: string }) {
  return (
    <div className="flex items-start justify-between gap-3 px-5 pt-4 pb-3">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-ink flex items-center gap-1.5">{title}{help && <Tip text={help} />}</h2>
        {subtitle && <p className="text-xs text-mute mt-0.5">{subtitle}</p>}
      </div>
      {action}
    </div>
  )
}

export function PageHeader({ title, description, actions, crumbs }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; crumbs?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {crumbs}
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-sm text-mute max-w-3xl">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...p }, ref) {
  return <input ref={ref} {...p} className={cn('w-full rounded-lg bg-bg border border-line px-3 py-2 text-sm text-ink placeholder:text-mute/70 focus:border-accent2 outline-none', className)} />
})
export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select({ className, children, ...p }, ref) {
  return <select ref={ref} {...p} className={cn('rounded-lg bg-bg border border-line px-2.5 py-2 text-sm text-ink focus:border-accent2 outline-none', className)}>{children}</select>
})
export function Label({ children, htmlFor }: { children: ReactNode; htmlFor?: string }) {
  return <label htmlFor={htmlFor} className="block text-xs font-medium text-mute mb-1.5">{children}</label>
}
export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled} onClick={() => onChange(!checked)}
      className={cn('relative h-6 w-11 shrink-0 rounded-full transition disabled:opacity-50', checked ? 'bg-accent' : 'bg-line')}>
      <span className={cn('absolute top-0.5 size-5 rounded-full bg-white transition-all', checked ? 'left-[22px]' : 'left-0.5')} />
    </button>
  )
}
export function Checkbox({ checked, onChange, id, children }: { checked: boolean; onChange: (v: boolean) => void; id: string; children: ReactNode }) {
  return (
    <label htmlFor={id} className="flex items-start gap-2.5 text-sm cursor-pointer select-none">
      <input id={id} type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="mt-0.5 size-4 accent-[#36d6b0]" />
      <span>{children}</span>
    </label>
  )
}

export function Skeleton({ className }: { className?: string }) { return <div className={cn('skeleton', className)} aria-hidden /> }
export function TableSkeleton({ rows = 5, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="p-4 space-y-3" role="status" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4">{Array.from({ length: cols }).map((__, j) => <Skeleton key={j} className="h-5 flex-1" />)}</div>
      ))}
    </div>
  )
}
export function Spinner({ label = 'Loading' }: { label?: string }) {
  return <div className="flex items-center gap-2 text-mute text-sm p-6" role="status"><Loader2 className="size-4 animate-spin" />{label}…</div>
}

export function EmptyState({ icon, title, description, action }: { icon?: ReactNode; title: string; description?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center text-center gap-3 py-14 px-6 fade-in">
      <div className="size-12 rounded-full bg-elevated border border-line grid place-items-center text-accent">{icon ?? <Inbox className="size-5" />}</div>
      <h3 className="font-semibold">{title}</h3>
      {description && <p className="text-sm text-mute max-w-md">{description}</p>}
      {action}
    </div>
  )
}
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : 'Something went wrong'
  return (
    <div role="alert" className="flex flex-col items-center text-center gap-3 py-12 px-6">
      <div className="size-12 rounded-full bg-crit/10 border border-crit/40 grid place-items-center text-crit"><AlertTriangle className="size-5" /></div>
      <h3 className="font-semibold">Could not load this data</h3>
      <p className="text-sm text-mute max-w-lg break-words">{msg}</p>
      {onRetry && <Button onClick={onRetry}>Try again</Button>}
    </div>
  )
}

export function Notice({ tone = 'info', title, children }: { tone?: 'info' | 'warn' | 'crit' | 'ok'; title?: string; children: ReactNode }) {
  const t = { info: 'border-accent2/40 bg-accent2/10', warn: 'border-warn/40 bg-warn/10', crit: 'border-crit/40 bg-crit/10', ok: 'border-accent/40 bg-accent/10' }[tone]
  return (
    <div role={tone === 'crit' ? 'alert' : 'note'} className={cn('rounded-lg border px-4 py-3 text-sm', t)}>
      {title && <div className="font-semibold mb-0.5">{title}</div>}
      <div className="text-ink/90">{children}</div>
    </div>
  )
}

export function Progress({ value, tone = 'accent' }: { value: number; tone?: 'accent' | 'crit' }) {
  return (
    <div className="h-2 rounded-full bg-bg border border-line overflow-hidden" role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}>
      <div className={cn('h-full transition-all duration-500', tone === 'crit' ? 'bg-crit' : 'bg-gradient-to-r from-accent to-accent2')} style={{ width: `${value}%` }} />
    </div>
  )
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button type="button" aria-label={`${label}: ${value.slice(0, 24)}`} title={label}
      onClick={async () => { try { await navigator.clipboard.writeText(value) } catch { /* clipboard blocked */ } setDone(true); setTimeout(() => setDone(false), 1400) }}
      className="inline-flex items-center justify-center size-6 rounded text-mute hover:text-accent hover:bg-elevated transition">
      {done ? <Check className="size-3.5 text-accent" /> : <Copy className="size-3.5" />}
    </button>
  )
}
export function Mono({ children, copy }: { children: string; copy?: boolean }) {
  return <span className="inline-flex items-center gap-1 font-mono text-xs text-ink/90 break-all">{children}{copy && <CopyButton value={children} />}</span>
}

export function KV({ items, cols = 2 }: { items: [ReactNode, ReactNode][]; cols?: 1 | 2 | 3 }) {
  return (
    <dl className={cn('grid gap-x-8 gap-y-3 text-sm', cols === 1 ? 'grid-cols-1' : cols === 2 ? 'sm:grid-cols-2' : 'sm:grid-cols-2 lg:grid-cols-3')}>
      {items.map(([k, v], i) => (
        <div key={i} className="min-w-0"><dt className="text-[11px] uppercase tracking-wider text-mute">{k}</dt><dd className="mt-0.5 break-words">{v ?? '-'}</dd></div>
      ))}
    </dl>
  )
}

export function Stat({ label, value, hint, icon, tone }: { label: string; value: ReactNode; hint?: string; icon?: ReactNode; tone?: 'crit' | 'accent' | 'warn' }) {
  return (
    <div className="card px-4 py-3.5 min-w-0">
      <div className="flex items-center justify-between text-xs text-mute"><span className="truncate">{label}</span>{icon && <span className={cn(tone === 'crit' ? 'text-crit' : tone === 'warn' ? 'text-warn' : 'text-accent')}>{icon}</span>}</div>
      <div className="mt-1.5 text-2xl font-semibold tabular-nums">{value}</div>
      {hint && <div className="text-[11px] text-mute mt-0.5">{hint}</div>}
    </div>
  )
}

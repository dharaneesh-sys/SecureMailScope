import { CheckCircle2, Info, X, XCircle } from 'lucide-react'
import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import { cn } from '@/utils/format'

type Tone = 'ok' | 'err' | 'info'
interface Toast { id: number; tone: Tone; title: string; body?: string }
const Ctx = createContext<(t: Omit<Toast, 'id'>) => void>(() => {})
export const useToast = () => useContext(Ctx)

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([])
  const push = useCallback((t: Omit<Toast, 'id'>) => {
    const id = Date.now() + Math.random()
    setItems((x) => [...x, { ...t, id }])
    setTimeout(() => setItems((x) => x.filter((y) => y.id !== id)), t.tone === 'err' ? 7000 : 4000)
  }, [])
  return (
    <Ctx.Provider value={push}>
      {children}
      <div className="fixed bottom-4 right-4 z-[200] flex w-[min(92vw,380px)] flex-col gap-2" aria-live="polite">
        {items.map((t) => {
          const Icon = t.tone === 'ok' ? CheckCircle2 : t.tone === 'err' ? XCircle : Info
          return (
            <div key={t.id} role={t.tone === 'err' ? 'alert' : 'status'} className={cn('fade-in flex items-start gap-3 rounded-lg border bg-elevated px-4 py-3 shadow-xl', t.tone === 'ok' ? 'border-accent/50' : t.tone === 'err' ? 'border-crit/50' : 'border-accent2/50')}>
              <Icon className={cn('mt-0.5 size-4 shrink-0', t.tone === 'ok' ? 'text-accent' : t.tone === 'err' ? 'text-crit' : 'text-accent2')} />
              <div className="min-w-0 flex-1 text-sm"><div className="font-medium">{t.title}</div>{t.body && <div className="text-xs text-mute mt-0.5 break-words">{t.body}</div>}</div>
              <button aria-label="Dismiss" onClick={() => setItems((x) => x.filter((y) => y.id !== t.id))} className="text-mute hover:text-ink"><X className="size-3.5" /></button>
            </div>
          )
        })}
      </div>
    </Ctx.Provider>
  )
}

import * as T from '@radix-ui/react-tooltip'
import { HelpCircle } from 'lucide-react'
import type { ReactNode } from 'react'

export function TooltipProvider({ children }: { children: ReactNode }) { return <T.Provider delayDuration={150}>{children}</T.Provider> }

export function Tip({ text, children }: { text: string; children?: ReactNode }) {
  return (
    <T.Root>
      <T.Trigger asChild>
        {children ? <span className="cursor-help">{children}</span> : <button type="button" aria-label={`Help: ${text}`} className="text-mute hover:text-accent2"><HelpCircle className="size-3.5" /></button>}
      </T.Trigger>
      <T.Portal>
        <T.Content sideOffset={6} className="z-[100] max-w-xs rounded-lg border border-line bg-elevated px-3 py-2 text-xs text-ink shadow-xl fade-in">{text}<T.Arrow className="fill-line" /></T.Content>
      </T.Portal>
    </T.Root>
  )
}

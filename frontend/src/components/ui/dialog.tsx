import * as D from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'
import { Button } from './primitives'

export function ConfirmDialog({ open, onOpenChange, title, description, confirmLabel = 'Confirm', danger, loading, onConfirm }: {
  open: boolean; onOpenChange: (o: boolean) => void; title: string; description: ReactNode; confirmLabel?: string; danger?: boolean; loading?: boolean; onConfirm: () => void
}) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-[2px]" />
        <D.Content className="fixed left-1/2 top-1/2 z-50 w-[calc(100vw-32px)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-xl border border-line bg-surface p-5 shadow-2xl fade-in">
          <D.Title className="text-base font-semibold">{title}</D.Title>
          <D.Description asChild><div className="mt-2 text-sm text-mute">{description}</div></D.Description>
          <div className="mt-5 flex justify-end gap-2">
            <D.Close asChild><Button variant="ghost">Cancel</Button></D.Close>
            <Button variant={danger ? 'danger' : 'primary'} loading={loading} onClick={onConfirm}>{confirmLabel}</Button>
          </div>
        </D.Content>
      </D.Portal>
    </D.Root>
  )
}

export function Drawer({ open, onOpenChange, title, subtitle, children, wide }: { open: boolean; onOpenChange: (o: boolean) => void; title: ReactNode; subtitle?: ReactNode; children: ReactNode; wide?: boolean }) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-50 bg-black/50" />
        <D.Content className={`fixed right-0 top-0 z-50 h-full w-full ${wide ? 'max-w-3xl' : 'max-w-xl'} overflow-y-auto border-l border-line bg-surface shadow-2xl fade-in`}>
          <div className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-line bg-surface/95 backdrop-blur px-5 py-4">
            <div className="min-w-0">
              <D.Title className="text-base font-semibold leading-snug">{title}</D.Title>
              <D.Description asChild><div className="text-xs text-mute mt-1">{subtitle}</div></D.Description>
            </div>
            <D.Close aria-label="Close panel" className="rounded-md p-1.5 text-mute hover:bg-elevated hover:text-ink"><X className="size-4" /></D.Close>
          </div>
          <div className="p-5">{children}</div>
        </D.Content>
      </D.Portal>
    </D.Root>
  )
}

import * as Tabs from '@radix-ui/react-tabs'
import type { ReactNode } from 'react'

export function TabbedPanel({ tabs, defaultValue }: { tabs: { value: string; label: string; content: ReactNode }[]; defaultValue?: string }) {
  return (
    <Tabs.Root defaultValue={defaultValue ?? tabs[0].value}>
      <Tabs.List className="flex gap-1 border-b border-line overflow-x-auto" aria-label="Sections">
        {tabs.map((t) => (
          <Tabs.Trigger key={t.value} value={t.value} className="px-3.5 py-2 text-sm text-mute border-b-2 border-transparent whitespace-nowrap hover:text-ink data-[state=active]:text-accent data-[state=active]:border-accent">
            {t.label}
          </Tabs.Trigger>
        ))}
      </Tabs.List>
      {tabs.map((t) => <Tabs.Content key={t.value} value={t.value} className="pt-4 outline-none">{t.content}</Tabs.Content>)}
    </Tabs.Root>
  )
}

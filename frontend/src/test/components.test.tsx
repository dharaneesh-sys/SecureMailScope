import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { CompletenessBadge, SeverityBadge, StateBadge } from '@/components/ui/badges'
import { ConfirmDialog } from '@/components/ui/dialog'
import { Pagination } from '@/components/ui/pagination'
import { TooltipProvider } from '@/components/ui/tooltip'

describe('badges', () => {
  it('shows the severity label as text, not colour alone', () => {
    render(<SeverityBadge severity="high" />)
    expect(screen.getByText('High')).toBeInTheDocument()
  })
  it('distinguishes not observed from incomplete evidence', () => {
    render(<TooltipProvider><StateBadge state="not_observed" /><StateBadge state="incomplete" /></TooltipProvider>)
    expect(screen.getByText('Not observed')).toBeInTheDocument()
    expect(screen.getByText('Incomplete evidence')).toBeInTheDocument()
  })
  it('labels evidence completeness', () => {
    render(<TooltipProvider><CompletenessBadge value="partial" /></TooltipProvider>)
    expect(screen.getByText('Partial evidence')).toBeInTheDocument()
  })
})

describe('ConfirmDialog', () => {
  it('requires explicit confirmation and can be cancelled', async () => {
    const onConfirm = vi.fn()
    const onOpenChange = vi.fn()
    render(<ConfirmDialog open onOpenChange={onOpenChange} title="Delete?" description="Gone forever" confirmLabel="Delete" danger onConfirm={onConfirm} />)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onConfirm).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(onConfirm).toHaveBeenCalledOnce()
  })
})

describe('Pagination', () => {
  it('reports the page and calls onPage', async () => {
    const onPage = vi.fn()
    render(<Pagination page={2} pages={3} total={45} onPage={onPage} />)
    expect(screen.getByText(/Page 2 of 3/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    expect(onPage).toHaveBeenCalledWith(3)
  })
})

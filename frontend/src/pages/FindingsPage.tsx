import { FindingsTable } from '@/components/findings/FindingsTable'
import { PageHeader } from '@/components/ui/primitives'

export default function FindingsPage() {
  return (
    <div className="fade-in">
      <PageHeader title="Security findings" description="Every finding is produced by a deterministic rule from parsed observations and links to packet-level evidence. “Insufficient evidence” entries are capture limitations, not vulnerabilities." />
      <FindingsTable />
    </div>
  )
}

import { Card, CardHeader, Notice, PageHeader } from '@/components/ui/primitives'

export default function AboutPage() {
  return (
    <div className="fade-in max-w-3xl">
      <PageHeader title="About SecureMailScope" description="Evidence-based review of email transport security in packet captures you are authorised to analyse." />
      <div className="space-y-6">
        <Card><CardHeader title="What it does" /><div className="space-y-3 px-5 pb-5 text-sm text-mute">
          <p>SecureMailScope uses TShark to dissect SMTP, IMAP, POP3 and TLS traffic, then applies deterministic rules to report STARTTLS/STLS stripping risk, TLS version and cipher-suite weaknesses, and certificate metadata issues. Every finding links to packet-level evidence.</p>
          <p>The rule engine establishes facts. Optional AI only explains findings in plain language and cannot add, remove or re-rate them.</p></div></Card>
        <Card><CardHeader title="What it does not do" /><ul className="list-disc space-y-2 px-9 pb-5 text-sm text-mute">
          <li>It does not decrypt TLS, recover credentials or read message bodies.</li>
          <li>It does not validate certificate trust chains, revocation or hostname identity.</li>
          <li>TLS 1.3 certificates are encrypted; they are reported as unavailable, not as a problem.</li>
          <li>Absence of an event in an incomplete capture is “not observed”, never proof of insecurity.</li>
          <li>The risk score (SMRS-1) is a prioritisation aid, not CVSS.</li></ul></Card>
        <Notice tone="warn" title="Authorised use only">Analyse only captures you own or have explicit permission to examine. Demo data is synthetic: CONTROLLED SYNTHETIC DEMONSTRATION DATA — NOT REAL CUSTOMER TRAFFIC.</Notice>
      </div>
    </div>
  )
}

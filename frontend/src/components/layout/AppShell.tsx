import { Bell, ChevronRight, FileBarChart, FileSearch, FolderArchive, Gauge, History, Info, LayoutDashboard, Lock, Menu, Network, PanelLeftClose, PanelLeftOpen, Scale, ScrollText, Search, Settings, ShieldAlert, ShieldCheck, Upload, UserCircle2, Award } from 'lucide-react'
import * as DM from '@radix-ui/react-dropdown-menu'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useAnalyses, useDemoStatus, useDependencies, useSettings } from '@/hooks/queries'
import { cn, relTime } from '@/utils/format'
import { Notice } from '@/components/ui/primitives'

const NAV: { to: string; label: string; icon: typeof Gauge }[] = [
  { to: '/dashboard', label: 'Overview', icon: LayoutDashboard },
  { to: '/analysis/new', label: 'New Analysis', icon: Upload },
  { to: '/captures', label: 'Capture Library', icon: FolderArchive },
  { to: '/history', label: 'Analysis History', icon: History },
  { to: '/protocols', label: 'Protocol Explorer', icon: Network },
  { to: '/tls', label: 'TLS Inspector', icon: Lock },
  { to: '/certificates', label: 'Certificate Inspector', icon: Award },
  { to: '/findings', label: 'Security Findings', icon: ShieldAlert },
  { to: '/risk', label: 'Risk Assessment', icon: Scale },
  { to: '/reports', label: 'Reports', icon: FileBarChart },
  { to: '/rules', label: 'Rule Management', icon: ScrollText },
  { to: '/settings', label: 'Settings', icon: Settings },
  { to: '/about', label: 'About SecureMailScope', icon: Info },
]
const TITLES: Record<string, string> = { dashboard: 'Overview', analysis: 'Analysis', new: 'New Analysis', captures: 'Capture Library', history: 'Analysis History', protocols: 'Protocol Explorer', tls: 'TLS Inspector', certificates: 'Certificate Inspector', findings: 'Security Findings', risk: 'Risk Assessment', reports: 'Reports', rules: 'Rule Management', settings: 'Settings', about: 'About', results: 'Results', evidence: 'Evidence Explorer' }

function Brand({ collapsed }: { collapsed: boolean }) {
  return (
    <Link to="/dashboard" className="flex items-center gap-2.5 px-4 h-14 border-b border-line">
      <span className="size-8 rounded-lg grid place-items-center bg-gradient-to-br from-accent/25 to-accent2/25 border border-accent/40"><ShieldCheck className="size-4.5 text-accent" /></span>
      {!collapsed && <span className="leading-tight"><span className="block text-sm font-semibold">SecureMailScope</span><span className="block text-[10px] uppercase tracking-widest text-mute">Analyst console</span></span>}
    </Link>
  )
}

function SideNav({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  return (
    <nav aria-label="Primary" className="flex-1 overflow-y-auto p-2.5 space-y-0.5">
      {NAV.map(({ to, label, icon: Icon }) => (
        <NavLink key={to} to={to} onClick={onNavigate} title={collapsed ? label : undefined}
          className={({ isActive }) => cn('flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition', isActive ? 'bg-accent/10 text-accent border border-accent/30' : 'text-mute border border-transparent hover:text-ink hover:bg-elevated', collapsed && 'justify-center px-2')}>
          <Icon className="size-4 shrink-0" aria-hidden />{!collapsed && <span className="truncate">{label}</span>}
        </NavLink>
      ))}
    </nav>
  )
}

function Crumbs() {
  const { pathname } = useLocation()
  const parts = pathname.split('/').filter(Boolean)
  return (
    <ol className="flex items-center gap-1 text-xs text-mute min-w-0" aria-label="Breadcrumb">
      <li><Link to="/dashboard" className="hover:text-ink">SecureMailScope</Link></li>
      {parts.map((p, i) => (
        <li key={i} className="flex items-center gap-1 min-w-0"><ChevronRight className="size-3 shrink-0" />
          <span className={cn('truncate', i === parts.length - 1 && 'text-ink')}>{/^[0-9a-f]{32}$/.test(p) ? p.slice(0, 8) + '…' : TITLES[p] ?? p}</span></li>
      ))}
    </ol>
  )
}

function Notifications() {
  const { data } = useAnalyses({ page_size: 8 })
  const [seen, setSeen] = useState(() => { try { return localStorage.getItem('sms-seen') ?? '' } catch { return '' } })
  const items = data?.items.filter((a) => a.finished_at) ?? []
  const unread = items.filter((a) => (a.finished_at ?? '') > seen).length
  const nav = useNavigate()
  return (
    <DM.Root onOpenChange={(o) => { if (!o && items[0]?.finished_at) { try { localStorage.setItem('sms-seen', items[0].finished_at) } catch { /* ignore */ } setSeen(items[0].finished_at) } }}>
      <DM.Trigger aria-label={`Notifications${unread ? `, ${unread} new` : ''}`} className="relative rounded-lg p-2 text-mute hover:bg-elevated hover:text-ink">
        <Bell className="size-4" />{unread > 0 && <span className="absolute right-1 top-1 size-2 rounded-full bg-accent" />}
      </DM.Trigger>
      <DM.Portal>
        <DM.Content align="end" sideOffset={8} className="z-[100] w-80 rounded-xl border border-line bg-elevated p-1 shadow-2xl fade-in">
          <div className="px-3 py-2 text-xs font-semibold text-mute">Recent activity</div>
          {items.length === 0 && <div className="px-3 py-4 text-sm text-mute">No completed analyses yet.</div>}
          {items.map((a) => (
            <DM.Item key={a.id} onSelect={() => nav(a.status === 'completed' ? `/analysis/${a.id}/results` : `/analysis/${a.id}`)} className="cursor-pointer rounded-lg px-3 py-2 text-sm outline-none data-[highlighted]:bg-surface">
              <div className="truncate font-medium">{a.capture?.filename}</div>
              <div className="text-xs text-mute">{a.status} · {a.counters.findings ?? 0} findings · {relTime(a.finished_at)}</div>
            </DM.Item>
          ))}
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  )
}

function ProfileMenu() {
  const { data } = useSettings()
  const nav = useNavigate()
  const name = data?.settings.analyst_name ?? 'Local analyst'
  return (
    <DM.Root>
      <DM.Trigger aria-label="Profile menu" className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm text-mute hover:bg-elevated hover:text-ink"><UserCircle2 className="size-5" /><span className="hidden md:inline max-w-32 truncate">{name}</span></DM.Trigger>
      <DM.Portal>
        <DM.Content align="end" sideOffset={8} className="z-[100] w-60 rounded-xl border border-line bg-elevated p-1 shadow-2xl fade-in">
          <div className="px-3 py-2"><div className="text-sm font-medium">{name}</div><div className="text-xs text-mute flex items-center gap-1"><Lock className="size-3" />Local-only mode {data?.settings.local_only_mode ? 'on' : 'off'}</div></div>
          <DM.Separator className="my-1 h-px bg-line" />
          {[['Settings', '/settings'], ['Rule management', '/rules'], ['About SecureMailScope', '/about']].map(([l, to]) => (
            <DM.Item key={to} onSelect={() => nav(to)} className="cursor-pointer rounded-lg px-3 py-2 text-sm outline-none data-[highlighted]:bg-surface">{l}</DM.Item>
          ))}
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  )
}

function GlobalSearch() {
  const nav = useNavigate()
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); ref.current?.focus() } }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])
  return (
    <form role="search" className="relative hidden sm:block w-full max-w-sm" onSubmit={(e) => { e.preventDefault(); const q = ref.current?.value.trim(); nav(q ? `/findings?q=${encodeURIComponent(q)}` : '/findings') }}>
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-mute" aria-hidden />
      <input ref={ref} aria-label="Search findings, rules and IDs" placeholder="Search findings, rule IDs…  (Ctrl K)" className="w-full rounded-lg bg-bg border border-line pl-9 pr-3 py-2 text-sm placeholder:text-mute/70 focus:border-accent2 outline-none" />
    </form>
  )
}

export function AppShell() {
  const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem('sms-collapsed') === '1' } catch { return false } })
  const [mobile, setMobile] = useState(false)
  const { pathname } = useLocation()
  const demo = useDemoStatus()
  const deps = useDependencies()
  useEffect(() => { setMobile(false); window.scrollTo(0, 0) }, [pathname])
  const toggle = () => setCollapsed((c) => { try { localStorage.setItem('sms-collapsed', c ? '0' : '1') } catch { /* ignore */ } return !c })
  return (
    <div className="flex h-full">
      <aside className={cn('hidden lg:flex flex-col shrink-0 bg-sidebar border-r border-line transition-all', collapsed ? 'w-[68px]' : 'w-64')}>
        <Brand collapsed={collapsed} /><SideNav collapsed={collapsed} />
        <button onClick={toggle} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} className="m-2.5 flex items-center justify-center gap-2 rounded-lg p-2 text-xs text-mute hover:bg-elevated hover:text-ink">
          {collapsed ? <PanelLeftOpen className="size-4" /> : <><PanelLeftClose className="size-4" />Collapse</>}
        </button>
      </aside>
      {mobile && (
        <div className="fixed inset-0 z-50 lg:hidden"><div className="absolute inset-0 bg-black/60" onClick={() => setMobile(false)} />
          <aside className="absolute left-0 top-0 flex h-full w-72 flex-col bg-sidebar border-r border-line"><Brand collapsed={false} /><SideNav collapsed={false} onNavigate={() => setMobile(false)} /></aside></div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-line bg-sidebar/80 px-4 backdrop-blur">
          <button className="lg:hidden rounded-lg p-2 text-mute hover:bg-elevated" aria-label="Open navigation" onClick={() => setMobile(true)}><Menu className="size-5" /></button>
          <div className="min-w-0 flex-1 hidden md:block"><Crumbs /></div>
          <GlobalSearch />
          <span className="hidden xl:inline-flex items-center gap-1.5 rounded-full border border-accent/30 bg-accent/10 px-2.5 py-1 text-[11px] text-accent"><Lock className="size-3" />Local-only</span>
          <Notifications /><ProfileMenu />
        </header>
        <main className="flex-1 overflow-y-auto" id="main">
          {demo.data && demo.data.loaded > 0 && (
            <div className="sticky top-0 z-20 border-b border-warn/40 bg-warn/15 px-4 py-2 text-center text-xs font-semibold tracking-wide text-warn backdrop-blur" role="status">
              {demo.data.label}
            </div>
          )}
          <div className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8">
            {deps.data && !deps.data.tshark.available && (
              <div className="mb-5"><Notice tone="crit" title="TShark is not installed">{deps.data.guidance} Analyses cannot run until it is available.</Notice></div>
            )}
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}

export function Crumb({ children }: { children: ReactNode }) { return <div className="mb-2 text-xs text-mute flex items-center gap-1.5">{children}</div> }
export { FileSearch }

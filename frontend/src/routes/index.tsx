import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from '@/components/layout/AppShell'
import AboutPage from '@/pages/AboutPage'
import AnalysisProgressPage from '@/pages/AnalysisProgressPage'
import CapturesPage from '@/pages/CapturesPage'
import CertificatesPage from '@/pages/CertificatesPage'
import DashboardPage from '@/pages/DashboardPage'
import EvidencePage from '@/pages/EvidencePage'
import FindingsPage from '@/pages/FindingsPage'
import HistoryPage from '@/pages/HistoryPage'
import NewAnalysisPage from '@/pages/NewAnalysisPage'
import ProtocolsPage from '@/pages/ProtocolsPage'
import ReportsPage from '@/pages/ReportsPage'
import ResultsPage from '@/pages/ResultsPage'
import RiskPage from '@/pages/RiskPage'
import RulesPage from '@/pages/RulesPage'
import SettingsPage from '@/pages/SettingsPage'
import TlsPage from '@/pages/TlsPage'
import { EmptyState } from '@/components/ui/primitives'

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="analysis/new" element={<NewAnalysisPage />} />
        <Route path="analysis/:analysisId" element={<AnalysisProgressPage />} />
        <Route path="analysis/:analysisId/results" element={<ResultsPage />} />
        <Route path="analysis/:analysisId/protocols" element={<ProtocolsPage />} />
        <Route path="analysis/:analysisId/tls" element={<TlsPage />} />
        <Route path="analysis/:analysisId/certificates" element={<CertificatesPage />} />
        <Route path="analysis/:analysisId/evidence" element={<EvidencePage />} />
        <Route path="protocols" element={<ProtocolsPage />} />
        <Route path="tls" element={<TlsPage />} />
        <Route path="certificates" element={<CertificatesPage />} />
        <Route path="evidence" element={<EvidencePage />} />
        <Route path="captures" element={<CapturesPage />} />
        <Route path="history" element={<HistoryPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="risk" element={<RiskPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="rules" element={<RulesPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="about" element={<AboutPage />} />
        <Route path="*" element={<EmptyState title="Page not found" description="That page does not exist." />} />
      </Route>
    </Routes>
  )
}

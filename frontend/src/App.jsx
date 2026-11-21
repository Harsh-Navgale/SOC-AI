import { useState } from 'react'
import Sidebar from './components/layout/Sidebar.jsx'
import Topbar from './components/layout/Topbar.jsx'
import Overview from './components/Overview.jsx'
import AlertsTable from './components/AlertsTable.jsx'
import IncidentsList from './components/IncidentsList.jsx'
import IncidentDetail from './components/IncidentDetail.jsx'
import AIQueue from './components/AIQueue.jsx'
import AIChat from './components/AIChat.jsx'
import SystemHealth from './components/SystemHealth.jsx'
import AssetCoverage from './components/AssetCoverage.jsx'
import S3Inventory from './components/S3Inventory.jsx'
import ThreatIntel from './components/ThreatIntel.jsx'
import UsersAdmin from './components/UsersAdmin.jsx'
import AuditLog from './components/AuditLog.jsx'
import ExclusionRules from './components/ExclusionRules.jsx'
import RuleHealth from './components/RuleHealth.jsx'
import EvalReport from './components/EvalReport.jsx'
import DebugPanel from './components/DebugPanel.jsx'
import WazuhDiagnostics from './components/WazuhDiagnostics.jsx'
import AlertBanner from './components/AlertBanner.jsx'
import Login from './components/Login.jsx'
import { AuthProvider, useAuth } from './AuthContext.jsx'
import { ToastProvider } from './ToastContext.jsx'
import { LiveConnectionProvider } from './LiveConnectionContext.jsx'

const TITLES = {
  overview: 'Overview',
  cases: 'Correlated Alerts',
  incidents: 'Incidents',
  queue: 'AI Queue',
  alerts: 'Raw Alerts',
  assets: 'Asset Coverage',
  s3: 'S3 Inventory',
  'threat-intel': 'Threat Intel',
  ai: 'Ask AI',
  health: 'System Health',
  users: 'Users',
  activity: 'Activity',
  exclusions: 'Alert Exclusions',
  'rule-health': 'Rule Health',
  'eval-report': 'AI Accuracy',
  debug: 'Debug',
  'wazuh-diagnostics': 'Wazuh Diagnostics',
}

function Dashboard() {
  const [tab, setTab] = useState('overview')
  const [selectedIncident, setSelectedIncident] = useState(null)
  const { isAdmin } = useAuth()

  return (
    <LiveConnectionProvider>
      <div className="app-shell">
        <Sidebar tab={tab} setTab={setTab} isAdmin={isAdmin} />
        <div className="content-area">
          <Topbar title={TITLES[tab]} onOpenIncident={setSelectedIncident} />
          <AlertBanner />
          <main className="page">
            <div className="page-content" key={tab}>
              {tab === 'overview' && <Overview />}
              {tab === 'cases' && <IncidentsList onSelect={setSelectedIncident} reviewed="false" noun="correlated alert" />}
              {tab === 'incidents' && <IncidentsList onSelect={setSelectedIncident} reviewed="true" noun="incident" />}
              {tab === 'queue' && <AIQueue />}
              {tab === 'alerts' && <AlertsTable />}
              {tab === 'assets' && <AssetCoverage />}
              {tab === 's3' && <S3Inventory />}
              {tab === 'threat-intel' && <ThreatIntel />}
              {tab === 'ai' && <AIChat />}
              {tab === 'health' && <SystemHealth />}
              {tab === 'users' && isAdmin && <UsersAdmin />}
              {tab === 'activity' && isAdmin && <AuditLog />}
              {tab === 'exclusions' && isAdmin && <ExclusionRules />}
              {tab === 'rule-health' && isAdmin && <RuleHealth />}
              {tab === 'eval-report' && isAdmin && <EvalReport />}
              {tab === 'debug' && isAdmin && <DebugPanel />}
              {tab === 'wazuh-diagnostics' && isAdmin && <WazuhDiagnostics />}
            </div>
          </main>
        </div>
        {selectedIncident && (
          <IncidentDetail incidentId={selectedIncident} onClose={() => setSelectedIncident(null)} />
        )}
      </div>
    </LiveConnectionProvider>
  )
}

function Gate() {
  const { authed } = useAuth()
  return authed ? <Dashboard /> : <Login />
}

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <Gate />
      </ToastProvider>
    </AuthProvider>
  )
}

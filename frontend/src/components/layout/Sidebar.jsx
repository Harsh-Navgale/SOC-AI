import { useEffect, useState } from 'react'
import { IconOverview, IconIncidents, IconCases, IconQueue, IconAlerts, IconChat, IconHealth, IconUsers, IconAssets, IconBucket, IconRadar, IconActivity, IconExclude, IconBug, IconTarget } from '../icons.jsx'
// Rule Health reuses IconHealth — no dedicated icon exists for it yet, and the "system health"
// pulse glyph reads sensibly for "health of a detection rule" too.
import { getIncidents } from '../../api.js'
import { useLiveEvents } from '../../LiveConnectionContext.jsx'

const NAV_ITEMS = [
  { key: 'overview', label: 'Overview', icon: IconOverview },
  { key: 'cases', label: 'Correlated Alerts', icon: IconCases },
  { key: 'incidents', label: 'Incidents', icon: IconIncidents },
  { key: 'queue', label: 'AI Queue', icon: IconQueue },
  { key: 'alerts', label: 'Raw Alerts', icon: IconAlerts },
  { key: 'assets', label: 'Asset Coverage', icon: IconAssets },
  { key: 's3', label: 'S3 Inventory', icon: IconBucket },
  { key: 'threat-intel', label: 'Threat Intel', icon: IconRadar },
  { key: 'ai', label: 'Ask AI', icon: IconChat },
  { key: 'health', label: 'System Health', icon: IconHealth },
]

// Backlog size for the Cases tab — cases the correlator has produced but the AI hasn't
// investigated yet. Polled rather than pushed on every tick, but also refreshed the moment a
// case gets auto/manually investigated (or a new one appears), via the shared incidents_changed
// live event, so the badge doesn't lag behind what auto-investigation is already doing.
function usePendingCasesCount() {
  const [count, setCount] = useState(0)

  const refresh = () => {
    getIncidents({ limit: 1, reviewed: 'false' })
      .then(({ total }) => setCount(total))
      .catch(() => {})
  }

  useEffect(() => {
    refresh()
    const interval = setInterval(refresh, 15000)
    return () => clearInterval(interval)
  }, [])

  useLiveEvents('incidents_changed', refresh)

  return count
}

export default function Sidebar({ tab, setTab, isAdmin }) {
  const pendingCases = usePendingCasesCount()
  const items = isAdmin
    ? [
      ...NAV_ITEMS,
      { key: 'exclusions', label: 'Alert Exclusions', icon: IconExclude },
      { key: 'rule-health', label: 'Rule Health', icon: IconHealth },
      { key: 'eval-report', label: 'AI Accuracy', icon: IconTarget },
      { key: 'users', label: 'Users', icon: IconUsers },
      { key: 'activity', label: 'Activity', icon: IconActivity },
      { key: 'debug', label: 'Debug', icon: IconBug },
      { key: 'wazuh-diagnostics', label: 'Wazuh Diagnostics', icon: IconBug },
    ]
    : NAV_ITEMS

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <span className="sidebar-brand-dot" />
        <span className="sidebar-brand-name">SOC-AI</span>
      </div>
      <nav className="sidebar-nav">
        {items.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            className={`sidebar-link ${tab === key ? 'active' : ''}`}
            onClick={() => setTab(key)}
          >
            <Icon />
            <span>{label}</span>
            {key === 'cases' && pendingCases > 0 && (
              <span className="sidebar-badge">{pendingCases > 99 ? '99+' : pendingCases}</span>
            )}
          </button>
        ))}
      </nav>
      <div className="sidebar-foot">Self-hosted SOC copilot</div>
    </aside>
  )
}

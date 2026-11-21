import { useEffect, useState } from 'react'
import { getDebugMode, setDebugMode, getDebugDiagnostics, getAuthToken, wipeAlertData } from '../api.js'
import { useToast } from '../ToastContext.jsx'
import { SkeletonCard } from './Skeleton.jsx'

const LIVE_LOGS_URL = () => `/debug/logs/all?token=${encodeURIComponent(getAuthToken() || '')}`
const WIPE_CONFIRM_PHRASE = 'DELETE ALL DATA'

function formatRelativeTime(input) {
  if (input === null || input === undefined) return '—'
  const ms = typeof input === 'number' ? input * 1000 : new Date(input).getTime()
  if (Number.isNaN(ms)) return '—'
  const diffSeconds = Math.max(0, (Date.now() - ms) / 1000)
  if (diffSeconds < 5) return 'just now'
  if (diffSeconds < 60) return `${Math.floor(diffSeconds)}s ago`
  const minutes = Math.floor(diffSeconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

// configured/not-configured shows up two ways from the backend: a single `configured` boolean
// (AWS, Wazuh Manager, manual agents) or several `<source>_configured` booleans bundled together
// (Threat Intel's three sources) — this covers both without hardcoding per-integration logic.
function configuredEntries(status) {
  return Object.entries(status).filter(([k]) => k.endsWith('configured'))
}

function Toggle({ checked, onClick, disabled }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      className={`toggle-switch ${checked ? 'on' : ''}`}
      onClick={onClick}
      disabled={disabled}
    >
      <span className="toggle-thumb" />
    </button>
  )
}

function Pill({ ok, okLabel, badLabel }) {
  return <span className={`ti-pill ${ok ? 'ti-pill--good' : 'ti-pill--bad'}`}>{ok ? okLabel : badLabel}</span>
}

function Stat({ label, value }) {
  return (
    <div className="stat-tile">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

export default function DebugPanel() {
  const [debugEnabled, setDebugEnabled] = useState(null)
  const [saving, setSaving] = useState(false)
  const [diagnostics, setDiagnostics] = useState(null)
  const [wiping, setWiping] = useState(false)
  const { showToast } = useToast()

  useEffect(() => {
    getDebugMode().then((r) => setDebugEnabled(r.enabled)).catch((e) => showToast(e.message))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const load = () => getDebugDiagnostics().then(setDiagnostics).catch((e) => showToast(e.message))

  useEffect(() => {
    load()
    const interval = setInterval(load, 10000)
    return () => clearInterval(interval)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const toggleDebugMode = async () => {
    setSaving(true)
    try {
      const r = await setDebugMode(!debugEnabled)
      setDebugEnabled(r.enabled)
      showToast(`Debug mode ${r.enabled ? 'enabled' : 'disabled'}.`, 'success')
      load()
    } catch (e) {
      showToast(e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleWipeAlertData = async () => {
    const typed = window.prompt(
      `This permanently deletes every raw alert, case, and incident — there is no undo.\n\n` +
      `Type "${WIPE_CONFIRM_PHRASE}" to confirm:`
    )
    if (typed !== WIPE_CONFIRM_PHRASE) {
      if (typed !== null) showToast('Did not match — nothing was deleted.')
      return
    }
    setWiping(true)
    try {
      const result = await wipeAlertData()
      showToast(
        `Deleted ${result.raw_alerts_deleted.toLocaleString()} raw alert(s) and ${result.incidents_deleted.toLocaleString()} case/incident(s).`,
        'success'
      )
      load()
    } catch (e) {
      showToast(e.message)
    } finally {
      setWiping(false)
    }
  }

  if (!diagnostics || debugEnabled === null) {
    return (
      <div className="health-grid">
        {Array.from({ length: 5 }).map((_, i) => <SkeletonCard key={i} lines={2} />)}
      </div>
    )
  }

  const { ai_usage: aiUsage, correlator, correlation, integrations, active_alerts: activeAlerts, recent_errors: recentErrors, wazuh_ingestion: wazuhIngestion } = diagnostics
  const hasActiveAlerts = activeAlerts.length > 0

  return (
    <div className="content-fade-in">
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <a className="btn-outline" href={LIVE_LOGS_URL()} target="_blank" rel="noopener noreferrer">
          View live logs
        </a>
      </div>

      <div className="debug-status-row">
        <div className="debug-status-tile">
          <span className="debug-status-label">Debug mode</span>
          <div className="debug-status-control">
            <Toggle checked={debugEnabled} onClick={toggleDebugMode} disabled={saving} />
            <span className="muted" style={debugEnabled ? { color: 'var(--warning)', fontWeight: 600 } : undefined}>
              {debugEnabled ? 'ON' : 'OFF'}
            </span>
          </div>
        </div>
        <div className="debug-status-tile">
          <span className="debug-status-label">Case enrichment</span>
          <Pill ok={diagnostics.enrichment_enabled} okLabel="Running" badLabel="Paused" />
        </div>
        <div className="debug-status-tile">
          <span className="debug-status-label">Auto-investigate</span>
          <Pill ok={diagnostics.auto_investigate_enabled} okLabel="Running" badLabel="Paused" />
        </div>
        <div className="debug-status-tile">
          <span className="debug-status-label">Scheduler alerts</span>
          <span className={`ti-pill ${hasActiveAlerts ? 'ti-pill--bad' : 'ti-pill--good'}`}>
            {hasActiveAlerts ? `${activeAlerts.length} active` : 'All clear'}
          </span>
        </div>
      </div>

      {hasActiveAlerts && (
        <div className="card debug-alert-card">
          <h3>Active alerts</h3>
          <ul className="notes-list">
            {activeAlerts.map((a) => (
              <li key={a.source}>
                <div>
                  <strong>{a.source}</strong>
                  <div className="muted" style={{ marginTop: 4 }}>{a.message}</div>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="health-grid">
        <div className="health-card">
          <div className="health-card-header">
            <h3>AI usage</h3>
            <span className="muted" style={{ fontSize: 11 }}>since backend start</span>
          </div>
          <div className="stat-row">
            <Stat label="Calls" value={aiUsage.calls} />
            <Stat label="Prompt tok" value={aiUsage.prompt_tokens.toLocaleString()} />
            <Stat label="Completion tok" value={aiUsage.completion_tokens.toLocaleString()} />
            <Stat label="Est. cost" value={`$${aiUsage.estimated_cost.toFixed(4)}`} />
            <Stat label="Month to date" value={`$${aiUsage.month_to_date_cost.toFixed(4)}${aiUsage.monthly_budget_cap != null ? ` / $${aiUsage.monthly_budget_cap}` : ''}`} />
          </div>
          <p className="muted" style={{ marginTop: 12, marginBottom: 0, fontSize: 12.5 }}>
            Parse failure rate: {aiUsage.parse_failure_rate === null
              ? 'no investigations yet'
              : `${(aiUsage.parse_failure_rate * 100).toFixed(1)}% (${aiUsage.parse_failures}/${aiUsage.parse_total})`}
          </p>
        </div>

        <div className="health-card">
          <div className="health-card-header"><h3>Correlator</h3></div>
          <div className="stat-row">
            <Stat label="Last run" value={formatRelativeTime(correlator.last_run)} />
            <Stat label="Alerts processed" value={(correlator.alerts_processed_total ?? 0).toLocaleString()} />
          </div>
          {correlator.last_error && (
            <p style={{ color: 'var(--critical)', fontSize: 12.5, marginTop: 10, marginBottom: 0 }}>{correlator.last_error}</p>
          )}
        </div>

        {wazuhIngestion && (
          <div className="health-card">
            <div className="health-card-header"><h3>Wazuh alert ingestion</h3></div>
            <div className="stat-row">
              <Stat label="Last poll" value={wazuhIngestion.at ? formatRelativeTime(wazuhIngestion.at) : 'never'} />
              <Stat label="Fetched" value={wazuhIngestion.fetched} />
            </div>
            {wazuhIngestion.truncated && (
              <p style={{ color: 'var(--critical)', fontSize: 12.5, marginTop: 10, marginBottom: 0 }}>
                Falling behind — more alerts were available than this poll could fetch.
              </p>
            )}
          </div>
        )}

        <div className="health-card">
          <div className="health-card-header"><h3>Correlation settings</h3></div>
          <div className="stat-row">
            <Stat label="Window (s)" value={correlation.window_seconds} />
            <Stat label="Threshold" value={correlation.threshold} />
          </div>
        </div>

        <div className="health-card" style={{ gridColumn: 'span 2' }}>
          <div className="health-card-header"><h3>Integrations</h3></div>
          <div className="debug-integration-list">
            {Object.entries(integrations).map(([name, status]) => (
              <div key={name} className="debug-integration-row">
                <span className="debug-integration-name">{name.replace(/_/g, ' ')}</span>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {configuredEntries(status).map(([key, val]) => (
                    <span key={key} className={`ti-pill ${val ? 'ti-pill--good' : 'ti-pill--bad'}`}>
                      {key === 'configured' ? (val ? 'Configured' : 'Not configured') : `${key.replace('_configured', '')}: ${val ? 'yes' : 'no'}`}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 20 }}>
        <h3 style={{ margin: '0 0 12px' }}>Recent errors</h3>
        {recentErrors.length === 0 ? (
          <p className="muted">No errors recorded since the backend last started.</p>
        ) : (
          <ul className="notes-list">
            {recentErrors.map((e, i) => (
              <li key={i}>
                <div>
                  <strong>{e.source}</strong> <span className="muted">{formatRelativeTime(e.at)}</span>
                  <div className="mono" style={{ marginTop: 4, fontSize: 12.5 }}>{e.detail}</div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="card debug-alert-card" style={{ marginTop: 20 }}>
        <h3>Danger zone</h3>
        <p className="muted" style={{ margin: '0 0 12px' }}>
          Permanently deletes every raw alert, case, and incident — the correlator's queue, the
          AI Queue, and the Incidents tab will all be empty afterward. This cannot be undone.
        </p>
        <button type="button" className="danger-link" onClick={handleWipeAlertData} disabled={wiping}>
          {wiping ? 'Deleting...' : 'Delete all cases, incidents & raw alerts'}
        </button>
      </div>
    </div>
  )
}

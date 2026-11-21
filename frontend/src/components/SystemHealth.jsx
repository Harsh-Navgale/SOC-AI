import { useEffect, useState } from 'react'
import {
  getSystemHealth,
  getAlertIngestionSetting, setAlertIngestionSetting,
  getCaseCorrelationSetting, setCaseCorrelationSetting,
  getCaseEnrichmentSetting, setCaseEnrichmentSetting,
  getAutoInvestigateSetting, setAutoInvestigateSetting,
  getCampaignCorrelationSetting, setCampaignCorrelationSetting,
} from '../api.js'
import { useToast } from '../ToastContext.jsx'
import { useAuth } from '../AuthContext.jsx'
import { SkeletonCard } from './Skeleton.jsx'

// Status palette per the design system's fixed status roles (never themed,
// always paired with an icon + label so color never carries meaning alone).
const STATUS_STYLES = {
  ok: { color: '#0ca30c', icon: '●', label: 'OK' },
  green: { color: '#0ca30c', icon: '●', label: 'GREEN' },
  stale: { color: '#fab219', icon: '▲', label: 'STALE' },
  yellow: { color: '#fab219', icon: '▲', label: 'YELLOW' },
  unreachable: { color: '#d03b3b', icon: '✕', label: 'UNREACHABLE' },
  red: { color: '#d03b3b', icon: '✕', label: 'RED' },
  error: { color: '#d03b3b', icon: '✕', label: 'ERROR' },
  not_configured: { color: '#898781', icon: '○', label: 'NOT CONFIGURED' },
  unknown: { color: '#898781', icon: '○', label: 'UNKNOWN' },
}

function StatusBadge({ status }) {
  const style = STATUS_STYLES[status] || STATUS_STYLES.unknown
  return (
    <span className="status-badge" style={{ color: style.color, borderColor: style.color }}>
      <span aria-hidden="true">{style.icon}</span> {style.label}
    </span>
  )
}

function Stat({ label, value }) {
  if (value === undefined || value === null) return null
  return (
    <div className="stat-tile">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

function HealthCard({ title, data, children }) {
  if (!data) return null
  return (
    <div className="health-card">
      <div className="health-card-header">
        <h3>{title}</h3>
        <StatusBadge status={data.status} />
      </div>
      {data.error && <p className="muted health-error">{data.error}</p>}
      {children}
    </div>
  )
}

// One card per pipeline stage (raw alert -> case -> AI investigation -> incident), each with
// its own independent pause switch — pausing one stage doesn't touch the others. What's
// already sitting downstream keeps working; only the paused stage stops picking up new work.
const PIPELINE_STAGES = [
  {
    title: 'Alert Ingestion',
    description: 'Pulls new alerts from Wazuh every 30s. Pause to stop polling — nothing already ingested is affected.',
    verb: 'polling for new alerts',
    get: getAlertIngestionSetting,
    set: setAlertIngestionSetting,
  },
  {
    title: 'Case Correlation',
    description: "Groups raw alerts into cases. Pause and alerts just wait, uncorrelated, until it's resumed.",
    verb: 'case correlation',
    get: getCaseCorrelationSetting,
    set: setCaseCorrelationSetting,
  },
  {
    title: 'Case Enrichment',
    description: 'Adds threat intel and org-docs instance/client context to every new case, right after correlation and before AI investigation. Pause if the threat-intel APIs or Bedrock need a break — cases wait in the queue until resumed.',
    verb: 'case enrichment',
    get: getCaseEnrichmentSetting,
    set: setCaseEnrichmentSetting,
  },
  {
    title: 'AI Investigation',
    description: 'Investigates every new case automatically, one at a time. Pause if Bedrock needs a break — cases wait in the queue until resumed.',
    verb: 'auto-investigation',
    get: getAutoInvestigateSetting,
    set: setAutoInvestigateSetting,
  },
  {
    title: 'Campaign Correlation',
    description: 'Groups open incidents that share a rule or MITRE tactic across different source IPs within a rolling window into a labeled campaign. Informational only — pausing it just stops new groupings; nothing already tagged is affected.',
    verb: 'campaign correlation',
    get: getCampaignCorrelationSetting,
    set: setCampaignCorrelationSetting,
  },
]

function PipelineStageCard({ stage }) {
  const [enabled, setEnabled] = useState(null)
  const [saving, setSaving] = useState(false)
  const { showToast } = useToast()

  useEffect(() => {
    stage.get().then((r) => setEnabled(r.enabled)).catch((e) => showToast(e.message))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const toggle = async () => {
    setSaving(true)
    try {
      const r = await stage.set(!enabled)
      setEnabled(r.enabled)
      showToast(`${stage.title}: ${r.enabled ? 'resumed' : 'paused'}.`, 'success')
    } catch (e) {
      showToast(e.message)
    } finally {
      setSaving(false)
    }
  }

  if (enabled === null) return null

  return (
    <div className="health-card">
      <div className="health-card-header">
        <h3>{stage.title}</h3>
        <span className="status-badge" style={{ color: enabled ? '#0ca30c' : '#898781', borderColor: enabled ? '#0ca30c' : '#898781' }}>
          <span aria-hidden="true">{enabled ? '●' : '○'}</span> {enabled ? 'RUNNING' : 'PAUSED'}
        </span>
      </div>
      <p className="muted" style={{ margin: '0 0 12px' }}>{stage.description}</p>
      <button type="button" className="btn-outline" onClick={toggle} disabled={saving}>
        {saving ? 'Saving...' : enabled ? `Pause ${stage.verb}` : `Resume ${stage.verb}`}
      </button>
    </div>
  )
}

export default function SystemHealth() {
  const [health, setHealth] = useState(null)
  const { showToast } = useToast()
  const { isAdmin } = useAuth()

  useEffect(() => {
    const load = () => getSystemHealth().then(setHealth).catch((e) => showToast(e.message))
    load()
    const interval = setInterval(load, 15000)
    return () => clearInterval(interval)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!health) {
    return (
      <div className="health-grid">
        {Array.from({ length: 6 }).map((_, i) => <SkeletonCard key={i} lines={2} />)}
      </div>
    )
  }

  return (
    <div className="health-grid content-fade-in">
      {isAdmin && PIPELINE_STAGES.map((stage) => <PipelineStageCard key={stage.title} stage={stage} />)}

      <HealthCard title="Backend" data={health.backend}>
        <div className="stat-row">
          <Stat label="Uptime (s)" value={health.backend.uptime_seconds} />
        </div>
      </HealthCard>

      <HealthCard title="MongoDB" data={health.mongodb}>
        <div className="stat-row">
          <Stat label="Storage (MB)" value={health.mongodb.storage_mb} />
          <Stat label="Connections" value={health.mongodb.connections_current} />
          <Stat label="Raw alerts" value={health.mongodb.collections?.raw_alerts} />
          <Stat label="Incidents" value={health.mongodb.collections?.incidents} />
          <Stat label="Users" value={health.mongodb.collections?.users} />
        </div>
      </HealthCard>

      <HealthCard title="ChromaDB (Vector DB)" data={health.chromadb}>
        <div className="stat-row">
          <Stat label="Documents" value={health.chromadb.documents} />
        </div>
      </HealthCard>

      <HealthCard title="Correlator" data={health.correlator}>
        <div className="stat-row">
          <Stat label="Last run (s ago)" value={health.correlator.seconds_since_last_run} />
          <Stat label="Alerts processed (total)" value={health.correlator.alerts_processed_total} />
        </div>
      </HealthCard>

      <HealthCard title="Wazuh Manager" data={health.wazuh_manager}>
        <div className="stat-row">
          <Stat label="Version" value={health.wazuh_manager.version} />
          <Stat label="Agents active" value={health.wazuh_manager.agents?.active} />
          <Stat label="Agents disconnected" value={health.wazuh_manager.agents?.disconnected} />
          <Stat label="Agents total" value={health.wazuh_manager.agents?.total} />
          <Stat label="Alerts (this hour)" value={health.wazuh_manager.current_hour?.total_alerts} />
          <Stat label="Events (this hour)" value={health.wazuh_manager.current_hour?.events} />
          <Stat label="Daemons running" value={health.wazuh_manager.daemons?.running?.length} />
        </div>
        {health.wazuh_manager.daemons?.stopped?.length > 0 && (
          <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>
            Stopped: {health.wazuh_manager.daemons.stopped.join(', ')}
          </p>
        )}
        {health.wazuh_manager.nodes?.map((node) => (
          <div key={node.name} style={{ marginTop: 12 }}>
            <p className="muted" style={{ margin: '0 0 6px', fontSize: 12, fontWeight: 600 }}>
              Node: {node.name} &mdash; {node.type || 'unknown role'}
            </p>
            <div className="stat-row">
              <Stat label="Version" value={node.version} />
              <Stat label="Sync status" value={node.status} />
              <Stat label="Last keep-alive" value={node.last_keep_alive} />
            </div>
          </div>
        ))}
      </HealthCard>

      <HealthCard title="Wazuh Indexer" data={health.wazuh_indexer}>
        <div className="stat-row">
          <Stat label="Cluster" value={health.wazuh_indexer.cluster_name} />
          <Stat label="Active shards" value={health.wazuh_indexer.active_shards} />
          <Stat label="Alert indices" value={health.wazuh_indexer.alert_index_count} />
          <Stat label="Alert storage (MB)" value={health.wazuh_indexer.alert_storage_mb} />
        </div>
        {health.wazuh_indexer.nodes?.map((node) => (
          <div key={node.name} style={{ marginTop: 12 }}>
            <p className="muted" style={{ margin: '0 0 6px', fontSize: 12, fontWeight: 600 }}>
              Node: {node.name} &mdash; real host disk usage, not just alert storage above
            </p>
            <div className="stat-row">
              <Stat label="Disk total (GB)" value={node.disk_total_gb} />
              <Stat label="Disk used (GB)" value={node.disk_used_gb} />
              <Stat label="Disk avail (GB)" value={node.disk_avail_gb} />
              <Stat label="Disk used %" value={node.disk_used_percent} />
              <Stat label="Heap %" value={node.heap_percent} />
              <Stat label="RAM %" value={node.ram_percent} />
              <Stat label="CPU %" value={node.cpu_percent} />
              {node.load_1m != null && <Stat label="Load (1m)" value={node.load_1m} />}
            </div>
          </div>
        ))}
      </HealthCard>
    </div>
  )
}

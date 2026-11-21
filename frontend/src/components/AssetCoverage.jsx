import { useEffect, useMemo, useState } from 'react'
import { getAWSStatus, clearAWSCredentials, getAssetCoverage, refreshAssetCache, getAssetCacheStatus } from '../api.js'
import { useAuth } from '../AuthContext.jsx'
import { useToast } from '../ToastContext.jsx'
import ConnectAWSForm from './ConnectAWSForm.jsx'
import ConnectWazuhForm from './ConnectWazuhForm.jsx'
import UploadAgentSheetForm from './UploadAgentSheetForm.jsx'
import { SkeletonKpiRow, SkeletonCard } from './Skeleton.jsx'
import WazuhAgents from './WazuhAgents.jsx'
import { toCsv, downloadCsv } from '../lib/csv.js'
import { IconRefresh, IconDownload, IconDisconnect, IconAssets, IconClock, IconAlerts } from './icons.jsx'

const FIXED_CSV_COLUMNS = ['category', 'hostname', 'ip', 'agent_id', 'agent_ip', 'agent_status']

// Every field from the S3 inventory record is carried into the CSV, not just hostname —
// prefixed with s3_ so an S3 column (e.g. one literally named "status" or "id") can never
// collide with or silently overwrite the fixed agent_id/agent_ip/agent_status columns above.
function s3FieldsToRow(s3Record) {
  const row = {}
  for (const [key, value] of Object.entries(s3Record || {})) {
    row[`s3_${key}`] = value
  }
  return row
}

function buildCoverageCsvRows(data) {
  const rows = []
  const addAll = (category, items, mapRow) => {
    for (const item of items) rows.push({ category, ...mapRow(item) })
  }

  addAll('missing', data.missing, (m) => ({
    hostname: m.hostname, ip: m.ip, agent_id: '', agent_ip: '', agent_status: '', ...s3FieldsToRow(m.s3_record),
  }))
  addAll('connected', data.connected, (c) => ({
    hostname: c.hostname, ip: c.ip, agent_id: c.agent_id, agent_ip: c.agent_ip, agent_status: 'active', ...s3FieldsToRow(c.s3_record),
  }))
  addAll('disconnected', data.disconnected, (d) => ({
    hostname: d.hostname, ip: d.ip, agent_id: d.agent_id, agent_ip: d.agent_ip, agent_status: d.agent_status, ...s3FieldsToRow(d.s3_record),
  }))
  addAll('pending', data.pending, (p) => ({
    hostname: p.hostname, ip: p.ip, agent_id: p.agent_id, agent_ip: p.agent_ip, agent_status: p.agent_status, ...s3FieldsToRow(p.s3_record),
  }))
  addAll('other', data.other, (o) => ({
    hostname: o.hostname, ip: o.ip, agent_id: o.agent_id, agent_ip: o.agent_ip, agent_status: o.agent_status, ...s3FieldsToRow(o.s3_record),
  }))
  addAll('orphaned_agent', data.orphaned_agents, (o) => ({
    hostname: o.name, ip: '', agent_id: o.agent_id, agent_ip: o.ip, agent_status: o.status,
  }))

  return rows
}

// Union of every S3 record field across all categories that carry one (missing, connected,
// disconnected, pending, other — orphaned agents have no s3_record, they're Wazuh-only) —
// used to render the full S3 data as real table columns on-screen, not just in the CSV export.
function collectS3Columns(data) {
  const keys = new Set()
  const scan = (items) => {
    for (const item of items) {
      for (const key of Object.keys(item.s3_record || {})) keys.add(key)
    }
  }
  scan(data.missing)
  scan(data.connected)
  scan(data.disconnected)
  scan(data.pending)
  scan(data.other)
  return [...keys]
}

function S3ColumnCells({ s3Record, columns }) {
  return columns.map((c) => (
    <td key={c} className="mono muted">{String(s3Record?.[c] ?? '')}</td>
  ))
}

function buildCoverageCsvColumns(rows) {
  const s3Columns = new Set()
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (key.startsWith('s3_')) s3Columns.add(key)
    }
  }
  return [...FIXED_CSV_COLUMNS, ...s3Columns]
}

function CoverageComparison() {
  const { isAdmin } = useAuth()
  const { showToast } = useToast()
  const [awsStatus, setAwsStatus] = useState(null)
  const [data, setData] = useState(null)
  const [state, setState] = useState('loading')
  const [error, setError] = useState(null)
  const [cacheStatus, setCacheStatus] = useState(null)
  const [resyncing, setResyncing] = useState(false)

  const load = async () => {
    setState('loading')
    setError(null)
    try {
      const status = await getAWSStatus()
      setAwsStatus(status)
      const coverage = await getAssetCoverage()
      setData(coverage)
      setState('ready')
      getAssetCacheStatus().then(setCacheStatus).catch(() => {})
    } catch (err) {
      const msg = err.message || ''
      setError(msg)
      if (msg.includes('AWS session')) setState('need_aws')
      else if (msg.includes('S3_INVENTORY_BUCKET')) setState('need_s3_config')
      else if (msg.includes('Wazuh Manager')) setState('need_wazuh')
      else setState('error')
    }
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const handleDisconnect = async () => {
    try {
      await clearAWSCredentials()
      load()
    } catch (err) {
      showToast(err.message)
    }
  }

  const handleResync = async () => {
    setResyncing(true)
    try {
      const result = await refreshAssetCache()
      showToast(`Refreshed S3 inventory cache — ${result.count} record(s).`, 'success')
      await load()
    } catch (err) {
      showToast(err.message)
    } finally {
      setResyncing(false)
    }
  }

  const [search, setSearch] = useState('')

  const filtered = useMemo(() => {
    if (!data) return null
    const term = search.trim().toLowerCase()
    if (!term) return data
    const match = (item, fields) => fields.some((f) => String(item[f] || '').toLowerCase().includes(term))
    const filterList = (items, fields) => items.filter((item) => match(item, fields))
    return {
      ...data,
      missing: filterList(data.missing, ['hostname', 'ip']),
      disconnected: filterList(data.disconnected, ['hostname', 'ip', 'agent_ip']),
      pending: filterList(data.pending, ['hostname', 'ip', 'agent_ip']),
      other: filterList(data.other, ['hostname', 'ip', 'agent_ip']),
      connected: filterList(data.connected, ['hostname', 'ip', 'agent_ip']),
      orphaned_agents: filterList(data.orphaned_agents, ['name', 'ip']),
    }
  }, [data, search])

  const s3Columns = useMemo(() => (data ? collectS3Columns(data) : []), [data])

  const handleDownload = () => {
    const rows = buildCoverageCsvRows(filtered)
    const columns = buildCoverageCsvColumns(rows).map((key) => ({ label: key, value: (row) => row[key] }))
    const timestamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
    downloadCsv(`asset-coverage-${timestamp}.csv`, toCsv(rows, columns))
  }

  if (state === 'loading') {
    return (
      <div>
        <SkeletonKpiRow count={6} />
        <SkeletonCard lines={3} />
      </div>
    )
  }

  if (state === 'need_aws') {
    return isAdmin ? (
      <ConnectAWSForm onConnected={load} />
    ) : (
      <p className="muted">AWS isn't connected yet. Ask an admin to connect it from this page.</p>
    )
  }

  if (state === 'need_s3_config') {
    return (
      <p className="login-error">
        S3_INVENTORY_BUCKET isn't set in .env yet. An admin needs to configure the S3 inventory
        bucket/prefix before this page can reconcile against Wazuh agents.
      </p>
    )
  }

  if (state === 'need_wazuh') {
    return isAdmin ? (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <ConnectWazuhForm onConnected={load} />
        <UploadAgentSheetForm onUploaded={load} />
      </div>
    ) : (
      <p className="muted">
        Wazuh Manager isn't connected yet. Ask an admin to connect it or upload an agent sheet.
      </p>
    )
  }

  if (state === 'error') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, alignItems: 'flex-start' }}>
        <p className="login-error">{error}</p>
        {isAdmin && (
          <button className="ask" onClick={() => setState('need_aws')}>
            Re-enter AWS credentials
          </button>
        )}
      </div>
    )
  }

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>
          {data.s3_record_count} S3 record{data.s3_record_count === 1 ? '' : 's'} vs {data.wazuh_agent_count} Wazuh agent{data.wazuh_agent_count === 1 ? '' : 's'}
          {data.agents_source && (
            <span className="role-pill" style={{ marginLeft: 10, textTransform: 'none' }}>
              {data.agents_source === 'live' ? 'Live' : 'Manual sheet'}
            </span>
          )}
        </h2>
        <div className="toolbar-actions">
          {awsStatus?.expires_at && (
            <span className="muted mono" style={{ fontSize: 11 }}>
              AWS session expires {awsStatus.expires_at}
            </span>
          )}
          {cacheStatus?.refreshed_at && (
            <span className="muted mono" style={{ fontSize: 11 }} title="S3 inventory cache last filled by the resync below or the daily scheduler job">
              S3 cache refreshed {cacheStatus.refreshed_at} ({cacheStatus.count} record{cacheStatus.count === 1 ? '' : 's'})
            </span>
          )}
          <button className="btn-outline" onClick={load} title="Reload the currently cached data"><IconRefresh width={14} height={14} /> Refresh</button>
          <button className="btn-outline" onClick={handleDownload} title="Download CSV"><IconDownload width={14} height={14} /> Download CSV</button>
          {isAdmin && (
            <button
              className="btn-outline"
              onClick={handleResync}
              disabled={resyncing}
              title="Pulls the latest S3 inventory now, instead of waiting for the daily scheduler job"
            >
              <IconRefresh width={14} height={14} /> {resyncing ? 'Resyncing…' : 'Resync from S3'}
            </button>
          )}
          {isAdmin && (
            <button className="btn-outline" onClick={handleDisconnect} title="Disconnect AWS"><IconDisconnect width={14} height={14} /> Disconnect</button>
          )}
        </div>
      </div>

      <div className="toolbar-actions" style={{ marginBottom: 18 }}>
        <input
          className="search-input"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search hostname or IP across every table..."
        />
      </div>

      <div className="kpi-row">
        <div className="kpi-tile kpi-accent-good">
          <div className="kpi-icon"><IconAssets width={16} height={16} /></div>
          <div className="kpi-value">{data.summary.connected}</div>
          <div className="kpi-label">Connected</div>
        </div>
        <div className="kpi-tile">
          <div className="kpi-icon"><IconDisconnect width={16} height={16} /></div>
          <div className="kpi-value">{data.summary.disconnected}</div>
          <div className="kpi-label">Disconnected</div>
        </div>
        <div className="kpi-tile">
          <div className="kpi-icon"><IconClock width={16} height={16} /></div>
          <div className="kpi-value">{data.summary.pending}</div>
          <div className="kpi-label">Pending</div>
        </div>
        <div className="kpi-tile">
          <div className="kpi-icon"><IconAssets width={16} height={16} /></div>
          <div className="kpi-value">{data.summary.other}</div>
          <div className="kpi-label">Other</div>
        </div>
        <div className="kpi-tile kpi-accent-critical">
          <div className="kpi-icon"><IconAlerts width={16} height={16} /></div>
          <div className="kpi-value">{data.summary.missing}</div>
          <div className="kpi-label">Missing coverage</div>
        </div>
        <div className="kpi-tile">
          <div className="kpi-icon"><IconAssets width={16} height={16} /></div>
          <div className="kpi-value">{data.summary.orphaned}</div>
          <div className="kpi-label">Orphaned agents</div>
        </div>
      </div>

      <h3>Missing coverage &mdash; in S3, no Wazuh agent with this IP</h3>
      <div className="table-card">
        <table>
          <thead><tr><th>Hostname</th><th>S3 IP</th>{s3Columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
          <tbody>
            {filtered.missing.map((m, i) => (
              <tr key={i}>
                <td className="mono">
                  <span className="sev-dot high" />
                  {m.hostname || <span className="muted">&mdash;</span>}
                </td>
                <td className="mono">
                  {m.ip || <span className="muted" title="No recognized IP column in this S3 record">&mdash;</span>}
                </td>
                <S3ColumnCells s3Record={m.s3_record} columns={s3Columns} />
              </tr>
            ))}
            {filtered.missing.length === 0 && <tr><td className="muted table-empty-cell" colSpan={2 + s3Columns.length}>{search ? 'No matches.' : 'None — full coverage.'}</td></tr>}
          </tbody>
        </table>
      </div>

      <h3>Disconnected</h3>
      <div className="table-card">
        <table>
          <thead><tr><th>Hostname</th><th>S3 IP</th><th>Agent IP</th><th>Status</th>{s3Columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
          <tbody>
            {filtered.disconnected.map((d, i) => (
              <tr key={i}>
                <td className="mono">{d.hostname}</td>
                <td className="mono">{d.ip}</td>
                <td className="mono">{d.agent_ip}</td>
                <td><span className="case-status case-status-closed">{d.agent_status}</span></td>
                <S3ColumnCells s3Record={d.s3_record} columns={s3Columns} />
              </tr>
            ))}
            {filtered.disconnected.length === 0 && <tr><td colSpan={4 + s3Columns.length} className="muted table-empty-cell">{search ? 'No matches.' : 'None.'}</td></tr>}
          </tbody>
        </table>
      </div>

      <h3>Pending &amp; other</h3>
      <div className="table-card">
        <table>
          <thead><tr><th>Hostname</th><th>S3 IP</th><th>Agent IP</th><th>Status</th>{s3Columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
          <tbody>
            {[...filtered.pending, ...filtered.other].map((p, i) => (
              <tr key={i}>
                <td className="mono">{p.hostname}</td>
                <td className="mono">{p.ip}</td>
                <td className="mono">{p.agent_ip}</td>
                <td><span className="case-status case-status-investigating">{p.agent_status}</span></td>
                <S3ColumnCells s3Record={p.s3_record} columns={s3Columns} />
              </tr>
            ))}
            {filtered.pending.length === 0 && filtered.other.length === 0 && (
              <tr><td colSpan={4 + s3Columns.length} className="muted table-empty-cell">{search ? 'No matches.' : 'None.'}</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <h3>Orphaned agents &mdash; registered in Wazuh, not in S3 inventory</h3>
      <div className="table-card">
        <table>
          <thead><tr><th>Name</th><th>IP</th><th>Status</th></tr></thead>
          <tbody>
            {filtered.orphaned_agents.map((o) => (
              <tr key={o.agent_id}>
                <td className="mono">{o.name}</td>
                <td className="mono">{o.ip}</td>
                <td>{o.status}</td>
              </tr>
            ))}
            {filtered.orphaned_agents.length === 0 && <tr><td colSpan={3} className="muted table-empty-cell">{search ? 'No matches.' : 'None.'}</td></tr>}
          </tbody>
        </table>
      </div>

      <h3>Connected</h3>
      <div className="table-card">
        <table>
          <thead><tr><th>Hostname</th><th>S3 IP</th><th>Agent IP</th>{s3Columns.map((c) => <th key={c}>{c}</th>)}</tr></thead>
          <tbody>
            {filtered.connected.map((c, i) => (
              <tr key={i}>
                <td className="mono"><span className="sev-dot low" />{c.hostname}</td>
                <td className="mono">{c.ip}</td>
                <td className="mono">{c.agent_ip}</td>
                <S3ColumnCells s3Record={c.s3_record} columns={s3Columns} />
              </tr>
            ))}
            {filtered.connected.length === 0 && <tr><td colSpan={3 + s3Columns.length} className="muted table-empty-cell">{search ? 'No matches.' : 'None yet.'}</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default function AssetCoverage() {
  const [subtab, setSubtab] = useState('agents')

  return (
    <div>
      <div className="subtabs">
        <button className={`subtab ${subtab === 'agents' ? 'active' : ''}`} onClick={() => setSubtab('agents')}>
          Wazuh Agents
        </button>
        <button className={`subtab ${subtab === 'comparison' ? 'active' : ''}`} onClick={() => setSubtab('comparison')}>
          Coverage Comparison
        </button>
      </div>
      {subtab === 'agents' && <WazuhAgents />}
      {subtab === 'comparison' && <CoverageComparison />}
    </div>
  )
}

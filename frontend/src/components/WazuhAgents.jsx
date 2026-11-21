import { useEffect, useMemo, useState } from 'react'
import { getWazuhAgents } from '../api.js'
import { useAuth } from '../AuthContext.jsx'
import { SkeletonRows } from './Skeleton.jsx'
import EmptyState from './EmptyState.jsx'
import { IconAssets, IconRefresh } from './icons.jsx'
import ConnectWazuhForm from './ConnectWazuhForm.jsx'
import UploadAgentSheetForm from './UploadAgentSheetForm.jsx'

const STATUS_CLASS = {
  active: 'case-status-open',
  disconnected: 'case-status-closed',
  pending: 'case-status-investigating',
}

export default function WazuhAgents() {
  const { isAdmin } = useAuth()
  const [state, setState] = useState('loading')
  const [error, setError] = useState(null)
  const [agents, setAgents] = useState([])
  const [source, setSource] = useState(null)
  const [search, setSearch] = useState('')

  const load = async () => {
    setState('loading')
    setError(null)
    try {
      const result = await getWazuhAgents()
      setAgents(result.agents)
      setSource(result.source)
      setState('ready')
    } catch (err) {
      const msg = err.message || ''
      setError(msg)
      setState(msg.includes('Wazuh Manager') ? 'need_wazuh' : 'error')
    }
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const filtered = useMemo(() => {
    if (!search.trim()) return agents
    const q = search.trim().toLowerCase()
    return agents.filter((a) => (a.name || '').toLowerCase().includes(q) || (a.ip || '').includes(q))
  }, [agents, search])

  // Manually-uploaded sheets can have arbitrary extra columns beyond id/name/ip/status
  // (captured in `raw`) — show every one of them as its own column, same union-of-columns
  // approach as the S3 Inventory tab, so nothing from an uploaded CSV is hidden.
  const extraColumns = useMemo(() => {
    const known = new Set(['id', 'name', 'ip', 'status'])
    const keys = new Set()
    for (const a of agents) {
      for (const key of Object.keys(a.raw || {})) {
        if (!known.has(key.toLowerCase())) keys.add(key)
      }
    }
    return [...keys]
  }, [agents])

  if (state === 'loading') {
    return (
      <div className="table-card">
        <table>
          <thead><tr><th>ID</th><th>Name</th><th>IP</th><th>Status</th></tr></thead>
          <tbody><SkeletonRows rows={6} columns={4} /></tbody>
        </table>
      </div>
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
        Wazuh Manager isn't connected yet. Ask an admin to connect it or upload an agent sheet
        from this page.
      </p>
    )
  }

  if (state === 'error') {
    return <p className="login-error">{error}</p>
  }

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>
          {filtered.length} of {agents.length} agent{agents.length === 1 ? '' : 's'}
          {source && (
            <span className="role-pill" style={{ marginLeft: 10, textTransform: 'none' }}>
              {source === 'live' ? 'Live' : 'Manual sheet'}
            </span>
          )}
        </h2>
        <div className="toolbar-actions">
          <input
            className="search-input"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by name or IP..."
          />
          <button className="btn-outline" onClick={load} title="Refresh"><IconRefresh width={14} height={14} /> Refresh</button>
        </div>
      </div>

      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>IP</th>
              <th>Status</th>
              {extraColumns.map((c) => <th key={c}>{c}</th>)}
            </tr>
          </thead>
          <tbody>
            {filtered.map((a) => (
              <tr key={a.id}>
                <td className="mono muted">{a.id}</td>
                <td className="mono">{a.name || <span className="muted">&mdash;</span>}</td>
                <td className="mono">{a.ip}</td>
                <td>
                  <span className={`case-status ${STATUS_CLASS[a.status] || 'case-status-closed'}`}>
                    {a.status}
                  </span>
                </td>
                {extraColumns.map((c) => <td key={c} className="mono muted">{String(a.raw?.[c] ?? '')}</td>)}
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={4 + extraColumns.length}>
                  <EmptyState
                    icon={IconAssets}
                    title={agents.length === 0 ? 'No agents registered' : 'No matching agents'}
                    subtitle={agents.length === 0 ? 'No agents are registered in Wazuh yet.' : 'Try a different name or IP filter.'}
                  />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

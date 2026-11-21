import { useEffect, useState } from 'react'
import { getWazuhLogs, runWazuhDiagnosticQuery } from '../api.js'
import { SkeletonRows } from './Skeleton.jsx'
import EmptyState from './EmptyState.jsx'
import { IconBug } from './icons.jsx'
import { useToast } from '../ToastContext.jsx'

export default function WazuhDiagnostics() {
  const [logs, setLogs] = useState(null)
  const [nodeId, setNodeId] = useState('')
  const [level, setLevel] = useState('')
  const [search, setSearch] = useState('')
  const { showToast } = useToast()

  const [target, setTarget] = useState('manager')
  const [path, setPath] = useState('/manager/info')
  const [result, setResult] = useState(null)
  const [running, setRunning] = useState(false)

  const loadLogs = () => {
    setLogs(null)
    getWazuhLogs({ nodeId, level, search }).then((r) => setLogs(r.logs)).catch((e) => {
      showToast(e.message)
      setLogs([])
    })
  }

  useEffect(() => {
    loadLogs()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const handleRunQuery = async (e) => {
    e.preventDefault()
    setRunning(true)
    setResult(null)
    try {
      const r = await runWazuhDiagnosticQuery(target, path)
      setResult(r)
    } catch (err) {
      showToast(err.message)
    } finally {
      setRunning(false)
    }
  }

  const loading = logs === null

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>Wazuh Diagnostics</h2>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <h3 style={{ margin: '0 0 10px' }}>Manager logs</h3>
        <p className="muted" style={{ marginTop: 0, fontSize: 12 }}>
          Pulled live from the manager's own REST API (ossec.log entries) — never direct file or SSH access.
        </p>
        <form onSubmit={(e) => { e.preventDefault(); loadLogs() }} className="user-form" style={{ flexWrap: 'wrap', marginBottom: 14 }}>
          <input aria-label="Cluster node id" value={nodeId} onChange={(e) => setNodeId(e.target.value)} placeholder="Node id (optional, master used by default)" style={{ flex: '1 1 40%' }} />
          <select aria-label="Log level" value={level} onChange={(e) => setLevel(e.target.value)} style={{ flex: '0 1 140px' }}>
            <option value="">Any level</option>
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="error">error</option>
            <option value="critical">critical</option>
          </select>
          <input aria-label="Search log text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search text" style={{ flex: '1 1 30%' }} />
          <button type="submit" className="btn-outline">Refresh</button>
        </form>
        <div className="table-card">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Level</th>
                <th>Tag</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {loading && <SkeletonRows rows={6} columns={4} />}
              {!loading && logs.map((l, i) => (
                <tr key={i}>
                  <td className="mono muted">{l.timestamp}</td>
                  <td className="mono">{l.level}</td>
                  <td className="mono">{l.tag}</td>
                  <td className="muted">{l.description}</td>
                </tr>
              ))}
              {!loading && logs.length === 0 && (
                <tr>
                  <td colSpan={4}>
                    <EmptyState icon={IconBug} title="No log entries" subtitle="Nothing matched the current filters, or the manager hasn't logged anything recently." />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <h3 style={{ margin: '0 0 10px' }}>Read-only API console</h3>
        <p className="muted" style={{ marginTop: 0, fontSize: 12 }}>
          Runs a GET-only request against the already-connected Manager or Indexer API for a quick
          problem checkup — every run is recorded in the audit log.
        </p>
        <form onSubmit={handleRunQuery} className="user-form" style={{ flexWrap: 'wrap' }}>
          <select aria-label="Diagnostic target" value={target} onChange={(e) => setTarget(e.target.value)} style={{ flex: '0 1 140px' }}>
            <option value="manager">Manager</option>
            <option value="indexer">Indexer</option>
          </select>
          <input aria-label="API path" value={path} onChange={(e) => setPath(e.target.value)} placeholder="/manager/info" style={{ flex: '1 1 50%' }} />
          <button type="submit" className="ask" disabled={running}>{running ? 'Running...' : 'Run'}</button>
        </form>
        {result && (
          <pre className="mono" style={{ marginTop: 14, maxHeight: 360, overflow: 'auto', background: 'var(--bg-surface-3)', padding: 12, borderRadius: 10, fontSize: 12 }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        )}
      </div>
    </div>
  )
}

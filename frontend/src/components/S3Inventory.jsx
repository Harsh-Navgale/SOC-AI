import { useEffect, useMemo, useState } from 'react'
import { getAWSStatus, clearAWSCredentials, getS3Inventory } from '../api.js'
import { useAuth } from '../AuthContext.jsx'
import { useToast } from '../ToastContext.jsx'
import ConnectAWSForm from './ConnectAWSForm.jsx'
import { SkeletonRows } from './Skeleton.jsx'
import EmptyState from './EmptyState.jsx'
import { IconBucket, IconRefresh, IconDisconnect, IconDownload } from './icons.jsx'
import { toCsv, downloadCsv } from '../lib/csv.js'

export default function S3Inventory() {
  const { isAdmin } = useAuth()
  const { showToast } = useToast()
  const [state, setState] = useState('loading')
  const [error, setError] = useState(null)
  const [records, setRecords] = useState([])
  const [search, setSearch] = useState('')
  const [awsStatus, setAwsStatus] = useState(null)

  const load = async () => {
    setState('loading')
    setError(null)
    try {
      const status = await getAWSStatus()
      setAwsStatus(status)
      const result = await getS3Inventory()
      setRecords(result.records)
      setState('ready')
    } catch (err) {
      const msg = err.message || ''
      setError(msg)
      if (msg.includes('AWS session')) setState('need_aws')
      else if (msg.includes('S3_INVENTORY_BUCKET')) setState('need_s3_config')
      else setState('error')
    }
  }

  const handleDisconnect = async () => {
    try {
      await clearAWSCredentials()
      load()
    } catch (err) {
      showToast(err.message)
    }
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const columns = useMemo(() => {
    // Union of every field across all records (not just the first row) — a JSON-format
    // export could have rows with slightly different keys, and none should be dropped.
    const keys = new Set()
    for (const r of records) {
      for (const key of Object.keys(r.raw || {})) {
        if (key.toLowerCase() !== 'hostname') keys.add(key)
      }
    }
    return [...keys]
  }, [records])

  const undetectedCount = useMemo(() => records.filter((r) => !r.hostname).length, [records])

  const filtered = useMemo(() => {
    if (!search.trim()) return records
    const q = search.trim().toLowerCase()
    return records.filter((r) => (r.hostname || '').toLowerCase().includes(q))
  }, [records, search])

  const handleExport = () => {
    const csvColumns = [
      { label: 'Hostname', value: (r) => r.hostname || '' },
      ...columns.map((c) => ({ label: c, value: (r) => r.raw?.[c] ?? '' })),
    ]
    downloadCsv(`s3-inventory-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(filtered, csvColumns))
  }

  if (state === 'loading') {
    return (
      <div className="table-card">
        <table>
          <thead><tr><th>Hostname</th></tr></thead>
          <tbody><SkeletonRows rows={6} columns={1} /></tbody>
        </table>
      </div>
    )
  }

  if (state === 'need_aws') {
    return isAdmin ? (
      <ConnectAWSForm onConnected={load} />
    ) : (
      <p className="muted">AWS isn't connected yet. Ask an admin to connect it (from this page or Asset Coverage).</p>
    )
  }

  if (state === 'need_s3_config') {
    return (
      <p className="login-error">
        S3_INVENTORY_BUCKET isn't set in .env yet. An admin needs to configure the bucket/prefix
        before this page can browse it.
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
          {filtered.length} of {records.length} record{records.length === 1 ? '' : 's'}
          {undetectedCount > 0 && (
            <span className="role-pill" style={{ marginLeft: 10, textTransform: 'none', color: 'var(--warning)', borderColor: 'var(--warning)' }}>
              {undetectedCount} without a detected hostname column
            </span>
          )}
        </h2>
        <div className="toolbar-actions">
          {awsStatus?.expires_at && (
            <span className="muted mono" style={{ fontSize: 11 }}>
              AWS session expires {awsStatus.expires_at}
            </span>
          )}
          <input
            className="search-input"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by hostname..."
          />
          <button className="btn-outline" onClick={load} title="Refresh"><IconRefresh width={14} height={14} /> Refresh</button>
          <button className="btn-outline" onClick={handleExport} title="Export CSV"><IconDownload width={14} height={14} /> Export CSV</button>
          {isAdmin && (
            <button className="btn-outline" onClick={handleDisconnect} title="Disconnect AWS"><IconDisconnect width={14} height={14} /> Disconnect</button>
          )}
        </div>
      </div>

      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              {columns.map((c) => <th key={c}>{c}</th>)}
            </tr>
          </thead>
          <tbody>
            {filtered.map((r, i) => (
              <tr key={i}>
                <td className="mono">
                  {r.hostname || <span className="muted" title="No recognized hostname column in this row">&mdash;</span>}
                </td>
                {columns.map((c) => <td key={c} className="mono muted">{String(r.raw?.[c] ?? '')}</td>)}
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={columns.length + 1}>
                  <EmptyState
                    icon={IconBucket}
                    title={records.length === 0 ? 'No inventory records' : 'No matching records'}
                    subtitle={records.length === 0 ? 'Nothing found in the latest S3 export.' : 'Try a different hostname filter.'}
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

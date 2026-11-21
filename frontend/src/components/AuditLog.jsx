import { useEffect, useState } from 'react'
import { getAuditLog } from '../api.js'
import { SkeletonRows } from './Skeleton.jsx'
import EmptyState from './EmptyState.jsx'
import { IconActivity } from './icons.jsx'
import { useToast } from '../ToastContext.jsx'

function detailsText(entry) {
  const details = entry.details || {}
  const parts = Object.entries(details).map(([k, v]) => `${k}: ${v}`)
  return parts.join(', ') || <span className="muted">&mdash;</span>
}

export default function AuditLog() {
  const [entries, setEntries] = useState(null)
  const { showToast } = useToast()

  useEffect(() => {
    getAuditLog().then(setEntries).catch((e) => {
      showToast(e.message)
      setEntries([])
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const loading = entries === null

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>{loading ? 'Loading activity...' : `${entries.length} recent event${entries.length === 1 ? '' : 's'}`}</h2>
      </div>
      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {loading && <SkeletonRows rows={6} columns={5} />}
            {!loading && entries.map((e) => (
              <tr key={e._id}>
                <td className="mono muted">{e.timestamp}</td>
                <td>{e.actor}</td>
                <td className="mono">{e.action}</td>
                <td className="mono">{e.target || <span className="muted">&mdash;</span>}</td>
                <td className="muted">{detailsText(e)}</td>
              </tr>
            ))}
            {!loading && entries.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <EmptyState
                    icon={IconActivity}
                    title="No activity yet"
                    subtitle="Admin actions — user changes, credential updates, case closures — will show up here."
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

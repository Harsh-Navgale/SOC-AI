import { useEffect, useState } from 'react'
import { getInvestigationQueue, updateIncident, deleteIncident, requeueIncident, getIncidents } from '../api.js'
import { SkeletonRows } from './Skeleton.jsx'
import EmptyState from './EmptyState.jsx'
import { IconCases, IconTrash, IconArrowToTop, IconArrowToBottom } from './icons.jsx'
import { useToast } from '../ToastContext.jsx'
import { useAuth } from '../AuthContext.jsx'
import { useLiveEvents } from '../LiveConnectionContext.jsx'
import RiskBadge from './RiskBadge.jsx'

export default function AIQueue() {
  const [items, setItems] = useState(null)
  const [busyId, setBusyId] = useState(null)
  const { isAdmin } = useAuth()
  const [searchInput, setSearchInput] = useState('')
  const [reviewedResults, setReviewedResults] = useState(null)
  const [searching, setSearching] = useState(false)
  const { showToast } = useToast()

  const load = () => {
    return getInvestigationQueue()
      .then(({ items: i }) => setItems(i))
      .catch((err) => {
        setItems((prev) => {
          if (prev === null) showToast(err.message)
          return prev ?? []
        })
      })
  }

  useEffect(() => {
    load()
    const interval = setInterval(load, 10000)
    return () => clearInterval(interval)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useLiveEvents('incidents_changed', load)

  useEffect(() => {
    const t = setTimeout(() => {
      const term = searchInput.trim()
      if (!term) {
        setReviewedResults(null)
        return
      }
      setSearching(true)
      getIncidents({ limit: 10, reviewed: 'true', search: term })
        .then(({ items: i }) => setReviewedResults(i))
        .catch((err) => showToast(err.message))
        .finally(() => setSearching(false))
    }, 350)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchInput])

  const setPriority = async (id, priority) => {
    setBusyId(id)
    try {
      await updateIncident(id, { priority })
      await load()
    } catch (err) {
      showToast(err.message)
    } finally {
      setBusyId(null)
    }
  }

  const bumpToTop = (id) => {
    const maxPriority = Math.max(0, ...items.map((i) => i.priority || 0))
    setPriority(id, maxPriority + 1)
  }

  const sendToBack = (id) => {
    const minPriority = Math.min(0, ...items.map((i) => i.priority || 0))
    setPriority(id, minPriority - 1)
  }

  const handleRemove = async (id) => {
    if (!window.confirm("Remove this case from the queue? This deletes the case — it can't be undone.")) return
    setBusyId(id)
    try {
      await deleteIncident(id)
      await load()
      showToast('Case removed from the queue.', 'success')
    } catch (err) {
      showToast(err.message)
    } finally {
      setBusyId(null)
    }
  }

  const handleRequeue = async (id) => {
    setBusyId(id)
    try {
      await requeueIncident(id)
      setReviewedResults((prev) => prev?.filter((i) => i._id !== id) ?? null)
      await load()
      showToast('Added to the queue for re-investigation.', 'success')
    } catch (err) {
      showToast(err.message)
    } finally {
      setBusyId(null)
    }
  }

  const loading = items === null

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>{loading ? 'Loading queue...' : `${items.length} case${items.length === 1 ? '' : 's'} in queue`}</h2>
      </div>
      <p className="muted" style={{ margin: '0 0 16px' }}>
        This is the exact order the AI investigates cases in — highest priority first, then
        oldest first. Investigations run one at a time, so reordering here changes what gets
        looked at next.
      </p>

      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th style={{ width: 40 }}>#</th>
              <th>Priority</th>
              <th>Risk</th>
              <th>Severity</th>
              <th>Source IP</th>
              <th>Rule</th>
              <th>First Seen</th>
              <th style={{ width: 110 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && <SkeletonRows rows={5} columns={8} />}
            {!loading && items.map((inc, idx) => (
              <tr key={inc._id} className={inc.severity === 'high' ? 'sev-row-high' : ''}>
                <td className="mono muted">{idx + 1}</td>
                <td>
                  <input
                    type="number"
                    className="queue-priority-input"
                    defaultValue={inc.priority || 0}
                    disabled={busyId === inc._id}
                    onBlur={(e) => {
                      const next = parseInt(e.target.value, 10) || 0
                      if (next !== (inc.priority || 0)) setPriority(inc._id, next)
                    }}
                  />
                </td>
                <td><RiskBadge risk={inc.risk} /></td>
                <td>
                  <span className={`sev-dot ${inc.severity === 'high' ? 'high' : 'low'}`} />
                  <span className={inc.severity === 'high' ? 'severity-high' : 'severity-low'}>{inc.severity}</span>
                </td>
                <td className="mono">{inc.source_ip}</td>
                <td>{inc.rule_description} <span className="muted">&middot; {inc.alert_count} alert{inc.alert_count === 1 ? '' : 's'}</span></td>
                <td className="mono muted">{inc.first_seen_iso}</td>
                <td onClick={(e) => e.stopPropagation()}>
                  <div style={{ display: 'flex', gap: 4 }}>
                    <button type="button" className="icon-btn" disabled={busyId === inc._id} onClick={() => bumpToTop(inc._id)} title="Bump to top of queue">
                      <IconArrowToTop width={14} height={14} />
                    </button>
                    <button type="button" className="icon-btn" disabled={busyId === inc._id} onClick={() => sendToBack(inc._id)} title="Send to back of queue">
                      <IconArrowToBottom width={14} height={14} />
                    </button>
                    {isAdmin && (
                      <button className="icon-btn" disabled={busyId === inc._id} onClick={() => handleRemove(inc._id)} title="Remove from queue (deletes the case)">
                        <IconTrash width={14} height={14} />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={8}>
                  <EmptyState
                    icon={IconCases}
                    title="Queue is empty"
                    subtitle="Every case has been AI-reviewed. New cases from the correlator will show up here."
                  />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <h3 style={{ marginTop: 28 }}>Add a reviewed case back to the queue</h3>
      <p className="muted" style={{ margin: '4px 0 12px' }}>
        Search already-investigated incidents to send one back for re-investigation — useful if
        new context (threat intel, an asset update) has come in since the AI last looked at it.
      </p>
      <input
        className="search-input"
        style={{ maxWidth: 360 }}
        value={searchInput}
        onChange={(e) => setSearchInput(e.target.value)}
        placeholder="Search reviewed incidents by IP or rule..."
      />
      {searching && <p className="muted" style={{ marginTop: 8 }}>Searching...</p>}
      {reviewedResults && reviewedResults.length === 0 && !searching && (
        <p className="muted" style={{ marginTop: 8 }}>No reviewed incidents match.</p>
      )}
      {reviewedResults && reviewedResults.length > 0 && (
        <ul className="notes-list" style={{ marginTop: 8 }}>
          {reviewedResults.map((inc) => (
            <li key={inc._id}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                <div>
                  <span className="mono">{inc.source_ip}</span>
                  <span className="muted"> &middot; {inc.rule_description} &middot; {inc.last_seen_iso}</span>
                </div>
                <button type="button" className="btn-outline" disabled={busyId === inc._id} onClick={() => handleRequeue(inc._id)}>
                  Add to queue
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

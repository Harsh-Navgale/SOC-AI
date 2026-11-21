import { useState } from 'react'
import { deleteAlert } from '../api.js'
import { useToast } from '../ToastContext.jsx'
import { useAuth } from '../AuthContext.jsx'
import { IconClose, IconCopy, IconTrash } from './icons.jsx'

// Top-level Wazuh alert keys rendered in this fixed order when present, so the shape of the
// view stays consistent across very different alert types (an sshd alert has no "syscheck",
// a FIM alert has no "data.srcip", a Windows Sysmon alert nests everything under
// "data.win.eventdata" instead) — whatever the rule/decoder actually populated just shows up,
// nothing else needs to change. Anything not in this list still shows, alphabetically, after it.
const SECTION_ORDER = ['rule', 'agent', 'data', 'syscheck', 'decoder', 'GeoLocation', 'manager', 'cluster', 'input', 'location']

// Fields the modal already surfaces elsewhere (header badges, the raw-log block, app-added
// bookkeeping) — kept out of the generic section list so they aren't shown twice.
const HANDLED_ELSEWHERE = new Set(['_id', 'full_log', 'timestamp', 'correlated', 'excluded', 'excluded_by_rule'])

function JsonValue({ value }) {
  if (value === null || value === undefined || value === '') return <span className="muted">&mdash;</span>

  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="muted">[]</span>
    const allPrimitive = value.every((v) => v === null || typeof v !== 'object')
    if (allPrimitive) return <span className="mono">{value.join(', ')}</span>
    return (
      <ul className="json-tree-list">
        {value.map((v, i) => (
          <li key={i}><JsonValue value={v} /></li>
        ))}
      </ul>
    )
  }

  if (typeof value === 'object') return <JsonObject obj={value} />

  return <span className="mono">{String(value)}</span>
}

function JsonObject({ obj }) {
  const entries = Object.entries(obj).filter(([, v]) => v !== null && v !== undefined && v !== '')
  if (entries.length === 0) return <span className="muted">&mdash;</span>
  return (
    <table className="json-tree-table">
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k}>
            <td className="json-tree-key">{k}</td>
            <td className="json-tree-value"><JsonValue value={v} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default function AlertDetail({ alert, onClose, onPromote, promoting, onDeleted }) {
  const [copied, setCopied] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const { showToast } = useToast()
  const { isAdmin } = useAuth()

  if (!alert) return null

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(alert, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const handleDelete = async () => {
    if (!window.confirm("Delete this alert? This can't be undone.")) return
    setDeleting(true)
    try {
      await deleteAlert(alert._id)
      showToast('Alert deleted.', 'success')
      onDeleted?.(alert._id)
      onClose()
    } catch (err) {
      showToast(err.message)
    } finally {
      setDeleting(false)
    }
  }

  const remainingKeys = Object.keys(alert).filter((k) => !HANDLED_ELSEWHERE.has(k))
  const orderedKeys = [
    ...SECTION_ORDER.filter((k) => remainingKeys.includes(k)),
    ...remainingKeys.filter((k) => !SECTION_ORDER.includes(k)).sort(),
  ]

  const level = alert.rule?.level ?? 0

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal modal-wide"
        role="dialog"
        aria-modal="true"
        aria-labelledby="alert-modal-title"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => e.key === 'Escape' && onClose()}
      >
        <div className="modal-header">
          <h2 id="alert-modal-title">{alert.rule?.description || 'Alert'}</h2>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <button className="msg-copy" onClick={handleCopy} title="Copy full alert JSON">
              {copied ? 'Copied' : <IconCopy width={13} height={13} />}
            </button>
            {isAdmin && (
              <button className="icon-btn" onClick={handleDelete} disabled={deleting} title="Delete alert">
                <IconTrash width={15} height={15} />
              </button>
            )}
            <button className="modal-close" onClick={onClose}><IconClose width={16} height={16} /></button>
          </div>
        </div>

        <div className="incident-meta">
          <span className={`sev-dot ${level >= 10 ? 'high' : 'low'}`} />
          <span className={level >= 10 ? 'severity-high' : 'severity-low'}>level {level}</span>
          {alert.agent?.name && <span className="mono">{alert.agent.name}{alert.agent.ip ? ` (${alert.agent.ip})` : ''}</span>}
          <span className="mono muted">{alert.timestamp}</span>
          {alert.excluded && (
            <span className="ti-pill ti-pill--warn" title={`Excluded by rule: ${alert.excluded_by_rule || ''}`}>Excluded</span>
          )}
          {alert.correlated && !alert.excluded && <span className="muted">In a case</span>}
        </div>

        {onPromote && !(alert.correlated && !alert.excluded) && (
          <div className="incident-controls">
            <button onClick={() => onPromote(alert._id)} disabled={promoting} className="ask">
              {promoting ? 'Promoting...' : alert.excluded ? 'Promote anyway' : 'Promote to case'}
            </button>
          </div>
        )}

        {alert.full_log && (
          <>
            <h3>Raw log line</h3>
            <pre className="full-log-line">{alert.full_log}</pre>
          </>
        )}

        <h3>Full alert</h3>
        <p className="muted" style={{ margin: '0 0 12px' }}>
          Wazuh alerts carry different fields depending on the rule and decoder that fired — this
          shows exactly what came through on this one, section by section.
        </p>
        {orderedKeys.map((key) => (
          <details key={key} className="alert-section" open={key === 'rule' || key === 'data'}>
            <summary>{key}</summary>
            <div className="alert-section-body">
              <JsonValue value={alert[key]} />
            </div>
          </details>
        ))}
      </div>
    </div>
  )
}

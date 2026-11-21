import { useEffect, useState } from 'react'
import { getIncident, updateIncident, addNote, closeIncident, investigateIncident, getRelatedIncidents, deleteIncident } from '../api.js'
import { useToast } from '../ToastContext.jsx'
import { useAuth } from '../AuthContext.jsx'
import { useDebugMode } from '../useDebugMode.js'
import { SkeletonCard } from './Skeleton.jsx'
import { IconClose, IconCopy, IconTrash, IconDownload } from './icons.jsx'
import { ThreatIntelCompact } from './threatIntelDisplay.jsx'
import RiskBadge from './RiskBadge.jsx'

function formatEnumLabel(value) {
  if (!value) return null
  const spaced = value.replace(/_/g, ' ')
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}

function verdictPillClass(verdict) {
  if (verdict === 'true_positive') return 'ti-pill ti-pill--bad'
  if (verdict === 'false_positive' || verdict === 'benign_positive') return 'ti-pill ti-pill--good'
  if (verdict === 'needs_review') return 'ti-pill ti-pill--warn'
  return 'ti-pill'
}

function investigationToText(investigation) {
  const lines = []
  if (investigation.verdict) lines.push(`Verdict: ${formatEnumLabel(investigation.verdict)}`)
  if (investigation.severity) lines.push(`Severity: ${investigation.severity}`)
  if (investigation.priority) lines.push(`Priority: ${investigation.priority}`)
  if (investigation.confidence) lines.push(`Confidence: ${investigation.confidence}`)
  if (investigation.origin) lines.push(`Origin: ${formatEnumLabel(investigation.origin)}`)
  if (investigation.category) lines.push(`Category: ${formatEnumLabel(investigation.category)}`)
  if (investigation.owning_team) lines.push(`Owning team: ${investigation.owning_team}`)
  if (investigation.escalate) lines.push('Escalate: yes')
  if (investigation.summary) lines.push('', investigation.summary)
  if (investigation.probable_cause) lines.push('', `Probable cause: ${investigation.probable_cause}`)
  if (investigation.impact) lines.push('', `Impact: ${investigation.impact}`)
  if (investigation.recommended_actions?.length > 0) {
    lines.push('', 'Recommended actions:', ...investigation.recommended_actions.map((a) => `- ${a}`))
  }
  return lines.join('\n')
}

const DISPOSITION_OPTIONS = [
  { value: 'true_positive', label: 'True positive' },
  { value: 'false_positive', label: 'False positive' },
  { value: 'benign_positive', label: 'Benign positive' },
]

export default function IncidentDetail({ incidentId, onClose }) {
  const [incident, setIncident] = useState(null)
  const [noteText, setNoteText] = useState('')
  const [resolution, setResolution] = useState('')
  const [disposition, setDisposition] = useState('')
  const [assignedTo, setAssignedTo] = useState('')
  const [investigating, setInvestigating] = useState(false)
  const [reportCopied, setReportCopied] = useState(false)
  const [related, setRelated] = useState(null)
  const [deleting, setDeleting] = useState(false)
  const { showToast } = useToast()
  const { isAdmin } = useAuth()
  const debugMode = useDebugMode()

  const handleCopyReport = () => {
    navigator.clipboard.writeText(investigationToText(incident.investigation))
    setReportCopied(true)
    setTimeout(() => setReportCopied(false), 1500)
  }

  const load = () => {
    getIncident(incidentId)
      .then((data) => {
        setIncident(data)
        setAssignedTo(data.assigned_to || '')
      })
      .catch((e) => showToast(e.message))
  }

  useEffect(() => {
    load()
    setRelated(null)
    getRelatedIncidents(incidentId).then(setRelated).catch(() => setRelated([]))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidentId])

  const handleStatusChange = async (case_status) => {
    try {
      const updated = await updateIncident(incidentId, { case_status })
      setIncident(updated)
    } catch (e) {
      showToast(e.message)
    }
  }

  const handleAssign = async () => {
    try {
      const updated = await updateIncident(incidentId, { assigned_to: assignedTo || null })
      setIncident(updated)
    } catch (e) {
      showToast(e.message)
    }
  }

  const handleAddNote = async (e) => {
    e.preventDefault()
    if (!noteText.trim()) return
    try {
      await addNote(incidentId, noteText)
      setNoteText('')
      load()
    } catch (e) {
      showToast(e.message)
    }
  }

  const handleClose = async (e) => {
    e.preventDefault()
    if (!resolution.trim() || !disposition) return
    try {
      await closeIncident(incidentId, resolution, disposition)
      setResolution('')
      setDisposition('')
      showToast('Case closed and resolution added to the knowledge base.', 'success')
      load()
    } catch (e) {
      showToast(e.message)
    }
  }

  const handleInvestigate = async () => {
    setInvestigating(true)
    try {
      const report = await investigateIncident(incidentId)
      setIncident((prev) => ({ ...prev, investigation: report }))
    } catch (e) {
      showToast(e.message)
    } finally {
      setInvestigating(false)
    }
  }

  const handleDelete = async () => {
    if (!window.confirm('Delete this case? This can\'t be undone.')) return
    setDeleting(true)
    try {
      await deleteIncident(incidentId)
      showToast('Case deleted.', 'success')
      onClose()
    } catch (e) {
      showToast(e.message)
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="incident-modal-title"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => e.key === 'Escape' && onClose()}
      >
        <div className="modal-header">
          <h2 id="incident-modal-title">{incident ? `${incident.rule_description} — ${incident.source_ip}` : 'Loading...'}</h2>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            {incident && (
              <button className="icon-btn" onClick={() => window.print()} title="Export report (print to PDF)">
                <IconDownload width={15} height={15} />
              </button>
            )}
            {isAdmin && incident && (
              <button className="icon-btn" onClick={handleDelete} disabled={deleting} title="Delete case">
                <IconTrash width={15} height={15} />
              </button>
            )}
            <button className="modal-close" onClick={onClose}><IconClose width={16} height={16} /></button>
          </div>
        </div>

        {!incident ? (
          <SkeletonCard lines={4} />
        ) : (
          <>
            <div className="incident-meta">
              <RiskBadge risk={incident.risk} />
              <span className={`case-status case-status-${incident.case_status || 'open'}`}>{incident.case_status || 'open'}</span>
              <span className={incident.severity === 'high' ? 'severity-high' : 'severity-low'}>{incident.severity} severity</span>
              <span>{incident.alert_count} alerts</span>
              <span>MITRE: {(incident.mitre_tactics || []).join(', ') || 'none'}</span>
              {incident.asset?.hostname && <span>Asset: {incident.asset.hostname}</span>}
              {incident.org_context?.instance_name && <span title="AI-extracted from org docs, unconfirmed">Instance: {incident.org_context.instance_name}</span>}
              {incident.org_context?.client_name && <span title="AI-extracted from org docs, unconfirmed">Client: {incident.org_context.client_name}</span>}
            </div>

            {incident.full_logs?.length > 0 && (
              <details className="full-log-details">
                <summary className="muted">
                  Raw log line{incident.full_logs.length === 1 ? '' : `s (${incident.full_logs.length} distinct)`}
                </summary>
                {incident.full_logs.map((line, i) => (
                  <pre className="full-log-line" key={i}>{line}</pre>
                ))}
              </details>
            )}

            {Object.entries(incident.unique_values || {}).some(([field]) => field !== 'full_log') && (
              <details className="full-log-details">
                <summary className="muted">Distinct values seen across this case's alerts</summary>
                <ul className="notes-list">
                  {Object.entries(incident.unique_values)
                    .filter(([field]) => field !== 'full_log')
                    .sort(([a], [b]) => a.localeCompare(b))
                    .map(([field, values]) => (
                      <li key={field}>
                        <span className="mono">{field}</span>
                        <span className="muted"> &middot; {values.join(', ')}</span>
                      </li>
                    ))}
                </ul>
              </details>
            )}

            <div className="incident-controls">
              <label>
                Status
                <select
                  value={incident.case_status === 'closed' ? 'closed' : (incident.case_status || 'open')}
                  onChange={(e) => handleStatusChange(e.target.value)}
                  disabled={incident.case_status === 'closed'}
                >
                  <option value="open">open</option>
                  <option value="investigating">investigating</option>
                  {/* Closing happens only through the "Close case" form below, which requires a
                      confirmed disposition — this dropdown can select into "closed" but not out
                      of it, since that's the only way the backend's required-disposition
                      guarantee holds. */}
                  {incident.case_status === 'closed' && <option value="closed">closed</option>}
                </select>
              </label>
              <label>
                Assigned to
                <input
                  value={assignedTo}
                  onChange={(e) => setAssignedTo(e.target.value)}
                  onBlur={handleAssign}
                  placeholder="unassigned"
                />
              </label>
              <button onClick={handleInvestigate} disabled={investigating} className="ask">
                {investigating ? 'Investigating...' : 'Investigate with AI'}
              </button>
            </div>

            <h3>Threat intelligence</h3>
            <ThreatIntelCompact result={incident.threat_intel} loading={false} indicator={incident.threat_intel_ip} />

            {incident.investigation && (
              <div className="answer-box investigation-report">
                <div className="investigation-report-header">
                  <button className="msg-copy" onClick={handleCopyReport} title="Copy report">
                    {reportCopied ? 'Copied' : <IconCopy width={13} height={13} />}
                  </button>
                </div>
                {incident.investigation.escalate === true && (
                  <div className="escalate-banner">⚠ Escalate — needs immediate attention</div>
                )}
                <div className="investigation-badges">
                  {incident.investigation.verdict && (
                    <span className={verdictPillClass(incident.investigation.verdict)} title="AI verdict — unconfirmed by an analyst">
                      AI verdict: {formatEnumLabel(incident.investigation.verdict)}
                    </span>
                  )}
                  {incident.investigation.rule_health && (
                    <span className="ti-pill ti-pill--outline" title="The AI's own opinion on the triggering rule itself, not a finding about this alert — unconfirmed">
                      Rule health: {formatEnumLabel(incident.investigation.rule_health)}
                    </span>
                  )}
                  {incident.investigation.severity && <span className="badge">Severity: {incident.investigation.severity}</span>}
                  {incident.investigation.priority && <span className="badge">Priority: {incident.investigation.priority}</span>}
                  {incident.investigation.confidence && <span className="badge">Confidence: {incident.investigation.confidence}</span>}
                  {incident.investigation.origin && <span className="badge">Origin: {formatEnumLabel(incident.investigation.origin)}</span>}
                  {incident.investigation.category && <span className="badge">Category: {formatEnumLabel(incident.investigation.category)}</span>}
                  {incident.investigation.owning_team && <span className="badge">Team: {incident.investigation.owning_team}</span>}
                </div>
                {incident.investigation.rule_health_reasoning && (
                  <p className="muted" style={{ fontSize: 12 }}>
                    <strong>Rule health (AI, unconfirmed):</strong> {incident.investigation.rule_health_reasoning}
                  </p>
                )}
                {incident.investigation.summary && <p>{incident.investigation.summary}</p>}
                {incident.investigation.probable_cause && (
                  <p>
                    <strong>Probable cause:</strong> {incident.investigation.probable_cause}
                  </p>
                )}
                {incident.investigation.impact && (
                  <p>
                    <strong>Impact:</strong> {incident.investigation.impact}
                  </p>
                )}
                {incident.investigation.recommended_actions?.length > 0 && (
                  <>
                    <strong>Recommended actions:</strong>
                    <ul>
                      {incident.investigation.recommended_actions.map((a, i) => (
                        <li key={i}>{a}</li>
                      ))}
                    </ul>
                  </>
                )}
                {isAdmin && debugMode && (
                  <details className="full-log-details" style={{ marginTop: 12 }}>
                    <summary className="muted">Debug: raw prompt, model output &amp; token usage</summary>
                    <div className="stat-row" style={{ margin: '8px 0' }}>
                      <div className="stat-tile">
                        <div className="stat-value">{incident.investigation.model_used || '—'}</div>
                        <div className="stat-label">Model</div>
                      </div>
                      <div className="stat-tile">
                        <div className="stat-value">{incident.investigation.prompt_tokens ?? '—'}</div>
                        <div className="stat-label">Prompt tokens</div>
                      </div>
                      <div className="stat-tile">
                        <div className="stat-value">{incident.investigation.completion_tokens ?? '—'}</div>
                        <div className="stat-label">Completion tokens</div>
                      </div>
                      <div className="stat-tile">
                        <div className="stat-value">
                          {incident.investigation.estimated_cost != null ? `$${incident.investigation.estimated_cost.toFixed(6)}` : '—'}
                        </div>
                        <div className="stat-label">Est. cost</div>
                      </div>
                      <div className="stat-tile">
                        <div className="stat-value">{incident.investigation.parse_ok === false ? 'No' : 'Yes'}</div>
                        <div className="stat-label">Parsed OK</div>
                      </div>
                    </div>
                    <p className="muted" style={{ margin: '8px 0 4px' }}>Prompt sent to the model</p>
                    <pre className="full-log-line">{incident.investigation.prompt || '(not recorded)'}</pre>
                    <p className="muted" style={{ margin: '8px 0 4px' }}>Raw model response</p>
                    <pre className="full-log-line">{incident.investigation.raw || '(not recorded)'}</pre>
                  </details>
                )}
              </div>
            )}

            <h3>Prior activity for this IP</h3>
            {related === null ? (
              <p className="muted">Checking history for this source IP...</p>
            ) : related.length === 0 ? (
              <p className="muted">No other cases have been opened for this source IP.</p>
            ) : (
              <ul className="notes-list">
                {related.map((r) => (
                  <li key={r._id}>
                    <div>
                      <span className={`case-status case-status-${r.case_status || 'open'}`}>{r.case_status || 'open'}</span>
                      {' '}
                      <span className={r.severity === 'high' ? 'severity-high' : 'severity-low'}>{r.severity}</span>
                      <span className="muted"> &middot; {r.alert_count} alert{r.alert_count === 1 ? '' : 's'} &middot; {r.last_seen_iso}</span>
                      {r.case_status === 'closed' && r.resolution && (
                        <div className="muted" style={{ marginTop: 4 }}>Resolved: {r.resolution}</div>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}

            <h3>Notes</h3>
            <ul className="notes-list">
              {(incident.notes || []).map((n, i) => (
                <li key={i}>
                  <div className="msg-avatar user-avatar">{(n.author || '?')[0].toUpperCase()}</div>
                  <div>
                    <strong>{n.author}</strong> <span className="muted">{n.created_at}</span>
                    <br />
                    {n.text}
                  </div>
                </li>
              ))}
              {(incident.notes || []).length === 0 && <li className="muted">No notes yet.</li>}
            </ul>
            <form onSubmit={handleAddNote} className="note-form">
              <input value={noteText} onChange={(e) => setNoteText(e.target.value)} placeholder="Add a note..." />
              <button type="submit">Add</button>
            </form>

            {incident.case_status !== 'closed' ? (
              <form onSubmit={handleClose} className="close-form">
                <h3>Close case</h3>
                <label>
                  Confirmed disposition
                  <select value={disposition} onChange={(e) => setDisposition(e.target.value)} required>
                    <option value="" disabled>Select one...</option>
                    {DISPOSITION_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>{opt.label}</option>
                    ))}
                  </select>
                </label>
                <textarea
                  value={resolution}
                  onChange={(e) => setResolution(e.target.value)}
                  placeholder="Resolution notes..."
                />
                <button type="submit" className="ask" disabled={!resolution.trim() || !disposition}>Close case</button>
              </form>
            ) : (
              <div className="resolution-box">
                <h3>Resolution</h3>
                {incident.disposition && (
                  <span className={verdictPillClass(incident.disposition)} title="Confirmed by an analyst at close time">
                    Confirmed disposition: {formatEnumLabel(incident.disposition)}
                  </span>
                )}
                <p>{incident.resolution}</p>
                <p className="muted">
                  Closed by {incident.closed_by} at {incident.closed_at}
                </p>
              </div>
            )}

            <div className="print-report">
              <h1>{incident.rule_description}</h1>
              <p className="print-meta">
                {incident.source_ip} &middot; {incident.severity} severity &middot; risk {incident.risk?.score}/100 ({incident.risk?.label}) &middot; case {incident.case_status || 'open'}
                {incident.asset?.hostname && <> &middot; asset {incident.asset.hostname}</>}
              </p>
              <p className="print-meta">
                {incident.alert_count} alert{incident.alert_count === 1 ? '' : 's'} &middot; first seen {incident.first_seen_iso} &middot; last seen {incident.last_seen_iso}
              </p>
              {incident.full_logs?.length > 0 && (
                <>
                  <h2>Raw log line{incident.full_logs.length === 1 ? '' : 's'}</h2>
                  {incident.full_logs.map((line, i) => <pre key={i}>{line}</pre>)}
                </>
              )}
              {incident.investigation && (
                <>
                  <h2>AI investigation</h2>
                  <p className="print-meta">
                    Verdict: {formatEnumLabel(incident.investigation.verdict) || '—'} &middot; Severity: {incident.investigation.severity || '—'} &middot; Confidence: {incident.investigation.confidence || '—'} &middot; Priority: {incident.investigation.priority || '—'}
                    {incident.investigation.escalate === true && <> &middot; ESCALATE</>}
                  </p>
                  <p className="print-meta">
                    Origin: {formatEnumLabel(incident.investigation.origin) || '—'} &middot; Category: {formatEnumLabel(incident.investigation.category) || '—'} &middot; Owning team: {incident.investigation.owning_team || '—'}
                  </p>
                  {incident.investigation.summary && <p>{incident.investigation.summary}</p>}
                  {incident.investigation.probable_cause && <p><strong>Probable cause:</strong> {incident.investigation.probable_cause}</p>}
                  {incident.investigation.impact && <p><strong>Impact:</strong> {incident.investigation.impact}</p>}
                  {incident.investigation.recommended_actions?.length > 0 && (
                    <>
                      <strong>Recommended actions:</strong>
                      <ul>
                        {incident.investigation.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}
                      </ul>
                    </>
                  )}
                </>
              )}
              <h2>Notes</h2>
              {(incident.notes || []).length === 0 && <p className="print-meta">No notes.</p>}
              <ul>
                {(incident.notes || []).map((n, i) => (
                  <li key={i}>{n.author} ({n.created_at}): {n.text}</li>
                ))}
              </ul>
              {incident.case_status === 'closed' && (
                <>
                  <h2>Resolution</h2>
                  {incident.disposition && <p className="print-meta">Confirmed disposition: {formatEnumLabel(incident.disposition)}</p>}
                  <p>{incident.resolution}</p>
                  <p className="print-meta">Closed by {incident.closed_by} at {incident.closed_at}</p>
                </>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

import { useEffect, useState } from 'react'
import { getIncidents, updateIncident, closeIncident, deleteIncidentsBulk } from '../api.js'
import { SkeletonRows } from './Skeleton.jsx'
import EmptyState from './EmptyState.jsx'
import { IconIncidents, IconDownload } from './icons.jsx'
import { useToast } from '../ToastContext.jsx'
import { useAuth } from '../AuthContext.jsx'
import { useLiveEvents } from '../LiveConnectionContext.jsx'
import { toCsv, downloadCsv } from '../lib/csv.js'
import RiskBadge from './RiskBadge.jsx'
import { SOURCES, sourceVerdict } from './threatIntelDisplay.jsx'

// One compact pill per row summarizing threat intel across all sources — the single worst
// verdict found (bad beats warn beats good), since a row has no space for four separate pills
// the way the incident detail page does.
function worstThreatVerdict(threatIntel) {
  const verdicts = SOURCES.map(({ key }) => sourceVerdict(key, threatIntel?.sources?.[key])).filter(Boolean)
  if (verdicts.length === 0) return null
  return verdicts.find((v) => v.level === 'bad') || verdicts.find((v) => v.level === 'warn') || verdicts[0]
}

const SEVERITY_OPTIONS = [
  { value: '', label: 'All severities' },
  { value: 'high', label: 'High' },
  { value: 'low', label: 'Low' },
]

const STATUS_OPTIONS = [
  { value: '', label: 'All statuses' },
  { value: 'open', label: 'Open' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'closed', label: 'Closed' },
]

const PAGE_SIZE = 50
const SAVED_VIEWS_KEY = 'soc_incident_saved_views'

function loadSavedViews() {
  try {
    return JSON.parse(localStorage.getItem(SAVED_VIEWS_KEY) || '[]')
  } catch {
    return []
  }
}

const CSV_COLUMNS = [
  { label: 'Risk Score', value: (i) => i.risk?.score ?? '' },
  { label: 'Risk Label', value: (i) => i.risk?.label ?? '' },
  { label: 'Severity', value: (i) => i.severity },
  { label: 'Source IP', value: (i) => i.source_ip },
  { label: 'Case Status', value: (i) => i.case_status || 'open' },
  { label: 'Assigned To', value: (i) => i.assigned_to || '' },
  { label: 'Alert Count', value: (i) => i.alert_count },
  { label: 'MITRE Tactics', value: (i) => (i.mitre_tactics || []).join('; ') },
  { label: 'Rule', value: (i) => i.rule_description || '' },
  { label: 'Asset', value: (i) => i.asset?.hostname || '' },
  { label: 'Client', value: (i) => i.org_context?.client_name || '' },
  { label: 'Instance', value: (i) => i.org_context?.instance_name || '' },
  { label: 'Last Seen', value: (i) => i.last_seen_iso },
]

export default function IncidentsList({ onSelect, reviewed = '', noun = 'case' }) {
  const [incidents, setIncidents] = useState(null)
  const [total, setTotal] = useState(0)
  const [limit, setLimit] = useState(PAGE_SIZE)
  const [loadingMore, setLoadingMore] = useState(false)
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [caseStatus, setCaseStatus] = useState('')
  const [campaignId, setCampaignId] = useState('')
  const [selected, setSelected] = useState(new Set())
  const [savedViews, setSavedViews] = useState(loadSavedViews)
  const [exporting, setExporting] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const { showToast } = useToast()
  const { isAdmin } = useAuth()

  useEffect(() => {
    const t = setTimeout(() => setSearch(searchInput.trim()), 350)
    return () => clearTimeout(t)
  }, [searchInput])

  // Filter changes start the list over at one page; only "Load more" grows `limit`.
  useEffect(() => {
    setLimit(PAGE_SIZE)
  }, [severity, caseStatus, search, campaignId])

  const load = (currentLimit = limit) => {
    return getIncidents({ limit: currentLimit, severity, caseStatus, search, reviewed, campaignId })
      .then(({ items, total: t }) => {
        setIncidents(items)
        setTotal(t)
      })
      .catch((err) => {
        setIncidents((prev) => {
          if (prev === null) showToast(err.message)
          return prev ?? []
        })
      })
  }

  useEffect(() => {
    load(limit)
    const interval = setInterval(() => load(limit), 10000)
    return () => clearInterval(interval)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severity, caseStatus, search, campaignId, limit, reviewed])

  useLiveEvents('incidents_changed', () => load(limit))

  const handleLoadMore = async () => {
    setLoadingMore(true)
    const nextLimit = limit + PAGE_SIZE
    await load(nextLimit)
    setLimit(nextLimit)
    setLoadingMore(false)
  }

  const loading = incidents === null
  const filtersActive = Boolean(severity || caseStatus || search || campaignId)

  const clearFilters = () => {
    setSearchInput('')
    setSearch('')
    setSeverity('')
    setCaseStatus('')
    setCampaignId('')
  }

  const applyView = (view) => {
    setSearchInput(view.search || '')
    setSearch(view.search || '')
    setSeverity(view.severity || '')
    setCaseStatus(view.caseStatus || '')
  }

  const saveCurrentView = () => {
    const name = window.prompt('Name this view (e.g. "My open high-severity"):')
    if (!name || !name.trim()) return
    const next = [...savedViews.filter((v) => v.name !== name.trim()), { name: name.trim(), severity, caseStatus, search }]
    setSavedViews(next)
    localStorage.setItem(SAVED_VIEWS_KEY, JSON.stringify(next))
    showToast(`Saved view "${name.trim()}".`, 'success')
  }

  const deleteView = (name) => {
    const next = savedViews.filter((v) => v.name !== name)
    setSavedViews(next)
    localStorage.setItem(SAVED_VIEWS_KEY, JSON.stringify(next))
  }

  const toggleSelected = (id) => {
    setSelected((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const toggleSelectAll = () => {
    setSelected((prev) => {
      if (!incidents || incidents.length === 0) return prev
      const allSelected = incidents.every((i) => prev.has(i._id))
      return allSelected ? new Set() : new Set(incidents.map((i) => i._id))
    })
  }

  const clearSelection = () => setSelected(new Set())

  const DISPOSITION_PROMPT_VALUES = { tp: 'true_positive', fp: 'false_positive', bp: 'benign_positive' }

  const handleBulkClose = async () => {
    const resolution = window.prompt(`Close ${selected.size} case(s) — resolution notes:`)
    if (!resolution || !resolution.trim()) return

    const dispositionInput = window.prompt(
      'Confirmed disposition — type one of: tp (true positive), fp (false positive), bp (benign positive)',
    )
    const disposition = DISPOSITION_PROMPT_VALUES[(dispositionInput || '').trim().toLowerCase()]
    if (!disposition) {
      showToast('Bulk close cancelled — a valid disposition (tp/fp/bp) is required.')
      return
    }

    try {
      await Promise.all([...selected].map((id) => closeIncident(id, resolution.trim(), disposition)))
      showToast(`Closed ${selected.size} case(s).`, 'success')
      clearSelection()
      load(limit)
    } catch (err) {
      showToast(err.message)
    }
  }

  const handleBulkAssign = async () => {
    const assignee = window.prompt(`Assign ${selected.size} case(s) to (leave blank to unassign):`)
    if (assignee === null) return
    try {
      await Promise.all([...selected].map((id) => updateIncident(id, { assigned_to: assignee.trim() || null })))
      showToast(`Updated ${selected.size} case(s).`, 'success')
      clearSelection()
      load(limit)
    } catch (err) {
      showToast(err.message)
    }
  }

  const handleBulkDelete = async () => {
    if (!window.confirm(`Delete ${selected.size} case(s)? This can't be undone.`)) return
    setDeleting(true)
    try {
      const result = await deleteIncidentsBulk([...selected])
      showToast(`Deleted ${result.deleted} case(s).`, 'success')
      clearSelection()
      load(limit)
    } catch (err) {
      showToast(err.message)
    } finally {
      setDeleting(false)
    }
  }

  const handleExport = async () => {
    setExporting(true)
    try {
      const { items } = await getIncidents({ limit: 5000, severity, caseStatus, search, reviewed, campaignId })
      downloadCsv(`${noun}s-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(items, CSV_COLUMNS))
    } catch (err) {
      showToast(err.message)
    } finally {
      setExporting(false)
    }
  }

  const allVisibleSelected = incidents && incidents.length > 0 && incidents.every((i) => selected.has(i._id))

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>{loading ? `Loading ${noun}s...` : `${total} ${noun}${total === 1 ? '' : 's'}`}</h2>
        <button type="button" className="btn-outline" onClick={handleExport} disabled={exporting || loading}>
          <IconDownload width={14} height={14} /> {exporting ? 'Exporting...' : 'Export CSV'}
        </button>
      </div>

      <div className="toolbar-actions" style={{ marginBottom: 12 }}>
        <input
          className="search-input"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder="Search source IP, rule, or assignee..."
        />
        <select className="filter-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          {SEVERITY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <select className="filter-select" value={caseStatus} onChange={(e) => setCaseStatus(e.target.value)}>
          {STATUS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        {campaignId && (
          <span className="filter-count" title={campaignId}>Filtering by campaign</span>
        )}
        {filtersActive && (
          <button type="button" className="btn-outline" onClick={clearFilters}>Clear filters</button>
        )}
        <button type="button" className="btn-outline" onClick={saveCurrentView}>Save view</button>
      </div>

      {savedViews.length > 0 && (
        <div className="ti-pill-row" style={{ marginBottom: 16 }}>
          {savedViews.map((v) => (
            <span key={v.name} className="ti-pill ti-pill--good" style={{ padding: '2px 4px 2px 10px' }}>
              <button type="button" className="chip-apply" onClick={() => applyView(v)}>{v.name}</button>
              <button type="button" className="chip-remove" onClick={() => deleteView(v.name)} title="Delete view">&times;</button>
            </span>
          ))}
        </div>
      )}

      {selected.size > 0 && (
        <div className="toolbar-actions" style={{ marginBottom: 12 }}>
          <span className="filter-count">{selected.size} selected</span>
          <button type="button" className="btn-outline" onClick={handleBulkAssign}>Assign to...</button>
          <button type="button" className="btn-outline" onClick={handleBulkClose}>Close selected</button>
          {isAdmin && (
            <button type="button" className="danger-link" onClick={handleBulkDelete} disabled={deleting}>
              {deleting ? 'Deleting...' : 'Delete selected'}
            </button>
          )}
          <button type="button" className="btn-outline" onClick={clearSelection}>Clear selection</button>
        </div>
      )}

      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th style={{ width: 32 }}>
                <input type="checkbox" checked={Boolean(allVisibleSelected)} onChange={toggleSelectAll} />
              </th>
              <th>Risk</th>
              <th>Severity</th>
              <th>Source IP</th>
              <th>Rule</th>
              <th>Asset</th>
              <th>Client / Instance</th>
              <th>Threat</th>
              <th>Case Status</th>
              <th>Alerts</th>
              <th>MITRE Tactics</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {loading && <SkeletonRows rows={5} columns={12} />}
            {!loading && incidents.map((inc) => (
              <tr
                key={inc._id}
                className={`clickable-row ${inc.severity === 'high' ? 'sev-row-high' : ''}`}
                onClick={() => onSelect(inc._id)}
              >
                <td onClick={(e) => e.stopPropagation()}>
                  <input type="checkbox" checked={selected.has(inc._id)} onChange={() => toggleSelected(inc._id)} />
                </td>
                <td>
                  <RiskBadge risk={inc.risk} />
                  {inc.investigation?.escalate === true && (
                    <span className="escalate-flag" title="AI flagged this for immediate escalation">⚠ Escalate</span>
                  )}
                </td>
                <td>
                  <span className={`sev-dot ${inc.severity === 'high' ? 'high' : 'low'}`} />
                  <span className={inc.severity === 'high' ? 'severity-high' : 'severity-low'}>{inc.severity}</span>
                </td>
                <td className="mono">{inc.source_ip}</td>
                <td>
                  {inc.rule_description}
                  {inc.campaign_id && (
                    <button
                      type="button"
                      className="filter-count"
                      style={{ marginLeft: 8, cursor: 'pointer' }}
                      title="Part of a campaign — incidents grouped by a shared rule or MITRE tactic across different source IPs. Click to filter the list to this campaign."
                      onClick={() => setCampaignId(inc.campaign_id)}
                    >
                      Campaign
                    </button>
                  )}
                </td>
                <td>{inc.asset?.hostname || <span className="muted">&mdash;</span>}</td>
                <td title={inc.org_context?.client_name || inc.org_context?.instance_name ? 'AI-extracted from org docs, unconfirmed' : undefined}>
                  {inc.org_context?.client_name || inc.org_context?.instance_name ? (
                    <>
                      {inc.org_context?.client_name || <span className="muted">Unknown client</span>}
                      {inc.org_context?.instance_name && <span className="muted"> &middot; {inc.org_context.instance_name}</span>}
                    </>
                  ) : (
                    <span className="muted">&mdash;</span>
                  )}
                </td>
                <td>
                  {(() => {
                    const verdict = worstThreatVerdict(inc.threat_intel)
                    return verdict ? <span className={`ti-pill ti-pill--${verdict.level}`}>{verdict.text}</span> : <span className="muted">&mdash;</span>
                  })()}
                </td>
                <td><span className={`case-status case-status-${inc.case_status || 'open'}`}>{inc.case_status || 'open'}</span></td>
                <td>{inc.alert_count}</td>
                <td>{(inc.mitre_tactics || []).join(', ') || <span className="muted">&mdash;</span>}</td>
                <td className="mono muted">{inc.last_seen_iso}</td>
              </tr>
            ))}
            {!loading && incidents.length === 0 && (
              <tr>
                <td colSpan={12}>
                  {filtersActive ? (
                    <EmptyState
                      icon={IconIncidents}
                      title={`No ${noun}s match these filters`}
                      subtitle="Try a different severity, status, or search term."
                    />
                  ) : (
                    <EmptyState
                      icon={IconIncidents}
                      title={`No ${noun}s yet`}
                      subtitle={
                        reviewed === 'false'
                          ? 'Correlated cases awaiting AI review will show up here.'
                          : 'AI-reviewed cases will show up here once investigated.'
                      }
                    />
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {!loading && incidents.length < total && (
        <div style={{ display: 'flex', justifyContent: 'center', marginTop: 16 }}>
          <button type="button" className="btn-outline" onClick={handleLoadMore} disabled={loadingMore}>
            {loadingMore ? 'Loading...' : `Load more (${incidents.length} of ${total})`}
          </button>
        </div>
      )}
    </div>
  )
}

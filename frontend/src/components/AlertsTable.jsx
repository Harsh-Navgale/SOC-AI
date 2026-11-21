import { useEffect, useState } from 'react'
import {
  getAlerts, promoteAlert, uploadAlertsJson, getAlertUploadStatus, deleteAlertsBulk,
  initAlertUpload, getAlertUploadSessionStatus, uploadAlertChunk, completeAlertUpload,
} from '../api.js'
import { SkeletonRows } from './Skeleton.jsx'
import EmptyState from './EmptyState.jsx'
import AlertDetail from './AlertDetail.jsx'
import { IconAlerts, IconDownload, IconUpload } from './icons.jsx'
import { useToast } from '../ToastContext.jsx'
import { useAuth } from '../AuthContext.jsx'
import { useLiveEvents } from '../LiveConnectionContext.jsx'
import { toCsv, downloadCsv } from '../lib/csv.js'

const SEVERITY_OPTIONS = [
  { value: '', label: 'All severities' },
  { value: 'high', label: 'High' },
  { value: 'low', label: 'Low' },
]

const PAGE_SIZE = 100

// Mirrors the backend's LARGE_FILE_THRESHOLD_BYTES (backend/app/alerts_upload.py) — files at or
// under this go through the plain single-request upload; bigger ones use the chunked/resumable
// session flow instead, since a single multi-GB request can't survive a dropped connection.
const LARGE_FILE_THRESHOLD = 50 * 1024 * 1024
const CHUNK_SIZE = 8 * 1024 * 1024
const MAX_CHUNK_RETRIES = 5
const RESUME_KEY = 'soc-ai-upload-resume'

// filename + size + lastModified is enough to tell "same file picked again" from "different file
// with the same name" without hashing the whole thing.
function fileSignature(file) {
  return `${file.name}::${file.size}::${file.lastModified}`
}

function loadResumeState(file) {
  try {
    const raw = localStorage.getItem(RESUME_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    return parsed.signature === fileSignature(file) ? parsed : null
  } catch {
    return null
  }
}

function saveResumeState(file, sessionId) {
  try {
    localStorage.setItem(RESUME_KEY, JSON.stringify({ signature: fileSignature(file), sessionId }))
  } catch {
    // localStorage unavailable (private mode, quota) — resuming just won't work, not fatal
  }
}

function clearResumeState() {
  try {
    localStorage.removeItem(RESUME_KEY)
  } catch {
    // ignore
  }
}

// Uploads a large file as a sequence of fixed-size chunks so a dropped connection, closed tab,
// or sleeping laptop only costs the current chunk, not the whole transfer — re-selecting the
// same file later resumes from the server's actual byte offset instead of starting over.
// This survives network interruptions but not a backend container restart, since session
// tracking lives in memory only (see upload_sessions.py).
async function uploadLargeFileResumable(file, onProgress) {
  let sessionId
  let offset = 0

  const resumed = loadResumeState(file)
  if (resumed) {
    try {
      const status = await getAlertUploadSessionStatus(resumed.sessionId)
      sessionId = resumed.sessionId
      offset = status.bytes_received
    } catch {
      clearResumeState()
    }
  }

  if (!sessionId) {
    const session = await initAlertUpload(file.name, file.size)
    sessionId = session.session_id
    offset = session.bytes_received
    saveResumeState(file, sessionId)
  }

  onProgress(offset, file.size)

  while (offset < file.size) {
    const chunkStart = offset
    const chunk = file.slice(chunkStart, chunkStart + CHUNK_SIZE)
    let attempt = 0
    for (;;) {
      try {
        const result = await uploadAlertChunk(sessionId, chunk, chunkStart, (loaded) => {
          onProgress(chunkStart + loaded, file.size)
        })
        offset = result.bytes_received
        break
      } catch (err) {
        if (err.status === 409) {
          // Someone else's chunk (or a retried duplicate) already moved the server past where
          // we thought we were — resync to the real offset and re-slice on the next iteration
          // instead of trusting our own bookkeeping.
          const status = await getAlertUploadSessionStatus(sessionId)
          offset = status.bytes_received
          break
        }
        attempt += 1
        if (attempt > MAX_CHUNK_RETRIES) throw err
        await new Promise((resolve) => setTimeout(resolve, Math.min(1000 * 2 ** attempt, 15000)))
      }
    }
  }

  const result = await completeAlertUpload(sessionId)
  clearResumeState()
  return result
}

function formatBytes(n) {
  if (!n && n !== 0) return '—'
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`
}

function formatEta(seconds) {
  if (seconds == null || !isFinite(seconds) || seconds < 0) return null
  if (seconds < 1) return 'a few seconds'
  const m = Math.floor(seconds / 60)
  const s = Math.round(seconds % 60)
  if (m === 0) return `${s}s`
  if (m < 60) return `${m}m ${s}s`
  const h = Math.floor(m / 60)
  return `${h}h ${m % 60}m`
}

const CSV_COLUMNS = [
  { label: 'Level', value: (a) => a.rule?.level ?? '' },
  { label: 'Rule', value: (a) => a.rule?.description ?? '' },
  { label: 'Agent', value: (a) => a.agent?.name ?? '' },
  { label: 'Agent IP', value: (a) => a.agent?.ip ?? '' },
  { label: 'Timestamp', value: (a) => a.timestamp },
  { label: 'Excluded', value: (a) => (a.excluded ? `Yes (${a.excluded_by_rule || ''})` : 'No') },
]

export default function AlertsTable() {
  const [alerts, setAlerts] = useState(null)
  const [total, setTotal] = useState(0)
  const [limit, setLimit] = useState(PAGE_SIZE)
  const [loadingMore, setLoadingMore] = useState(false)
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [exporting, setExporting] = useState(false)
  const [promoting, setPromoting] = useState(null)
  // null when idle; while active: { phase: 'uploading'|'processing', percent, loaded, total,
  // speedBps, etaSeconds, inserted?, duplicates?, failed? } — 'processing' only ever appears for
  // large files, once the transfer has finished and the backend is working through it in the
  // background (see upload_jobs.py / GET /api/alerts/upload/status).
  const [uploadState, setUploadState] = useState(null)
  const [selected, setSelected] = useState(new Set())
  const [deleting, setDeleting] = useState(false)
  const [selectedAlert, setSelectedAlert] = useState(null)
  const { showToast } = useToast()
  const { isAdmin } = useAuth()

  useEffect(() => {
    const t = setTimeout(() => setSearch(searchInput.trim()), 350)
    return () => clearTimeout(t)
  }, [searchInput])

  useEffect(() => {
    setLimit(PAGE_SIZE)
  }, [severity, search])

  const load = (currentLimit = limit) => {
    return getAlerts({ limit: currentLimit, severity, search })
      .then(({ items, total: t }) => {
        setAlerts(items)
        setTotal(t)
      })
      .catch((err) => {
        setAlerts((prev) => {
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
  }, [severity, search, limit])

  useLiveEvents('alerts_changed', () => load(limit))

  const handleLoadMore = async () => {
    setLoadingMore(true)
    const nextLimit = limit + PAGE_SIZE
    await load(nextLimit)
    setLimit(nextLimit)
    setLoadingMore(false)
  }

  const loading = alerts === null
  const filtersActive = Boolean(severity || search)

  const clearFilters = () => {
    setSearchInput('')
    setSearch('')
    setSeverity('')
  }

  const handlePromote = async (alertId) => {
    setPromoting(alertId)
    try {
      await promoteAlert(alertId)
      showToast('Promoted to a case.', 'success')
      setSelectedAlert((prev) => (prev && prev._id === alertId ? { ...prev, correlated: true } : prev))
      load(limit)
    } catch (err) {
      showToast(err.message)
    } finally {
      setPromoting(null)
    }
  }

  const handleDeletedFromDetail = (alertId) => {
    setAlerts((prev) => prev?.filter((a) => a._id !== alertId) ?? prev)
    setSelected((prev) => {
      if (!prev.has(alertId)) return prev
      const next = new Set(prev)
      next.delete(alertId)
      return next
    })
  }

  const reportIngestResult = (result, filename) => {
    const notes = []
    if (result.duplicates > 0) notes.push(`${result.duplicates} already present`)
    if (result.failed > 0) notes.push(`${result.failed} could not be stored`)
    if (result.skipped_low_severity > 0) notes.push(`${result.skipped_low_severity} below the minimum rule level`)
    const suffix = notes.length > 0 ? ` (${notes.join(', ')})` : ''
    showToast(`Ingested ${result.inserted} alert${result.inserted === 1 ? '' : 's'} from ${filename}${suffix}.`, result.inserted > 0 ? 'success' : 'error')
    load(limit)
  }

  // Large files (see LARGE_FILE_THRESHOLD_BYTES on the backend) come back from the upload
  // itself with just a job_id — the actual import runs in the background, so progress after
  // that point means polling GET /api/alerts/upload/status/{job_id} instead of tracking bytes
  // sent, which is what the earlier 'uploading' phase's progress bar was showing.
  const pollUploadJob = async (jobId, filename) => {
    const startedAt = Date.now()
    for (;;) {
      const job = await getAlertUploadStatus(jobId)
      const elapsed = (Date.now() - startedAt) / 1000
      const speedBps = elapsed > 0 ? job.bytes_processed / elapsed : 0
      const etaSeconds = speedBps > 0 ? (job.total_bytes - job.bytes_processed) / speedBps : null
      setUploadState({
        phase: 'processing',
        percent: job.total_bytes ? (job.bytes_processed / job.total_bytes) * 100 : 0,
        loaded: job.bytes_processed,
        total: job.total_bytes,
        speedBps,
        etaSeconds,
        inserted: job.inserted,
        duplicates: job.duplicates,
        failed: job.failed,
        skippedLowSeverity: job.skipped_low_severity,
      })

      if (job.status === 'done') {
        reportIngestResult(job, filename)
        return
      }
      if (job.status === 'error') {
        showToast(`Import of ${filename} failed: ${job.error}`)
        return
      }
      await new Promise((resolve) => setTimeout(resolve, 1000))
    }
  }

  const handleUploadFile = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    const startedAt = Date.now()
    setUploadState({ phase: 'uploading', percent: 0, loaded: 0, total: file.size, speedBps: 0, etaSeconds: null })
    const onProgress = (loaded, total) => {
      const elapsed = (Date.now() - startedAt) / 1000
      const speedBps = elapsed > 0 ? loaded / elapsed : 0
      const etaSeconds = speedBps > 0 ? (total - loaded) / speedBps : null
      setUploadState({ phase: 'uploading', percent: total ? (loaded / total) * 100 : 0, loaded, total, speedBps, etaSeconds })
    }
    try {
      const result = file.size > LARGE_FILE_THRESHOLD
        ? await uploadLargeFileResumable(file, onProgress)
        : await uploadAlertsJson(file, onProgress)

      if (result.job_id) {
        await pollUploadJob(result.job_id, file.name)
      } else {
        reportIngestResult({ inserted: result.inserted, duplicates: result.skipped_duplicates, failed: result.failed }, file.name)
      }
    } catch (err) {
      showToast(err.message)
    } finally {
      setUploadState(null)
      e.target.value = ''
    }
  }

  const handleExport = async () => {
    setExporting(true)
    try {
      const { items } = await getAlerts({ limit: 5000, severity, search })
      downloadCsv(`alerts-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(items, CSV_COLUMNS))
    } catch (err) {
      showToast(err.message)
    } finally {
      setExporting(false)
    }
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
      if (!alerts || alerts.length === 0) return prev
      const allSelected = alerts.every((a) => prev.has(a._id))
      return allSelected ? new Set() : new Set(alerts.map((a) => a._id))
    })
  }

  const clearSelection = () => setSelected(new Set())

  const handleBulkDelete = async () => {
    if (!window.confirm(`Delete ${selected.size} alert(s)? This can't be undone.`)) return
    setDeleting(true)
    try {
      const result = await deleteAlertsBulk([...selected])
      showToast(`Deleted ${result.deleted} alert(s).`, 'success')
      clearSelection()
      load(limit)
    } catch (err) {
      showToast(err.message)
    } finally {
      setDeleting(false)
    }
  }

  const allVisibleSelected = alerts && alerts.length > 0 && alerts.every((a) => selected.has(a._id))

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>{loading ? 'Loading alerts...' : `${total} alert${total === 1 ? '' : 's'}`}</h2>
        <div className="toolbar-actions">
          {isAdmin && (
            <label className="btn-outline" style={{ cursor: uploadState ? 'default' : 'pointer' }}>
              <IconUpload width={14} height={14} /> {uploadState ? 'Upload in progress...' : 'Upload alerts JSON'}
              <input
                type="file"
                accept=".json,.jsonl,.txt,application/json"
                onChange={handleUploadFile}
                disabled={Boolean(uploadState)}
                style={{ display: 'none' }}
              />
            </label>
          )}
          <button type="button" className="btn-outline" onClick={handleExport} disabled={exporting || loading}>
            <IconDownload width={14} height={14} /> {exporting ? 'Exporting...' : 'Export CSV'}
          </button>
        </div>
      </div>

      {uploadState && (
        <div className="upload-progress">
          <div className="upload-progress-row">
            <span className="upload-progress-phase">
              {uploadState.phase === 'uploading' ? 'Uploading file' : 'Processing alerts'}
            </span>
            <span className="upload-progress-detail">
              {formatBytes(uploadState.loaded)} / {formatBytes(uploadState.total)}
              {uploadState.speedBps > 0 && ` · ${formatBytes(uploadState.speedBps)}/s`}
              {uploadState.etaSeconds != null && ` · ${formatEta(uploadState.etaSeconds)} remaining`}
            </span>
          </div>
          <div className="upload-progress-track">
            <div className="upload-progress-fill" style={{ width: `${Math.min(uploadState.percent, 100)}%` }} />
          </div>
          {uploadState.phase === 'processing' && (
            <div className="upload-progress-counts">
              {uploadState.inserted ?? 0} inserted
              {uploadState.duplicates > 0 && ` · ${uploadState.duplicates} duplicate`}
              {uploadState.failed > 0 && ` · ${uploadState.failed} failed`}
              {uploadState.skippedLowSeverity > 0 && ` · ${uploadState.skippedLowSeverity} below min. rule level`}
            </div>
          )}
        </div>
      )}

      <div className="toolbar-actions" style={{ marginBottom: 16 }}>
        <input
          className="search-input"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder="Search rule, agent name, or agent IP..."
        />
        <select className="filter-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          {SEVERITY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        {filtersActive && (
          <button type="button" className="btn-outline" onClick={clearFilters}>Clear filters</button>
        )}
      </div>

      {isAdmin && selected.size > 0 && (
        <div className="toolbar-actions" style={{ marginBottom: 12 }}>
          <span className="filter-count">{selected.size} selected</span>
          <button type="button" className="danger-link" onClick={handleBulkDelete} disabled={deleting}>
            {deleting ? 'Deleting...' : 'Delete selected'}
          </button>
          <button type="button" className="btn-outline" onClick={clearSelection}>Clear selection</button>
        </div>
      )}

      <div className="table-card">
        <table>
          <thead>
            <tr>
              {isAdmin && (
                <th style={{ width: 32 }}>
                  <input type="checkbox" checked={Boolean(allVisibleSelected)} onChange={toggleSelectAll} />
                </th>
              )}
              <th>Level</th>
              <th>Rule</th>
              <th>Agent</th>
              <th>Timestamp</th>
              <th>Case</th>
            </tr>
          </thead>
          <tbody>
            {loading && <SkeletonRows rows={5} columns={isAdmin ? 6 : 5} />}
            {!loading && alerts.map((a) => (
              <tr
                key={a._id}
                className={`clickable-row ${(a.rule?.level || 0) >= 10 ? 'sev-row-high' : ''}`}
                onClick={() => setSelectedAlert(a)}
              >
                {isAdmin && (
                  <td onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" checked={selected.has(a._id)} onChange={() => toggleSelected(a._id)} />
                  </td>
                )}
                <td>
                  <span className={`sev-dot ${(a.rule?.level || 0) >= 10 ? 'high' : 'low'}`} />
                  {a.rule?.level}
                </td>
                <td>{a.rule?.description}</td>
                <td className="mono">{a.agent?.name}</td>
                <td className="mono muted">{a.timestamp}</td>
                <td onClick={(e) => e.stopPropagation()}>
                  {a.excluded && (
                    <span className="ti-pill ti-pill--warn" style={{ marginRight: 6 }} title={`Excluded by rule: ${a.excluded_by_rule || ''}`}>
                      Excluded
                    </span>
                  )}
                  {a.correlated && !a.excluded ? (
                    <span className="muted">In a case</span>
                  ) : (
                    <button
                      type="button"
                      className="btn-outline"
                      onClick={() => handlePromote(a._id)}
                      disabled={promoting === a._id}
                    >
                      {promoting === a._id ? 'Promoting...' : a.excluded ? 'Promote anyway' : 'Promote to case'}
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {!loading && alerts.length === 0 && (
              <tr>
                <td colSpan={isAdmin ? 6 : 5}>
                  {filtersActive ? (
                    <EmptyState
                      icon={IconAlerts}
                      title="No alerts match these filters"
                      subtitle="Try a different severity or search term."
                    />
                  ) : (
                    <EmptyState
                      icon={IconAlerts}
                      title="No alerts yet"
                      subtitle="Alerts polled from Wazuh will appear here as they arrive."
                    />
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {!loading && alerts.length < total && (
        <div style={{ display: 'flex', justifyContent: 'center', marginTop: 16 }}>
          <button type="button" className="btn-outline" onClick={handleLoadMore} disabled={loadingMore}>
            {loadingMore ? 'Loading...' : `Load more (${alerts.length} of ${total})`}
          </button>
        </div>
      )}

      {selectedAlert && (
        <AlertDetail
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onPromote={handlePromote}
          promoting={promoting === selectedAlert._id}
          onDeleted={handleDeletedFromDetail}
        />
      )}
    </div>
  )
}

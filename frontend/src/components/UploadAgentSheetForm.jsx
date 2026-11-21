import { useEffect, useState } from 'react'
import { getAgentSheetStatus, uploadAgentSheet, clearAgentSheet } from '../api.js'
import { useToast } from '../ToastContext.jsx'

export default function UploadAgentSheetForm({ onUploaded }) {
  const [status, setStatus] = useState(null)
  const [uploading, setUploading] = useState(false)
  const { showToast } = useToast()

  const loadStatus = () => getAgentSheetStatus().then(setStatus).catch(() => {})

  useEffect(() => {
    loadStatus()
  }, [])

  const handleFileChange = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    try {
      const result = await uploadAgentSheet(file)
      showToast(`Uploaded ${result.count} agent${result.count === 1 ? '' : 's'} from ${file.name}.`, 'success')
      loadStatus()
      onUploaded?.()
    } catch (err) {
      showToast(err.message)
    } finally {
      setUploading(false)
      e.target.value = ''
    }
  }

  const handleClear = async () => {
    try {
      await clearAgentSheet()
      loadStatus()
      onUploaded?.()
    } catch (err) {
      showToast(err.message)
    }
  }

  return (
    <div className="card" style={{ maxWidth: 520 }}>
      <h3 style={{ margin: '0 0 10px' }}>Or upload a manual agent sheet</h3>
      <p className="muted" style={{ marginTop: 0, fontSize: 12, lineHeight: 1.6 }}>
        A CSV with <span className="mono">name</span>, <span className="mono">ip</span>, and
        <span className="mono"> status</span> columns. Used automatically whenever the live
        Wazuh Manager API isn't configured or isn't reachable. Held in server memory only for
        12 hours, same as the AWS/Wazuh connections above.
      </p>

      {status?.configured ? (
        <div className="stat-row" style={{ marginBottom: 12 }}>
          <div className="stat-tile">
            <div className="stat-value">{status.count}</div>
            <div className="stat-label">Agents in sheet</div>
          </div>
          <div className="stat-tile">
            <div className="stat-value mono" style={{ fontSize: 12 }}>{status.uploaded_by}</div>
            <div className="stat-label">Uploaded by</div>
          </div>
        </div>
      ) : (
        <p className="muted" style={{ fontSize: 12 }}>No sheet currently uploaded.</p>
      )}

      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
        <label className="ask" style={{ display: 'inline-block', cursor: 'pointer' }}>
          {uploading ? 'Uploading...' : 'Choose CSV file'}
          <input type="file" accept=".csv,text/csv" onChange={handleFileChange} disabled={uploading} style={{ display: 'none' }} />
        </label>
        {status?.configured && (
          <button className="danger-link" onClick={handleClear}>Clear sheet</button>
        )}
      </div>
    </div>
  )
}

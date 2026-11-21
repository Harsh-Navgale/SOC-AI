import { useEffect, useState } from 'react'
import { getThreatIntelStatus, setThreatIntelCredentials, clearThreatIntelCredentials, lookupThreatIntel } from '../api.js'
import { useAuth } from '../AuthContext.jsx'
import { useToast } from '../ToastContext.jsx'
import { SkeletonCard } from './Skeleton.jsx'
import { IconRadar } from './icons.jsx'
import { SOURCES, externalLink, SourceBody } from './threatIntelDisplay.jsx'

function ThreatIntelKeysForm({ status, onChanged }) {
  const [vtKey, setVtKey] = useState('')
  const [abuseKey, setAbuseKey] = useState('')
  const [abusechKey, setAbusechKey] = useState('')
  const [saving, setSaving] = useState(false)
  const [open, setOpen] = useState(true)
  const { showToast } = useToast()

  const anyConfigured = status?.virustotal_configured || status?.abuseipdb_configured || status?.abusech_configured

  const handleSave = async (e) => {
    e.preventDefault()
    setSaving(true)
    try {
      await setThreatIntelCredentials(vtKey.trim() || null, abuseKey.trim() || null, abusechKey.trim() || null)
      showToast('Threat intel keys saved.', 'success')
      setVtKey('')
      setAbuseKey('')
      setAbusechKey('')
      onChanged()
    } catch (err) {
      showToast(err.message)
    } finally {
      setSaving(false)
    }
  }

  const handleClear = async () => {
    try {
      await clearThreatIntelCredentials()
      showToast('Threat intel keys cleared.', 'success')
      onChanged()
    } catch (err) {
      showToast(err.message)
    }
  }

  if (!open) {
    return (
      <button className="btn-outline" onClick={() => setOpen(true)} style={{ marginBottom: 16 }}>
        Manage API keys
      </button>
    )
  }

  return (
    <div className="card" style={{ maxWidth: 560, marginBottom: 20 }}>
      <h3 style={{ margin: '0 0 10px' }}>API keys</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        All four sources need a free key/account &mdash; none of them offer fully anonymous
        access. URLhaus and ThreatFox share one abuse.ch Auth-Key. Held in server memory only
        for 12 hours, same as the AWS/Wazuh connections; you'll need to re-enter after that.
      </p>
      <form onSubmit={handleSave} className="user-form" style={{ flexWrap: 'wrap' }}>
        <input
          value={vtKey}
          onChange={(e) => setVtKey(e.target.value)}
          placeholder={status?.virustotal_configured ? 'VirusTotal key (configured — enter to replace)' : 'VirusTotal API key'}
          type="password"
          style={{ flex: '1 1 100%' }}
        />
        <input
          value={abuseKey}
          onChange={(e) => setAbuseKey(e.target.value)}
          placeholder={status?.abuseipdb_configured ? 'AbuseIPDB key (configured — enter to replace)' : 'AbuseIPDB API key'}
          type="password"
          style={{ flex: '1 1 100%' }}
        />
        <input
          value={abusechKey}
          onChange={(e) => setAbusechKey(e.target.value)}
          placeholder={status?.abusech_configured ? 'abuse.ch Auth-Key (configured — enter to replace)' : 'abuse.ch Auth-Key (URLhaus + ThreatFox)'}
          type="password"
          style={{ flex: '1 1 100%' }}
        />
        <button type="submit" className="ask" disabled={saving}>{saving ? 'Saving...' : 'Save'}</button>
        {anyConfigured && (
          <button type="button" className="danger-link" onClick={handleClear}>Clear keys</button>
        )}
        <button type="button" className="btn-outline" onClick={() => setOpen(false)}>Hide</button>
      </form>
    </div>
  )
}

export default function ThreatIntel() {
  const { isAdmin } = useAuth()
  const [status, setStatus] = useState(null)
  const [indicator, setIndicator] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const { showToast } = useToast()

  const loadStatus = () => getThreatIntelStatus().then(setStatus).catch(() => {})

  useEffect(() => {
    loadStatus()
  }, [])

  const noSourcesConfigured = status && !status.virustotal_configured && !status.abuseipdb_configured && !status.abusech_configured

  const handleLookup = async (e) => {
    e?.preventDefault()
    const value = indicator.trim()
    if (!value || loading) return
    setLoading(true)
    setResult(null)
    try {
      const data = await lookupThreatIntel(value)
      setResult(data)
    } catch (err) {
      showToast(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>Indicator lookup</h2>
      </div>

      {noSourcesConfigured && (
        <p className="muted" style={{ marginBottom: 16 }}>
          No threat intel sources are configured yet, so a lookup won't return data here — only
          each source's &ldquo;View &rarr;&rdquo; link, which opens that source's own website in
          a new tab (that's expected, not a redirect bug).{' '}
          {isAdmin
            ? 'Add at least one API key below to see results in this dashboard.'
            : 'Ask an admin to add an API key (VirusTotal, AbuseIPDB, and/or an abuse.ch Auth-Key) under Manage API keys.'}
        </p>
      )}

      {isAdmin && <ThreatIntelKeysForm status={status} onChanged={loadStatus} />}

      <form onSubmit={handleLookup} className="toolbar-actions" style={{ marginBottom: 20 }}>
        <input
          className="search-input"
          style={{ minWidth: 360, flex: 1, maxWidth: 520 }}
          value={indicator}
          onChange={(e) => setIndicator(e.target.value)}
          placeholder="IP, domain, URL, or file hash (MD5/SHA1/SHA256)..."
          autoFocus
        />
        <button type="submit" className="ask" disabled={loading || !indicator.trim()}>
          {loading ? 'Looking up...' : 'Look up'}
        </button>
      </form>

      {!result && !loading && (
        <div className="chat-empty-hint">
          <IconRadar width={22} height={22} style={{ marginBottom: 8, opacity: 0.4 }} />
          <div>Search an indicator to check it against VirusTotal, AbuseIPDB, URLhaus, and ThreatFox at once.</div>
        </div>
      )}

      {loading && (
        <div className="chart-grid">
          {SOURCES.map((s) => <SkeletonCard key={s.key} lines={2} />)}
        </div>
      )}

      {result && !loading && (
        <>
          <p className="muted" style={{ marginBottom: 14 }}>
            Showing results for <span className="mono">{result.indicator}</span>
            {' '}&middot; detected as <strong>{result.indicator_type}</strong>
          </p>
          <div className="chart-grid">
            {SOURCES.map(({ key, label }) => (
              <div className="chart-card" key={key}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                  <h3>{label}</h3>
                  <a href={externalLink(key, result.indicator, result.indicator_type)} target="_blank" rel="noreferrer" className="context-toggle">
                    View &rarr;
                  </a>
                </div>
                <SourceBody sourceKey={key} result={result.sources?.[key]} />
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

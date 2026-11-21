export const SOURCES = [
  { key: 'virustotal', label: 'VirusTotal' },
  { key: 'abuseipdb', label: 'AbuseIPDB' },
  { key: 'urlhaus', label: 'URLhaus (abuse.ch)' },
  { key: 'threatfox', label: 'ThreatFox (abuse.ch)' },
]

export const NOT_CONFIGURED_HINT = {
  virustotal: 'Add a VirusTotal API key above to include this source.',
  abuseipdb: 'Add an AbuseIPDB API key above to include this source.',
  urlhaus: 'Add an abuse.ch Auth-Key above to include this source.',
  threatfox: 'Add an abuse.ch Auth-Key above to include this source.',
}

export function externalLink(sourceKey, indicator, indicatorType) {
  const q = encodeURIComponent(indicator)
  switch (sourceKey) {
    case 'virustotal': return `https://www.virustotal.com/gui/search/${q}`
    case 'abuseipdb': return `https://www.abuseipdb.com/check/${q}`
    case 'urlhaus': return indicatorType === 'url' ? `https://urlhaus.abuse.ch/browse.php?search=${q}` : `https://urlhaus.abuse.ch/host/${q}/`
    case 'threatfox': return `https://threatfox.abuse.ch/browse.php?search=${q}`
    default: return null
  }
}

export function SourceBody({ sourceKey, result }) {
  if (!result || result.status === 'not_configured') {
    return <p className="muted">{NOT_CONFIGURED_HINT[sourceKey]}</p>
  }
  if (result.status === 'not_applicable') {
    return <p className="muted">AbuseIPDB only checks IP addresses.</p>
  }
  if (result.status === 'error') {
    return <p className="login-error">{result.error}</p>
  }
  const d = result.data || {}
  if (!d.found) {
    return <p className="muted">No records found for this indicator.</p>
  }

  if (sourceKey === 'virustotal') {
    const total = (d.malicious || 0) + (d.suspicious || 0) + (d.harmless || 0) + (d.undetected || 0)
    return (
      <div className="ti-stats">
        <div className={`ti-stat ${d.malicious > 0 ? 'ti-stat--bad' : 'ti-stat--good'}`}>
          <span className="ti-stat-value">{d.malicious}/{total}</span>
          <span className="ti-stat-label">engines flagged malicious</span>
        </div>
        {d.suspicious > 0 && <p className="muted">{d.suspicious} flagged suspicious</p>}
        {d.reputation != null && <p className="muted">Community reputation: {d.reputation}</p>}
      </div>
    )
  }
  if (sourceKey === 'abuseipdb') {
    const score = d.abuse_confidence_score ?? 0
    return (
      <div className="ti-stats">
        <div className={`ti-stat ${score >= 50 ? 'ti-stat--bad' : score > 0 ? 'ti-stat--warn' : 'ti-stat--good'}`}>
          <span className="ti-stat-value">{score}%</span>
          <span className="ti-stat-label">abuse confidence</span>
        </div>
        <p className="muted">{d.total_reports} report{d.total_reports === 1 ? '' : 's'} &middot; {d.isp || 'Unknown ISP'} &middot; {d.country_code || '—'}</p>
      </div>
    )
  }
  if (sourceKey === 'urlhaus') {
    return (
      <div className="ti-stats">
        <div className="ti-stat ti-stat--bad">
          <span className="ti-stat-value">{d.url_count}</span>
          <span className="ti-stat-label">known malicious URL{d.url_count === 1 ? '' : 's'}</span>
        </div>
        {d.threat && <p className="muted">Threat: {d.threat}</p>}
        {d.tags?.length > 0 && <p className="muted">Tags: {d.tags.join(', ')}</p>}
      </div>
    )
  }
  if (sourceKey === 'threatfox') {
    return (
      <div className="ti-stats">
        <div className="ti-stat ti-stat--bad">
          <span className="ti-stat-value">{d.ioc_count}</span>
          <span className="ti-stat-label">matching IOC{d.ioc_count === 1 ? '' : 's'}</span>
        </div>
        {d.malware && <p className="muted">Malware: {d.malware} &middot; {d.threat_type}</p>}
        {d.confidence_level != null && <p className="muted">Confidence: {d.confidence_level}%</p>}
      </div>
    )
  }
  return null
}

// Condensed one-line-per-source verdict, for contexts (like the incident modal) where the full
// card grid used on the Threat Intel page itself would be too heavy. Returns null for a source
// that isn't configured/applicable, so callers can filter those out rather than showing noise.
export function sourceVerdict(sourceKey, result) {
  if (!result || result.status === 'not_configured' || result.status === 'not_applicable') return null
  if (result.status === 'error') return { level: 'warn', text: 'lookup failed' }
  const d = result.data || {}
  if (!d.found) return { level: 'good', text: 'no records found' }

  if (sourceKey === 'virustotal') {
    const total = (d.malicious || 0) + (d.suspicious || 0) + (d.harmless || 0) + (d.undetected || 0)
    return { level: d.malicious > 0 ? 'bad' : 'good', text: `${d.malicious}/${total} malicious` }
  }
  if (sourceKey === 'abuseipdb') {
    const score = d.abuse_confidence_score ?? 0
    return { level: score >= 50 ? 'bad' : score > 0 ? 'warn' : 'good', text: `${score}% confidence` }
  }
  if (sourceKey === 'urlhaus') {
    return { level: d.url_count > 0 ? 'bad' : 'good', text: `${d.url_count} malicious URL${d.url_count === 1 ? '' : 's'}` }
  }
  if (sourceKey === 'threatfox') {
    return { level: d.ioc_count > 0 ? 'bad' : 'good', text: `${d.ioc_count} IOC match${d.ioc_count === 1 ? '' : 'es'}` }
  }
  return null
}

export function ThreatIntelCompact({ result, loading, indicator }) {
  if (loading) return <p className="muted">Checking VirusTotal, AbuseIPDB, URLhaus, and ThreatFox for {indicator}...</p>
  if (!result) return null

  const pills = SOURCES
    .map(({ key, label }) => ({ key, label, verdict: sourceVerdict(key, result.sources?.[key]) }))
    .filter((p) => p.verdict)

  if (pills.length === 0) {
    return <p className="muted">No threat intel sources are configured — add API keys on the Threat Intel tab.</p>
  }

  return (
    <div className="ti-pill-row">
      {pills.map(({ key, label, verdict }) => (
        <a
          key={key}
          className={`ti-pill ti-pill--${verdict.level}`}
          href={externalLink(key, result.indicator, result.indicator_type)}
          target="_blank"
          rel="noreferrer"
          title={`View ${label} on ${result.indicator}`}
        >
          <strong>{label}</strong> {verdict.text}
        </a>
      ))}
    </div>
  )
}

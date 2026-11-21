import { useEffect, useMemo, useState } from 'react'
import { getIncidents, getAlerts } from '../api.js'
import TrendChart from './charts/TrendChart.jsx'
import BarList from './charts/BarList.jsx'
import { SkeletonKpiRow, SkeletonBlock } from './Skeleton.jsx'
import { useToast } from '../ToastContext.jsx'
import { IconIncidents, IconClock, IconAlerts, IconHealth, IconQueue, IconExclude } from './icons.jsx'

function buildHourlyBuckets(alerts) {
  const now = new Date()
  const buckets = []
  for (let i = 23; i >= 0; i--) {
    const bucketTime = new Date(now.getTime() - i * 3600000)
    buckets.push({
      label: bucketTime.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }),
      value: 0,
    })
  }
  alerts.forEach((a) => {
    if (!a.timestamp) return
    const t = new Date(a.timestamp)
    if (Number.isNaN(t.getTime())) return
    const hoursAgo = Math.floor((now - t) / 3600000)
    if (hoursAgo >= 0 && hoursAgo < 24) {
      buckets[23 - hoursAgo].value += 1
    }
  })
  return buckets
}

function topSourceIPs(incidents) {
  const totals = {}
  incidents.forEach((inc) => {
    const ip = inc.source_ip || 'unknown'
    totals[ip] = (totals[ip] || 0) + (inc.alert_count || 1)
  })
  return Object.entries(totals)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([label, value]) => ({ label, value, color: 'var(--accent)' }))
}

function mitreBreakdown(incidents) {
  const totals = {}
  incidents.forEach((inc) => {
    (inc.mitre_tactics || []).forEach((tactic) => {
      totals[tactic] = (totals[tactic] || 0) + 1
    })
  })
  return Object.entries(totals)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([label, value]) => ({ label, value, color: 'var(--accent)' }))
}

function topRules(incidents) {
  const totals = {}
  incidents.forEach((inc) => {
    const rule = inc.rule_description || 'unknown'
    totals[rule] = (totals[rule] || 0) + 1
  })
  return Object.entries(totals)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([label, value]) => ({ label, value, color: 'var(--accent)' }))
}

// A case counts as "near closure" once it's actively being worked (an analyst assigned, a note
// added, or the AI has already produced a report) but hasn't been closed yet — distinct from a
// plain "investigating" case that no one has touched. Every case falls into exactly one of the
// four buckets below, so they still sum to the total (no double-counting against "Investigating").
function isNearClosure(inc) {
  return (
    (inc.case_status || 'open') === 'investigating' &&
    Boolean(inc.assigned_to || (inc.notes && inc.notes.length > 0) || inc.investigation)
  )
}

export default function Overview() {
  const [incidents, setIncidents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [loaded, setLoaded] = useState(false)
  const { showToast } = useToast()

  useEffect(() => {
    const load = () => {
      Promise.allSettled([getIncidents({ limit: 500 }), getAlerts({ limit: 500 })]).then(([incRes, alertRes]) => {
        if (incRes.status === 'fulfilled') setIncidents(incRes.value.items)
        if (alertRes.status === 'fulfilled') setAlerts(alertRes.value.items)
        if (incRes.status === 'rejected' || alertRes.status === 'rejected') {
          if (!loaded) showToast('Could not load overview data.')
        }
        setLoaded(true)
      })
    }
    load()
    const interval = setInterval(load, 20000)
    return () => clearInterval(interval)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const stats = useMemo(() => {
    const openCases = incidents.filter((i) => (i.case_status || 'open') !== 'closed').length
    const pendingReview = incidents.filter((i) => !i.investigation).length
    const riskCounts = { critical: 0, high: 0, medium: 0, low: 0 }
    incidents.forEach((i) => {
      const label = i.risk?.label || 'low'
      riskCounts[label] = (riskCounts[label] || 0) + 1
    })

    let nearClosure = 0
    const statusCounts = { open: 0, investigating: 0, closed: 0 }
    incidents.forEach((i) => {
      const s = i.case_status || 'open'
      if (s === 'investigating' && isNearClosure(i)) {
        nearClosure += 1
      } else {
        statusCounts[s] = (statusCounts[s] || 0) + 1
      }
    })

    const excludedAlerts = alerts.filter((a) => a.excluded).length
    const inCaseAlerts = alerts.filter((a) => a.correlated && !a.excluded).length
    const pendingAlerts = alerts.length - excludedAlerts - inCaseAlerts

    return {
      totalIncidents: incidents.length,
      openCases,
      criticalRisk: riskCounts.critical,
      pendingReview,
      totalAlerts: alerts.length,
      excludedAlerts,
      severityBreakdown: [
        { label: 'Critical', value: riskCounts.critical, color: 'var(--critical)' },
        { label: 'High', value: riskCounts.high, color: 'var(--serious)' },
        { label: 'Medium', value: riskCounts.medium, color: 'var(--warning)' },
        { label: 'Low', value: riskCounts.low, color: 'var(--good)' },
      ],
      caseStatusBreakdown: [
        { label: 'Open', value: statusCounts.open, color: 'var(--accent)' },
        { label: 'Investigating', value: statusCounts.investigating, color: 'var(--warning)' },
        { label: 'Near closure', value: nearClosure, color: 'var(--serious)' },
        { label: 'Closed', value: statusCounts.closed, color: 'var(--muted-status)' },
      ],
      alertTriage: [
        { label: 'Pending', value: Math.max(0, pendingAlerts), color: 'var(--accent)' },
        { label: 'In a case', value: inCaseAlerts, color: 'var(--good)' },
        { label: 'Excluded', value: excludedAlerts, color: 'var(--muted-status)' },
      ],
      topIPs: topSourceIPs(incidents),
      topRules: topRules(incidents),
      mitre: mitreBreakdown(incidents),
      trend: buildHourlyBuckets(alerts),
    }
  }, [incidents, alerts])

  if (!loaded) {
    return (
      <div>
        <SkeletonKpiRow count={6} />
        <div className="chart-grid">
          <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
            <SkeletonBlock height={160} />
          </div>
          {Array.from({ length: 6 }).map((_, i) => (
            <div className="chart-card" key={i}>
              <SkeletonBlock height={120} />
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="content-fade-in">
      <div className="kpi-row">
        <div className="kpi-tile">
          <div className="kpi-icon"><IconIncidents width={16} height={16} /></div>
          <div className="kpi-value">{stats.totalIncidents}</div>
          <div className="kpi-label">Total cases</div>
        </div>
        <div className="kpi-tile kpi-accent-accent">
          <div className="kpi-icon"><IconClock width={16} height={16} /></div>
          <div className="kpi-value">{stats.openCases}</div>
          <div className="kpi-label">Open cases</div>
        </div>
        <div className="kpi-tile kpi-accent-critical">
          <div className="kpi-icon"><IconAlerts width={16} height={16} /></div>
          <div className="kpi-value">{stats.criticalRisk}</div>
          <div className="kpi-label">Critical risk</div>
        </div>
        <div className="kpi-tile kpi-accent-warning">
          <div className="kpi-icon"><IconQueue width={16} height={16} /></div>
          <div className="kpi-value">{stats.pendingReview}</div>
          <div className="kpi-label">Pending AI review</div>
        </div>
        <div className="kpi-tile kpi-accent-good">
          <div className="kpi-icon"><IconHealth width={16} height={16} /></div>
          <div className="kpi-value">{stats.totalAlerts}</div>
          <div className="kpi-label">Alerts ingested</div>
        </div>
        <div className="kpi-tile">
          <div className="kpi-icon"><IconExclude width={16} height={16} /></div>
          <div className="kpi-value">{stats.excludedAlerts}</div>
          <div className="kpi-label">Excluded alerts</div>
        </div>
      </div>

      <div className="chart-grid">
        <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
          <h3>Alert volume</h3>
          <div className="chart-sub">Last 24 hours, hourly</div>
          <TrendChart data={stats.trend} title="Alert volume, last 24 hours, hourly" />
        </div>

        <div className="chart-card">
          <h3>Severity breakdown</h3>
          <div className="chart-sub">Cases by computed risk level</div>
          <BarList items={stats.severityBreakdown} />
        </div>

        <div className="chart-card">
          <h3>Case status</h3>
          <div className="chart-sub">Current workflow state</div>
          <BarList items={stats.caseStatusBreakdown} />
        </div>

        <div className="chart-card">
          <h3>Alert triage</h3>
          <div className="chart-sub">Where recent raw alerts ended up</div>
          <BarList items={stats.alertTriage} />
        </div>

        <div className="chart-card">
          <h3>Top source IPs</h3>
          <div className="chart-sub">By correlated alert count</div>
          <BarList items={stats.topIPs} />
        </div>

        <div className="chart-card">
          <h3>Top rules triggered</h3>
          <div className="chart-sub">Across all cases</div>
          <BarList items={stats.topRules} />
        </div>

        <div className="chart-card">
          <h3>MITRE ATT&CK tactics</h3>
          <div className="chart-sub">Across all cases</div>
          <BarList items={stats.mitre} />
        </div>
      </div>
    </div>
  )
}

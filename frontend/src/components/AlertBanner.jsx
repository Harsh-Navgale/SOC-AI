import { useEffect, useState } from 'react'
import { getActiveAlerts } from '../api.js'
import { useLiveEvents } from '../LiveConnectionContext.jsx'
import { IconClose } from './icons.jsx'

// Scheduler/correlator failure states, surfaced the moment they cross the failure threshold —
// this is the in-app half of alerting.py; the other half (an optional webhook) has no UI, it's
// configured purely via ALERT_WEBHOOK_URL in .env. Dismissing a banner only hides it for this
// tab/session; it reappears on reload as long as the underlying alert is still active, since
// dismissal isn't the same thing as the problem being fixed.
export default function AlertBanner() {
  const [alerts, setAlerts] = useState([])
  const [dismissed, setDismissed] = useState(() => new Set())

  useEffect(() => {
    getActiveAlerts().then((r) => setAlerts(r.items)).catch(() => {})
  }, [])

  useLiveEvents('alert_triggered', (msg) => {
    setAlerts((prev) => [...prev.filter((a) => a.source !== msg.source), { source: msg.source, message: msg.message }])
    setDismissed((prev) => {
      const next = new Set(prev)
      next.delete(msg.source)
      return next
    })
  })

  useLiveEvents('alert_resolved', (msg) => {
    setAlerts((prev) => prev.filter((a) => a.source !== msg.source))
  })

  const visible = alerts.filter((a) => !dismissed.has(a.source))
  if (visible.length === 0) return null

  return (
    <div className="alert-banner-stack">
      {visible.map((a) => (
        <div className="alert-banner" key={a.source} role="alert">
          <span className="alert-banner-dot" />
          <span className="alert-banner-text">{a.message}</span>
          <button
            className="alert-banner-dismiss"
            onClick={() => setDismissed((prev) => new Set(prev).add(a.source))}
            title="Dismiss (reappears if still active on reload)"
          >
            <IconClose width={13} height={13} />
          </button>
        </div>
      ))}
    </div>
  )
}

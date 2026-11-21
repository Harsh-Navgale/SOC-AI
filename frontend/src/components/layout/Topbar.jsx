import { useEffect, useRef, useState } from 'react'
import { IconLogout, IconSun, IconMoon, IconChevronDown } from '../icons.jsx'
import { useAuth } from '../../AuthContext.jsx'
import { useLiveConnectionStatus } from '../../LiveConnectionContext.jsx'
import { getTheme, toggleTheme } from '../../theme.js'
import NotificationBell from '../NotificationBell.jsx'

const STATUS_LABEL = {
  connected: 'Live',
  connecting: 'Connecting...',
  disconnected: 'Reconnecting...',
}

// One clock, any zone — UTC is just the first entry here rather than a separate pinned clock,
// since every timestamp elsewhere in the app (alerts, cases, audit log) is UTC and worth keeping
// one tap away, but the analyst's own zone is what should be visible by default.
const TIMEZONES = [
  { id: 'UTC', label: 'UTC' },
  { id: 'Asia/Kolkata', label: 'IST' },
  { id: 'America/New_York', label: 'ET' },
  { id: 'America/Chicago', label: 'CT' },
  { id: 'America/Los_Angeles', label: 'PT' },
  { id: 'Europe/London', label: 'UK' },
  { id: 'Europe/Paris', label: 'CET' },
  { id: 'Asia/Dubai', label: 'GST' },
  { id: 'Asia/Singapore', label: 'SGT' },
  { id: 'Asia/Tokyo', label: 'JST' },
  { id: 'Australia/Sydney', label: 'AEST' },
]

const TZ_KEY = 'soc_topbar_tz'

function loadTz() {
  const saved = localStorage.getItem(TZ_KEY)
  return TIMEZONES.some((t) => t.id === saved) ? saved : 'Asia/Kolkata'
}

function TimezoneClock({ now }) {
  const [tz, setTz] = useState(loadTz)
  const [open, setOpen] = useState(false)
  const rootRef = useRef(null)

  useEffect(() => {
    const onDocClick = (e) => {
      if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false)
    }
    const onKeyDown = (e) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDocClick)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onDocClick)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [])

  const pick = (id) => {
    setTz(id)
    localStorage.setItem(TZ_KEY, id)
    setOpen(false)
  }

  const current = TIMEZONES.find((t) => t.id === tz) || TIMEZONES[0]
  const clockText = now.toLocaleTimeString('en-GB', { hour12: false, timeZone: current.id })

  return (
    <div className="tz-picker" ref={rootRef}>
      <button type="button" className="tz-trigger" onClick={() => setOpen((v) => !v)}>
        <span className="topbar-clock">{clockText}</span>
        <span className="tz-trigger-label">{current.label}</span>
        <IconChevronDown width={13} height={13} />
      </button>
      {open && (
        <div className="tz-menu">
          {TIMEZONES.map((t) => (
            <button
              type="button"
              key={t.id}
              className={`tz-menu-item ${t.id === tz ? 'active' : ''}`}
              onClick={() => pick(t.id)}
            >
              <span className="tz-menu-label">{t.label}</span>
              <span className="tz-menu-time">{now.toLocaleTimeString('en-GB', { hour12: false, timeZone: t.id })}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export default function Topbar({ title, onOpenIncident }) {
  const { username, role, logout } = useAuth()
  const [now, setNow] = useState(new Date())
  const [theme, setThemeState] = useState(getTheme())
  const liveStatus = useLiveConnectionStatus()

  useEffect(() => {
    const interval = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(interval)
  }, [])

  return (
    <header className="topbar">
      <div className="topbar-title">{title}</div>
      <div className="topbar-right">
        <span
          className={`live-status live-status--${liveStatus}`}
          title={liveStatus === 'connected' ? 'Live updates connected' : 'Live updates unavailable — falling back to periodic refresh'}
        >
          <span className="live-status-dot" />
          {STATUS_LABEL[liveStatus] || 'Reconnecting...'}
        </span>
        <TimezoneClock now={now} />
        <NotificationBell onOpenIncident={onOpenIncident} />
        <button
          className="icon-btn theme-toggle-btn"
          onClick={() => setThemeState(toggleTheme())}
          title={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
        >
          {theme === 'light' ? <IconMoon width={16} height={16} /> : <IconSun width={16} height={16} />}
        </button>
        <div className="topbar-user">
          <span>{username}</span>
          <span className="role-pill">{role}</span>
        </div>
        <button className="icon-btn" onClick={logout} title="Log out">
          <IconLogout width={16} height={16} />
        </button>
      </div>
    </header>
  )
}

import { useEffect, useRef, useState } from 'react'
import { getNotifications, markNotificationRead, markAllNotificationsRead } from '../api.js'
import { useLiveEvents } from '../LiveConnectionContext.jsx'
import { IconBell } from './icons.jsx'

function formatRelativeTime(iso) {
  const diffSeconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (diffSeconds < 60) return 'just now'
  const minutes = Math.floor(diffSeconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

// Case assignment + case-aging notifications. Same custom-dropdown shape as the timezone
// picker (trigger button + outside-click-to-close menu) for a consistent topbar feel.
export default function NotificationBell({ onOpenIncident }) {
  const [items, setItems] = useState([])
  const [unread, setUnread] = useState(0)
  const [open, setOpen] = useState(false)
  const rootRef = useRef(null)

  const load = () => getNotifications().then((r) => { setItems(r.items); setUnread(r.unread) }).catch(() => {})

  useEffect(() => {
    load()
    const interval = setInterval(load, 20000)
    return () => clearInterval(interval)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useLiveEvents('notifications_changed', load)

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

  const handleClickItem = async (n) => {
    if (!n.read) {
      await markNotificationRead(n._id).catch(() => {})
      load()
    }
    if (n.incident_id && onOpenIncident) {
      onOpenIncident(n.incident_id)
      setOpen(false)
    }
  }

  const handleMarkAll = async () => {
    await markAllNotificationsRead().catch(() => {})
    load()
  }

  return (
    <div className="tz-picker" ref={rootRef}>
      <button type="button" className="tz-trigger notif-trigger" onClick={() => setOpen((v) => !v)} title="Notifications">
        <IconBell width={15} height={15} />
        {unread > 0 && <span className="notif-badge">{unread > 9 ? '9+' : unread}</span>}
      </button>
      {open && (
        <div className="tz-menu notif-menu">
          <div className="notif-menu-header">
            <span>Notifications</span>
            {unread > 0 && (
              <button type="button" className="context-toggle" onClick={handleMarkAll}>Mark all read</button>
            )}
          </div>
          {items.length === 0 && <p className="muted notif-empty">No notifications yet.</p>}
          {items.map((n) => (
            <button
              type="button"
              key={n._id}
              className={`notif-item ${n.read ? '' : 'unread'}`}
              onClick={() => handleClickItem(n)}
            >
              <span className="notif-item-message">{n.message}</span>
              <span className="notif-item-time">{formatRelativeTime(n.created_at)}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

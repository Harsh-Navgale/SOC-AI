import { createContext, useContext, useEffect, useRef, useState } from 'react'

const TOKEN_KEY = 'soc_token'
const RETRY_MS = 4000

const LiveConnectionContext = createContext({ status: 'disconnected', subscribe: () => () => {} })

// One WebSocket connection for the whole dashboard, not one per page. Every page that wants
// live updates subscribes to this shared socket instead of opening its own — cheaper on the
// backend's connection set, and it's what lets a single "Live" indicator in the topbar reflect
// the app's real connection state rather than whichever page happens to be open.
export function LiveConnectionProvider({ children }) {
  const [status, setStatus] = useState('connecting')
  const listenersRef = useRef(new Set())

  useEffect(() => {
    const token = localStorage.getItem(TOKEN_KEY)
    if (!token) {
      setStatus('disconnected')
      return undefined
    }

    let ws
    let closedByUs = false
    let retryTimer

    const connect = () => {
      setStatus('connecting')
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      ws = new WebSocket(`${proto}://${window.location.host}/api/ws/events?token=${encodeURIComponent(token)}`)
      ws.onopen = () => setStatus('connected')
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          listenersRef.current.forEach((fn) => fn(msg))
        } catch {
          // Ignore malformed frames — worst case one listener misses a refresh ping.
        }
      }
      ws.onclose = () => {
        setStatus('disconnected')
        if (!closedByUs) retryTimer = setTimeout(connect, RETRY_MS)
      }
      ws.onerror = () => ws.close()
    }
    connect()

    return () => {
      closedByUs = true
      clearTimeout(retryTimer)
      ws?.close()
    }
  }, [])

  const subscribe = (eventType, callback) => {
    const fn = (msg) => {
      if (!eventType || msg.type === eventType) callback(msg)
    }
    listenersRef.current.add(fn)
    return () => listenersRef.current.delete(fn)
  }

  return (
    <LiveConnectionContext.Provider value={{ status, subscribe }}>
      {children}
    </LiveConnectionContext.Provider>
  )
}

export function useLiveConnectionStatus() {
  return useContext(LiveConnectionContext).status
}

// Drop-in replacement for the old per-component hook of the same name — same call shape
// (eventType, onEvent) — but now rides the one shared connection above.
export function useLiveEvents(eventType, onEvent) {
  const { subscribe } = useContext(LiveConnectionContext)
  const onEventRef = useRef(onEvent)
  onEventRef.current = onEvent

  useEffect(() => subscribe(eventType, (msg) => onEventRef.current(msg)), [eventType, subscribe])
}

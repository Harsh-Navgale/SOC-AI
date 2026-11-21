import { useEffect, useState } from 'react'
import { getDebugMode } from './api.js'

// Read-only check used by IncidentDetail/AIChat to decide whether to show raw AI prompt/response
// tracing. One fetch per mount is enough — debug mode is an admin flipping a rare troubleshooting
// switch, not something that needs live push updates into every open tab.
export function useDebugMode() {
  const [enabled, setEnabled] = useState(false)

  useEffect(() => {
    getDebugMode().then((r) => setEnabled(r.enabled)).catch(() => {})
  }, [])

  return enabled
}

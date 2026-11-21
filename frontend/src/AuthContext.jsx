import { createContext, useContext, useEffect, useState } from 'react'
import { isAuthenticated, getRole, getUsername, logout as apiLogout, refreshToken } from './api.js'

// Well inside the 12h token TTL, so a session gets several silent-renewal attempts before it
// would otherwise expire mid-shift — one missed attempt (laptop asleep, brief network blip)
// still leaves plenty of runway before the token actually lapses.
const REFRESH_INTERVAL_MS = 45 * 60 * 1000

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [authed, setAuthed] = useState(isAuthenticated())
  const [role, setRole] = useState(getRole())
  const [username, setUsername] = useState(getUsername())

  useEffect(() => {
    const onExpired = () => {
      setAuthed(false)
      setRole(null)
      setUsername(null)
    }
    window.addEventListener('soc-auth-expired', onExpired)
    return () => window.removeEventListener('soc-auth-expired', onExpired)
  }, [])

  useEffect(() => {
    if (!authed) return undefined
    const interval = setInterval(() => {
      refreshToken().catch(() => {})
    }, REFRESH_INTERVAL_MS)
    return () => clearInterval(interval)
  }, [authed])

  const login = (newRole, newUsername) => {
    setAuthed(true)
    setRole(newRole)
    setUsername(newUsername)
  }

  const logout = () => {
    apiLogout()
    setAuthed(false)
    setRole(null)
    setUsername(null)
  }

  return (
    <AuthContext.Provider value={{ authed, role, username, isAdmin: role === 'admin', login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}

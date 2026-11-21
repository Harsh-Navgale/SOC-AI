import { useState } from 'react'
import { login as apiLogin } from '../api.js'
import { useAuth } from '../AuthContext.jsx'
import { IconIncidents, IconSparkle, IconAssets, IconUser, IconLock, IconEye, IconEyeOff, IconSun, IconMoon } from './icons.jsx'
import { getTheme, toggleTheme } from '../theme.js'

const FEATURES = [
  { icon: IconIncidents, text: 'Real-time alert correlation into cases' },
  { icon: IconSparkle, text: 'AI-assisted investigation & RAG knowledge base' },
  { icon: IconAssets, text: 'Unified Wazuh + cloud asset coverage' },
]

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [theme, setThemeState] = useState(getTheme())
  const { login } = useAuth()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const data = await apiLogin(username, password)
      login(data.role, username)
    } catch (err) {
      setError('Invalid username or password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-screen">
      <button
        className="icon-btn theme-toggle-btn theme-toggle-fixed"
        onClick={() => setThemeState(toggleTheme())}
        title={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
      >
        {theme === 'light' ? <IconMoon width={16} height={16} /> : <IconSun width={16} height={16} />}
      </button>
      <div className="login-hero">
        <div className="login-hero-content">
          <div className="login-brand">
            <span className="login-brand-dot" />
            <h1>SOC-AI</h1>
          </div>
          <p className="login-hero-tagline">
            A self-hosted, AI-augmented Security Operations Console &mdash; correlate alerts,
            investigate with your own knowledge base, and track coverage in one place.
          </p>
          <ul className="login-hero-features">
            {FEATURES.map(({ icon: Icon, text }, i) => (
              <li key={i}>
                <span className="login-hero-feature-icon"><Icon width={16} height={16} /></span>
                {text}
              </li>
            ))}
          </ul>
        </div>
        <div className="login-hero-glow" aria-hidden="true" />
      </div>

      <div className="login-form-panel">
        <form onSubmit={handleSubmit} className="login-form">
          <div className="login-form-header">
            <h2>Sign in</h2>
            <p className="subtitle">Enter your analyst credentials to continue</p>
          </div>

          <label className="input-with-icon">
            <IconUser width={16} height={16} />
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              autoFocus
              autoComplete="username"
            />
          </label>

          <label className="input-with-icon">
            <IconLock width={16} height={16} />
            <input
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="current-password"
            />
            <button
              type="button"
              className="input-icon-toggle"
              onClick={() => setShowPassword((v) => !v)}
              title={showPassword ? 'Hide password' : 'Show password'}
              tabIndex={-1}
            >
              {showPassword ? <IconEyeOff width={16} height={16} /> : <IconEye width={16} height={16} />}
            </button>
          </label>

          {error && <p className="login-error">{error}</p>}

          <button type="submit" className="login-submit" disabled={loading}>
            {loading ? <span className="thinking"><span /><span /><span /></span> : 'Sign in'}
          </button>

          <p className="login-footer">Self-hosted SOC copilot</p>
        </form>
      </div>
    </div>
  )
}

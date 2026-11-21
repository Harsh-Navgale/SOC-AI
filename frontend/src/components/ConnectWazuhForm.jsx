import { useState } from 'react'
import { setWazuhCredentials } from '../api.js'

export default function ConnectWazuhForm({ onConnected }) {
  const [host, setHost] = useState('')
  const [user, setUser] = useState('')
  const [password, setPassword] = useState('')
  const [verifySsl, setVerifySsl] = useState(true)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await setWazuhCredentials(host, user, password, verifySsl)
      onConnected()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card" style={{ maxWidth: 520 }}>
      <h3 style={{ margin: '0 0 10px' }}>Connect Wazuh Manager</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        Held in server memory only for 12 hours, never written to disk or Mongo &mdash; same as
        the AWS connection. You'll need to re-enter it after that.
      </p>
      <form onSubmit={handleSubmit} className="user-form" style={{ flexWrap: 'wrap' }}>
        <input aria-label="Wazuh Manager host URL" value={host} onChange={(e) => setHost(e.target.value)} placeholder="https://your-wazuh-manager:55000" style={{ flex: '1 1 100%' }} />
        <input aria-label="Wazuh API user" value={user} onChange={(e) => setUser(e.target.value)} placeholder="API user" style={{ flex: '1 1 48%' }} />
        <input aria-label="Wazuh API password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" style={{ flex: '1 1 48%' }} />
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-muted)' }}>
          <input type="checkbox" checked={verifySsl} onChange={(e) => setVerifySsl(e.target.checked)} style={{ width: 'auto' }} />
          Verify SSL certificate
        </label>
        <button type="submit" className="ask" disabled={loading}>{loading ? 'Connecting...' : 'Connect'}</button>
      </form>
      {error && <p className="login-error" style={{ marginTop: 10 }}>{error}</p>}
    </div>
  )
}

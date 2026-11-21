import { useState } from 'react'
import { setAWSCredentials } from '../api.js'

export default function ConnectAWSForm({ onConnected }) {
  const [accessKeyId, setAccessKeyId] = useState('')
  const [secretAccessKey, setSecretAccessKey] = useState('')
  const [sessionToken, setSessionToken] = useState('')
  const [region, setRegion] = useState('us-east-1')
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await setAWSCredentials(accessKeyId, secretAccessKey, sessionToken, region)
      onConnected()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card" style={{ maxWidth: 520 }}>
      <h3 style={{ margin: '0 0 10px' }}>Connect AWS</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        Held in server memory only for 12 hours, never written to disk or Mongo. You'll need
        to re-enter it after that.
      </p>
      <p className="muted" style={{ marginTop: 0, fontSize: 12, lineHeight: 1.6 }}>
        Only SSO console access, no IAM user/role? Open your org's AWS access portal (the
        page you use to click into the Console) &rarr; the account for this bucket &rarr;
        <strong> "Command line or programmatic access"</strong> &rarr; copy the three values
        shown there in. They're temporary (usually valid 1&ndash;12h) &mdash; repeat this
        once a session expires, same as the <span className="mono">s3_daily_digest</span> cron job.
      </p>
      <form onSubmit={handleSubmit} className="user-form" style={{ flexWrap: 'wrap' }}>
        <input aria-label="AWS access key ID" value={accessKeyId} onChange={(e) => setAccessKeyId(e.target.value)} placeholder="AWS_ACCESS_KEY_ID" style={{ flex: '1 1 100%' }} />
        <input aria-label="AWS secret access key" value={secretAccessKey} onChange={(e) => setSecretAccessKey(e.target.value)} placeholder="AWS_SECRET_ACCESS_KEY" type="password" style={{ flex: '1 1 100%' }} />
        <input aria-label="AWS session token" value={sessionToken} onChange={(e) => setSessionToken(e.target.value)} placeholder="AWS_SESSION_TOKEN" type="password" style={{ flex: '1 1 100%' }} />
        <input aria-label="AWS region" value={region} onChange={(e) => setRegion(e.target.value)} placeholder="AWS_DEFAULT_REGION" style={{ width: 180 }} />
        <button type="submit" className="ask" disabled={loading}>{loading ? 'Connecting...' : 'Connect'}</button>
      </form>
      {error && <p className="login-error" style={{ marginTop: 10 }}>{error}</p>}
    </div>
  )
}

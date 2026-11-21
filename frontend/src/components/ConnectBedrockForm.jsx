import { useState } from 'react'
import { setBedrockCredentials, setBedrockApiKey } from '../api.js'

export default function ConnectBedrockForm({ onConnected }) {
  const [mode, setMode] = useState('api_key') // 'api_key' | 'iam'
  const [apiKey, setApiKey] = useState('')
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
      if (mode === 'api_key') {
        await setBedrockApiKey(apiKey, region)
      } else {
        await setBedrockCredentials(accessKeyId, secretAccessKey, sessionToken, region)
      }
      onConnected()
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card" style={{ maxWidth: 520 }}>
      <h3 style={{ margin: '0 0 10px' }}>Connect Bedrock</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        A separate connection from the AWS one used for S3 asset inventory &mdash; use a
        different account/role here if Bedrock model access lives elsewhere. Held in server
        memory only for 12 hours, never written to disk or Mongo. You'll need to re-enter it
        after that.
      </p>
      <p className="muted" style={{ marginTop: 0, fontSize: 12, lineHeight: 1.6 }}>
        Model access no longer needs a separate approval step in the Bedrock console &mdash;
        AWS made all serverless models (including every Nova model) available by default in
        September 2025. A valid connection below is enough on its own.
      </p>

      <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
        <button
          type="button"
          className={mode === 'api_key' ? 'ask' : 'btn-outline'}
          onClick={() => setMode('api_key')}
        >
          API key
        </button>
        <button
          type="button"
          className={mode === 'iam' ? 'ask' : 'btn-outline'}
          onClick={() => setMode('iam')}
        >
          IAM access key
        </button>
      </div>

      <form onSubmit={handleSubmit} className="user-form" style={{ flexWrap: 'wrap' }}>
        {mode === 'api_key' ? (
          <>
            <p className="muted" style={{ marginTop: 0, fontSize: 12 }}>
              Generate one in the Bedrock console under "API keys" &mdash; simpler to create and
              rotate than a full IAM access key/secret pair.
            </p>
            <input aria-label="Bedrock API key" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="Bedrock API key" type="password" style={{ flex: '1 1 100%' }} />
          </>
        ) : (
          <>
            <input aria-label="AWS access key ID" value={accessKeyId} onChange={(e) => setAccessKeyId(e.target.value)} placeholder="AWS_ACCESS_KEY_ID" style={{ flex: '1 1 100%' }} />
            <input aria-label="AWS secret access key" value={secretAccessKey} onChange={(e) => setSecretAccessKey(e.target.value)} placeholder="AWS_SECRET_ACCESS_KEY" type="password" style={{ flex: '1 1 100%' }} />
            <input aria-label="AWS session token (optional)" value={sessionToken} onChange={(e) => setSessionToken(e.target.value)} placeholder="AWS_SESSION_TOKEN (optional)" type="password" style={{ flex: '1 1 100%' }} />
          </>
        )}
        <input aria-label="Bedrock region" value={region} onChange={(e) => setRegion(e.target.value)} placeholder="Bedrock region" style={{ width: 180 }} />
        <button type="submit" className="ask" disabled={loading}>{loading ? 'Connecting...' : 'Connect'}</button>
      </form>
      {error && <p className="login-error" style={{ marginTop: 10 }}>{error}</p>}
    </div>
  )
}

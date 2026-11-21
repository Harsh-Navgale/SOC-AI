import { useEffect, useRef, useState } from 'react'
import { runEval, getLatestEvalReport } from '../api.js'
import EmptyState from './EmptyState.jsx'
import { IconTarget } from './icons.jsx'
import { useToast } from '../ToastContext.jsx'

const DISPOSITIONS = ['true_positive', 'false_positive', 'benign_positive']
const COLUMNS = [...DISPOSITIONS, 'needs_review', 'unparsed']

function pct(fraction) {
  if (fraction === null || fraction === undefined) return <span className="muted">&mdash;</span>
  return `${Math.round(fraction * 100)}%`
}

export default function EvalReport() {
  const [report, setReport] = useState(null)
  const [sampleSize, setSampleSize] = useState(10)
  const [starting, setStarting] = useState(false)
  const { showToast } = useToast()
  const pollRef = useRef(null)

  const load = () => {
    getLatestEvalReport()
      .then(setReport)
      .catch((e) => {
        // api.js's request() throws a plain Error with no status code attached — the backend's
        // 404 detail text is the only signal distinguishing "never run" from a real failure.
        if (e.message === 'No eval run has ever been started') setReport({ status: 'never_run' })
        else showToast(e.message)
      })
  }

  useEffect(() => {
    load()
    return () => clearInterval(pollRef.current)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (report?.status === 'running') {
      pollRef.current = setInterval(load, 2000)
      return () => clearInterval(pollRef.current)
    }
  }, [report?.status])

  const handleRun = async () => {
    setStarting(true)
    try {
      await runEval(Number(sampleSize))
      load()
    } catch (e) {
      showToast(e.message)
    } finally {
      setStarting(false)
    }
  }

  const loading = report === null

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>AI verdict accuracy</h2>
      </div>
      <p className="muted" style={{ marginTop: -8, marginBottom: 16, fontSize: 12.5 }}>
        Re-runs the investigation on a random sample of already-closed incidents (excluding each
        one's own confirmed disposition from retrieval) and compares the fresh verdict against
        what an analyst actually confirmed. This makes real, billed AI calls — see the monthly
        budget cap on the Ask AI tab before running a large sample.
      </p>

      <div className="card" style={{ maxWidth: 480, marginBottom: 20 }}>
        <h3 style={{ margin: '0 0 10px' }}>Run a new eval</h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <input
            type="number" min="1" max="200" value={sampleSize}
            onChange={(e) => setSampleSize(e.target.value)}
            disabled={starting || report?.status === 'running'}
            style={{ width: 90 }}
          />
          <button
            className="ask" onClick={handleRun}
            disabled={starting || report?.status === 'running' || !sampleSize}
          >
            {report?.status === 'running' ? 'Running…' : starting ? 'Starting…' : 'Run eval'}
          </button>
        </div>
        <p className="muted" style={{ marginTop: 10, marginBottom: 0, fontSize: 11.5 }}>
          Each sampled incident is one full AI investigation — a sample of {sampleSize || 0}
          costs roughly {sampleSize || 0}&times; a normal investigation's cost.
        </p>
      </div>

      {loading ? (
        <p className="muted">Loading...</p>
      ) : report.status === 'never_run' ? (
        <EmptyState icon={IconTarget} title="No eval has run yet" subtitle="Run one above to measure AI verdict accuracy against confirmed dispositions." />
      ) : report.status === 'running' ? (
        <p className="muted">Eval in progress (sample of {report.sample_size_requested})...</p>
      ) : report.status === 'error' ? (
        <p className="login-error">Last eval run failed: {report.error}</p>
      ) : (
        <>
          <div className="stat-row" style={{ marginBottom: 20 }}>
            <div className="stat-tile">
              <div className="stat-value">{pct(report.agreement_rate)}</div>
              <div className="stat-label">Agreement rate</div>
            </div>
            <div className="stat-tile">
              <div className="stat-value">{report.sample_size_scored}</div>
              <div className="stat-label">Incidents scored</div>
            </div>
            <div className="stat-tile">
              <div className="stat-value">{report.errors}</div>
              <div className="stat-label">Investigation errors</div>
            </div>
          </div>

          <h3 style={{ marginBottom: 8 }}>Confusion matrix</h3>
          <p className="muted" style={{ marginTop: 0, marginBottom: 12, fontSize: 12 }}>
            Rows are the human-confirmed disposition; columns are the AI's fresh verdict on
            re-investigation. The diagonal (confirmed disposition = AI verdict) is the agreement.
          </p>
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>Confirmed disposition</th>
                  {COLUMNS.map((c) => <th key={c}>{c.replace(/_/g, ' ')}</th>)}
                </tr>
              </thead>
              <tbody>
                {DISPOSITIONS.map((disposition) => (
                  <tr key={disposition}>
                    <td><strong>{disposition.replace(/_/g, ' ')}</strong></td>
                    {COLUMNS.map((verdict) => (
                      <td key={verdict} className="mono" style={verdict === disposition ? { fontWeight: 700 } : undefined}>
                        {report.confusion_matrix[disposition][verdict]}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted" style={{ marginTop: 12, fontSize: 11.5 }}>
            Last run: {new Date(report.finished_at).toLocaleString()}
          </p>
        </>
      )}
    </div>
  )
}

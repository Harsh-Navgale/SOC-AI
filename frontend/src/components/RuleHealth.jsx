import { useEffect, useState, Fragment } from 'react'
import { getRuleHealth } from '../api.js'
import { SkeletonRows } from './Skeleton.jsx'
import EmptyState from './EmptyState.jsx'
import { IconHealth, IconCopy } from './icons.jsx'
import { useToast } from '../ToastContext.jsx'

function pct(fraction) {
  if (fraction === null || fraction === undefined) return <span className="muted">&mdash;</span>
  return `${Math.round(fraction * 100)}%`
}

// rule_key (correlator.py) is Wazuh's own numeric rule.id when the triggering alert had one,
// falling back to the rule description text only when it didn't — <if_sid> below needs a real
// numeric id, so this is the same check used to decide whether a snippet can be offered at all.
function isNumericRuleId(id) {
  return /^\d+$/.test(id)
}

function suppressionSnippet(row) {
  const count = row.confirmed_false_positive
  return `<!-- Wazuh custom rule override — add to /var/ossec/etc/rules/local_rules.xml on the
     manager, then restart it. level="0" fully suppresses the alert; use a lower non-zero
     level instead to keep logging it without raising an alert. Pick a real unused id >= 100000
     for your own ruleset — 100000 here is only a placeholder. -->
<rule id="100000" level="0">
  <if_sid>${row._id}</if_sid>
  <description>Confirmed false positive: ${row.rule_description || row._id} (SOC-AI Rule Health, ${count} confirmed FP${count === 1 ? '' : 's'})</description>
</rule>`
}

export default function RuleHealth() {
  const [rows, setRows] = useState(null)
  const [expandedId, setExpandedId] = useState(null)
  const [copiedId, setCopiedId] = useState(null)
  const { showToast } = useToast()

  const handleCopy = (row) => {
    navigator.clipboard.writeText(suppressionSnippet(row))
    setCopiedId(row._id)
    setTimeout(() => setCopiedId(null), 1500)
  }

  useEffect(() => {
    getRuleHealth().then(setRows).catch((e) => {
      showToast(e.message)
      setRows([])
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const loading = rows === null

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>{loading ? 'Loading rule health...' : `${rows.length} rule${rows.length === 1 ? '' : 's'} with confirmed closures`}</h2>
      </div>
      <p className="muted" style={{ marginTop: -8, marginBottom: 16, fontSize: 12.5 }}>
        Confirmed FP/TP/Benign counts come only from an analyst's confirmed disposition at case
        close — real evidence a rule needs tuning, not a single AI guess. The "AI flagged" column
        is the model's own, unconfirmed opinion from each investigation and should be read as a
        secondary signal only.
      </p>
      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Confirmed FP rate</th>
              <th>Confirmed FP</th>
              <th>Confirmed TP</th>
              <th>Confirmed benign</th>
              <th>AI flagged miscalibrated (unconfirmed)</th>
              <th>Suggested fix</th>
            </tr>
          </thead>
          <tbody>
            {loading && <SkeletonRows rows={6} columns={7} />}
            {!loading && rows.map((r) => (
              <Fragment key={r._id}>
                <tr>
                  <td>
                    <div style={{ fontWeight: 600 }}>{r.rule_description || r._id}</div>
                    <div className="muted mono" style={{ fontSize: 11 }}>{r._id}</div>
                  </td>
                  <td className="mono">{pct(r.confirmed_fp_rate)}</td>
                  <td className="mono">{r.confirmed_false_positive}</td>
                  <td className="mono">{r.confirmed_true_positive}</td>
                  <td className="mono">{r.confirmed_benign_positive}</td>
                  <td className="mono muted">
                    {r.ai_rule_health_total > 0
                      ? `${r.ai_flagged_miscalibrated}/${r.ai_rule_health_total} runs`
                      : <span className="muted">&mdash;</span>}
                  </td>
                  <td>
                    {r.confirmed_false_positive > 0 && isNumericRuleId(r._id) ? (
                      <button className="btn-outline" onClick={() => setExpandedId(expandedId === r._id ? null : r._id)}>
                        {expandedId === r._id ? 'Hide' : 'View snippet'}
                      </button>
                    ) : (
                      <span className="muted" style={{ fontSize: 12 }}>
                        {r.confirmed_false_positive > 0 ? 'No stable rule ID' : '—'}
                      </span>
                    )}
                  </td>
                </tr>
                {expandedId === r._id && (
                  <tr>
                    <td colSpan={7}>
                      <div className="investigation-report-header">
                        <button className="msg-copy" onClick={() => handleCopy(r)} title="Copy snippet">
                          {copiedId === r._id ? 'Copied' : <IconCopy width={13} height={13} />}
                        </button>
                      </div>
                      <pre className="full-log-line">{suppressionSnippet(r)}</pre>
                      <p className="muted" style={{ fontSize: 12, margin: '4px 0 0' }}>
                        This is a suggestion to review and apply yourself in Wazuh's own
                        ruleset — nothing here is applied automatically.
                      </p>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    icon={IconHealth}
                    title="No confirmed closures yet"
                    subtitle="Close a case with a confirmed disposition (true/false/benign positive) to start building rule-health evidence here."
                  />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

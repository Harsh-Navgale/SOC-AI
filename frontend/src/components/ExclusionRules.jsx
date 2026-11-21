import { useEffect, useState } from 'react'
import { getExclusionRules, createExclusionRule, updateExclusionRule, deleteExclusionRule } from '../api.js'
import { useToast } from '../ToastContext.jsx'
import { SkeletonCard } from './Skeleton.jsx'
import EmptyState from './EmptyState.jsx'
import { IconExclude } from './icons.jsx'

function criteriaText(criteria) {
  if (!criteria || criteria.length === 0) return 'No match criteria'
  return criteria.map((c) => `${c.field} ${c.operator} "${c.value}"`).join(' AND ')
}

export default function ExclusionRules() {
  const [rules, setRules] = useState(null)
  const [label, setLabel] = useState('')
  const [ruleId, setRuleId] = useState('')
  const [ruleDescription, setRuleDescription] = useState('')
  const [ip, setIp] = useState('')
  const [ipField, setIpField] = useState('source_ip')
  const [saving, setSaving] = useState(false)
  const [busyId, setBusyId] = useState(null)
  const { showToast } = useToast()

  const load = () => getExclusionRules().then(setRules).catch((err) => {
    showToast(err.message)
    setRules((prev) => prev ?? [])
  })

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const canSave = Boolean(ruleId.trim() || ruleDescription.trim() || ip.trim())

  const handleCreate = async (e) => {
    e.preventDefault()
    if (!canSave) return
    setSaving(true)
    try {
      await createExclusionRule({
        description: label.trim() || undefined,
        rule_id: ruleId.trim() || undefined,
        rule_description: ruleDescription.trim() || undefined,
        ip: ip.trim() || undefined,
        ip_field: ipField,
      })
      showToast('Exclusion rule saved.', 'success')
      setLabel('')
      setRuleId('')
      setRuleDescription('')
      setIp('')
      load()
    } catch (err) {
      showToast(err.message)
    } finally {
      setSaving(false)
    }
  }

  const handleToggle = async (rule) => {
    setBusyId(rule._id)
    try {
      await updateExclusionRule(rule._id, { active: !rule.active })
      load()
    } catch (err) {
      showToast(err.message)
    } finally {
      setBusyId(null)
    }
  }

  const handleDelete = async (rule) => {
    setBusyId(rule._id)
    try {
      await deleteExclusionRule(rule._id)
      showToast('Exclusion rule deleted.', 'success')
      load()
    } catch (err) {
      showToast(err.message)
    } finally {
      setBusyId(null)
    }
  }

  const loading = rules === null

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>{loading ? 'Loading rules...' : `${rules.length} exclusion rule${rules.length === 1 ? '' : 's'}`}</h2>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <h3 style={{ margin: '0 0 4px' }}>Add an exclusion rule</h3>
        <p className="muted" style={{ margin: '0 0 12px', fontSize: 12 }}>
          Fill in any combination — all given fields must match together (AND) for an alert to be excluded.
        </p>
        <form onSubmit={handleCreate} className="toolbar-actions">
          <input
            className="search-input"
            style={{ minWidth: 140, flex: '1 1 140px' }}
            value={ruleId}
            onChange={(e) => setRuleId(e.target.value)}
            placeholder="Rule ID"
          />
          <input
            className="search-input"
            style={{ minWidth: 200, flex: '2 1 200px' }}
            value={ruleDescription}
            onChange={(e) => setRuleDescription(e.target.value)}
            placeholder="Rule description contains..."
          />
          <input
            className="search-input"
            style={{ minWidth: 140, flex: '1 1 140px' }}
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="IP address"
          />
          <select value={ipField} onChange={(e) => setIpField(e.target.value)} className="filter-select">
            <option value="source_ip">Source IP</option>
            <option value="agent.ip">Agent IP</option>
          </select>
          <input
            className="search-input"
            style={{ minWidth: 160, flex: '1 1 160px' }}
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Label (optional)"
          />
          <button type="submit" className="ask" disabled={saving || !canSave}>
            {saving ? 'Saving...' : 'Add rule'}
          </button>
        </form>
      </div>

      {loading && <SkeletonCard lines={4} />}

      {!loading && rules.length === 0 && (
        <EmptyState
          icon={IconExclude}
          title="No exclusion rules yet"
          subtitle="Add one above to keep known-noisy alerts from ever becoming a case."
        />
      )}

      {!loading && rules.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {rules.map((rule) => (
            <div className="card" key={rule._id}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
                <div style={{ minWidth: 0 }}>
                  <p style={{ margin: '0 0 4px', fontWeight: 600 }}>{rule.description}</p>
                  <p className="muted mono" style={{ margin: 0, fontSize: 12 }}>{criteriaText(rule.criteria)}</p>
                  <p className="muted" style={{ margin: '6px 0 0', fontSize: 11 }}>
                    Added by {rule.created_by} &middot; {rule.created_at}
                  </p>
                </div>
                <div style={{ display: 'flex', gap: 8, flexShrink: 0, alignItems: 'center' }}>
                  <span className={`status-badge`} style={{ color: rule.active ? 'var(--good)' : 'var(--text-muted)', borderColor: rule.active ? 'var(--good)' : 'var(--border-strong)' }}>
                    {rule.active ? 'Active' : 'Disabled'}
                  </span>
                  <button className="btn-outline" onClick={() => handleToggle(rule)} disabled={busyId === rule._id}>
                    {rule.active ? 'Disable' : 'Enable'}
                  </button>
                  <button className="danger-link" onClick={() => handleDelete(rule)} disabled={busyId === rule._id}>
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

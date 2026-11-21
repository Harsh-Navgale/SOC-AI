export default function RiskBadge({ risk }) {
  if (!risk) return null
  return (
    <span
      className={`risk-badge risk-${risk.label}`}
      title={risk.threat_intel_included ? 'Includes cached threat-intel signal' : 'Based on Wazuh alert data only'}
    >
      <span className="risk-badge-dot" />
      {risk.score} &middot; {risk.label}
    </span>
  )
}

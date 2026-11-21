export default function EmptyState({ icon: Icon, title, subtitle }) {
  return (
    <div className="empty-state">
      {Icon && <Icon width={26} height={26} className="empty-state-icon" />}
      <div className="empty-state-title">{title}</div>
      {subtitle && <div className="empty-state-subtitle">{subtitle}</div>}
    </div>
  )
}

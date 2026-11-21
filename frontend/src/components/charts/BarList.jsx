export default function BarList({ items }) {
  if (!items || items.length === 0) {
    return <div className="chart-empty">No data yet</div>
  }

  const max = Math.max(1, ...items.map((i) => i.value))

  return (
    <div className="barlist">
      {items.map((item) => (
        <div className="barlist-row" key={item.label}>
          <div className="barlist-label" title={item.label}>{item.label}</div>
          <div className="barlist-track">
            <div
              className="barlist-fill"
              style={{ width: `${Math.max(3, (item.value / max) * 100)}%`, background: item.color || 'var(--accent)' }}
            />
          </div>
          <div className="barlist-value">{item.value}</div>
        </div>
      ))}
    </div>
  )
}

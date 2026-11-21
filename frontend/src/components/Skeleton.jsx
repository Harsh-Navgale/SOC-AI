export function SkeletonRows({ rows = 5, columns = 4 }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, r) => (
        <tr key={r}>
          {Array.from({ length: columns }).map((_, c) => (
            <td key={c}>
              <div className="skeleton skeleton-text" style={{ width: `${55 + ((r + c) % 3) * 15}%` }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

export function SkeletonKpiRow({ count = 4 }) {
  return (
    <div className="kpi-row">
      {Array.from({ length: count }).map((_, i) => (
        <div className="kpi-tile" key={i}>
          <div className="skeleton skeleton-text" style={{ width: '50%', height: 24, marginBottom: 8 }} />
          <div className="skeleton skeleton-text" style={{ width: '70%', height: 10 }} />
        </div>
      ))}
    </div>
  )
}

export function SkeletonCard({ lines = 3 }) {
  return (
    <div className="card">
      <div className="skeleton skeleton-text" style={{ width: '35%', height: 14, marginBottom: 12 }} />
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className="skeleton skeleton-text"
          style={{ width: `${90 - i * 15}%`, height: 10, marginBottom: 6 }}
        />
      ))}
    </div>
  )
}

export function SkeletonBlock({ height = 160 }) {
  return <div className="skeleton" style={{ width: '100%', height }} />
}

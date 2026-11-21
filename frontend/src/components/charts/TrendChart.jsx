import { useRef, useState } from 'react'

const W = 600
const H = 160
const PAD_TOP = 10
const PAD_BOTTOM = 22

export default function TrendChart({ data, color = 'var(--accent)', title = 'Trend chart' }) {
  const wrapRef = useRef(null)
  const [hover, setHover] = useState(null)

  if (!data || data.length === 0) {
    return <div className="chart-empty">No data yet</div>
  }

  const innerH = H - PAD_TOP - PAD_BOTTOM
  const max = Math.max(1, ...data.map((d) => d.value)) * 1.15
  const stepX = data.length > 1 ? W / (data.length - 1) : 0

  const points = data.map((d, i) => ({
    ...d,
    x: data.length > 1 ? i * stepX : W / 2,
    y: PAD_TOP + innerH - (d.value / max) * innerH,
  }))

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')
  const baseline = H - PAD_BOTTOM
  const areaPath = `${linePath} L ${points[points.length - 1].x.toFixed(1)},${baseline} L ${points[0].x.toFixed(1)},${baseline} Z`
  const last = points[points.length - 1]

  const handleMove = (e) => {
    if (!wrapRef.current) return
    const rect = wrapRef.current.getBoundingClientRect()
    const ratio = Math.min(1, Math.max(0, (e.clientX - rect.left) / rect.width))
    const idx = data.length > 1 ? Math.round(ratio * (data.length - 1)) : 0
    setHover(idx)
  }

  const hoveredPoint = hover !== null ? points[hover] : null

  // Keyboard equivalent of hovering a point with the mouse — for sighted keyboard users. Screen
  // reader users get the full dataset unconditionally via the hidden table below instead, since
  // that doesn't depend on moving focus point-by-point.
  const handleKeyDown = (e) => {
    if (e.key === 'ArrowRight') {
      e.preventDefault()
      setHover((prev) => Math.min(data.length - 1, (prev ?? -1) + 1))
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault()
      setHover((prev) => Math.max(0, (prev ?? data.length) - 1))
    } else if (e.key === 'Escape') {
      setHover(null)
    }
  }

  return (
    <div
      className="trend-wrap"
      ref={wrapRef}
      style={{ position: 'relative' }}
      onMouseMove={handleMove}
      onMouseLeave={() => setHover(null)}
      tabIndex={0}
      role="group"
      aria-label={`${title}. Use the left and right arrow keys to inspect each point.`}
      onFocus={() => setHover((prev) => prev ?? data.length - 1)}
      onBlur={() => setHover(null)}
      onKeyDown={handleKeyDown}
    >
      {/* The visual chart is presentation only — its data is fully available, unconditionally,
          via the .sr-only table below, so screen readers don't need this element at all. */}
      <svg aria-hidden="true" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" width="100%" height={H}>
        {[0.25, 0.5, 0.75].map((f) => (
          <line
            key={f}
            x1={0} x2={W}
            y1={PAD_TOP + innerH * f} y2={PAD_TOP + innerH * f}
            stroke="var(--border)" strokeWidth="1"
          />
        ))}
        <path d={areaPath} fill={color} fillOpacity="0.1" stroke="none" />
        <path d={linePath} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx={last.x} cy={last.y} r="4" fill={color} stroke="var(--bg-surface)" strokeWidth="2" />
        {hoveredPoint && (
          <>
            <line
              x1={hoveredPoint.x} x2={hoveredPoint.x}
              y1={PAD_TOP} y2={baseline}
              stroke="var(--border-strong)" strokeWidth="1"
            />
            <circle cx={hoveredPoint.x} cy={hoveredPoint.y} r="4" fill={color} stroke="var(--bg-surface)" strokeWidth="2" />
          </>
        )}
      </svg>
      {hoveredPoint && (
        <div
          className="trend-tooltip"
          aria-hidden="true"
          style={{ left: `${(hoveredPoint.x / W) * 100}%`, top: `${(hoveredPoint.y / H) * 100}%` }}
        >
          <div className="trend-tooltip-label">{hoveredPoint.label}</div>
          <div className="trend-tooltip-value">{hoveredPoint.value}</div>
        </div>
      )}
      {/* Full data, always available to screen readers regardless of keyboard focus — doesn't
          depend on stepping through points one at a time like the visual tooltip above does. */}
      <table className="sr-only">
        <caption>{title}</caption>
        <thead>
          <tr><th scope="col">Time</th><th scope="col">Value</th></tr>
        </thead>
        <tbody>
          {data.map((d, i) => (
            <tr key={i}><td>{d.label}</td><td>{d.value}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

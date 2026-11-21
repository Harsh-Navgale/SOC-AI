import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import RiskBadge from './RiskBadge.jsx'

describe('RiskBadge', () => {
  it('renders nothing when no risk is provided', () => {
    const { container } = render(<RiskBadge risk={null} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the score and label', () => {
    render(<RiskBadge risk={{ score: 72, label: 'high', threat_intel_included: false }} />)
    expect(screen.getByText(/72/)).toBeInTheDocument()
    expect(screen.getByText(/high/)).toBeInTheDocument()
  })

  it('applies the risk-level-specific class', () => {
    const { container } = render(<RiskBadge risk={{ score: 10, label: 'low' }} />)
    expect(container.querySelector('.risk-low')).toBeInTheDocument()
  })

  it('notes when the score includes cached threat-intel signal', () => {
    render(<RiskBadge risk={{ score: 90, label: 'critical', threat_intel_included: true }} />)
    expect(screen.getByText(/90/).closest('.risk-badge')).toHaveAttribute(
      'title', 'Includes cached threat-intel signal',
    )
  })
})

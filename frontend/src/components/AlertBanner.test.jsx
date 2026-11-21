import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import AlertBanner from './AlertBanner.jsx'
import * as api from '../api.js'

vi.mock('../api.js')

describe('AlertBanner', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders nothing when there are no active alerts', async () => {
    api.getActiveAlerts.mockResolvedValue({ items: [] })

    const { container } = render(<AlertBanner />)
    await waitFor(() => expect(api.getActiveAlerts).toHaveBeenCalled())

    expect(container).toBeEmptyDOMElement()
  })

  it('shows an alert fetched on mount', async () => {
    api.getActiveAlerts.mockResolvedValue({
      items: [{ source: 'poll_wazuh', message: 'poll_wazuh has failed 3 times in a row: unreachable' }],
    })

    render(<AlertBanner />)

    expect(await screen.findByText(/poll_wazuh has failed 3 times/)).toBeInTheDocument()
  })

  it('dismisses a banner locally without waiting on the server', async () => {
    api.getActiveAlerts.mockResolvedValue({
      items: [{ source: 'poll_wazuh', message: 'poll_wazuh has failed 3 times in a row: unreachable' }],
    })

    render(<AlertBanner />)
    await screen.findByText(/poll_wazuh has failed/)

    fireEvent.click(screen.getByTitle(/Dismiss/))

    await waitFor(() => expect(screen.queryByText(/poll_wazuh has failed/)).not.toBeInTheDocument())
  })

  it('shows multiple simultaneous alerts from different sources', async () => {
    api.getActiveAlerts.mockResolvedValue({
      items: [
        { source: 'poll_wazuh', message: 'poll_wazuh is down' },
        { source: 'correlator', message: 'correlator is stale' },
      ],
    })

    render(<AlertBanner />)

    expect(await screen.findByText('poll_wazuh is down')).toBeInTheDocument()
    expect(await screen.findByText('correlator is stale')).toBeInTheDocument()
  })
})

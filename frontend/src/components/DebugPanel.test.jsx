import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import DebugPanel from './DebugPanel.jsx'
import { ToastProvider } from '../ToastContext.jsx'
import * as api from '../api.js'

vi.mock('../api.js')

const DIAGNOSTICS = {
  debug_mode_enabled: false,
  enrichment_enabled: true,
  auto_investigate_enabled: true,
  correlation: { window_seconds: 300, threshold: 5 },
  integrations: { aws: { configured: false }, wazuh_manager: { configured: false }, threat_intel: {}, manual_agents: { configured: false } },
  correlator: { last_run: Date.now() / 1000, alerts_processed_total: 10 },
  wazuh_ingestion: { fetched: 42, truncated: false, at: new Date().toISOString() },
  ai_usage: {
    calls: 4, prompt_tokens: 800, completion_tokens: 200, estimated_cost: 0.0021, parse_failures: 1, parse_total: 4, parse_failure_rate: 0.25,
    month_to_date_cost: 0.0021, monthly_budget_cap: null,
  },
  active_alerts: [],
  recent_errors: [],
}

function renderPanel() {
  return render(
    <ToastProvider>
      <DebugPanel />
    </ToastProvider>,
  )
}

describe('DebugPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows the current debug mode status and AI usage stats', async () => {
    api.getDebugMode.mockResolvedValue({ enabled: false })
    api.getDebugDiagnostics.mockResolvedValue(DIAGNOSTICS)

    renderPanel()

    expect(await screen.findByText('OFF')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument() // calls
    expect(screen.getByText(/25\.0% \(1\/4\)/)).toBeInTheDocument()
  })

  it('toggles debug mode by clicking the switch', async () => {
    api.getDebugMode.mockResolvedValue({ enabled: false })
    api.getDebugDiagnostics.mockResolvedValue(DIAGNOSTICS)
    api.setDebugMode.mockResolvedValue({ enabled: true })

    renderPanel()
    await screen.findByText('OFF')

    fireEvent.click(screen.getByRole('switch'))

    await waitFor(() => expect(api.setDebugMode).toHaveBeenCalledWith(true))
    expect(await screen.findByText('ON')).toBeInTheDocument()
  })

  it('shows an "all clear" state when there are no active alerts', async () => {
    api.getDebugMode.mockResolvedValue({ enabled: false })
    api.getDebugDiagnostics.mockResolvedValue(DIAGNOSTICS)

    renderPanel()

    expect(await screen.findByText('All clear')).toBeInTheDocument()
  })

  it('lists active alerts when present', async () => {
    api.getDebugMode.mockResolvedValue({ enabled: false })
    api.getDebugDiagnostics.mockResolvedValue({
      ...DIAGNOSTICS,
      active_alerts: [{ source: 'poll_wazuh', message: 'poll_wazuh has failed 3 times in a row' }],
    })

    renderPanel()

    expect(await screen.findByText('1 active')).toBeInTheDocument()
    expect(screen.getByText('poll_wazuh has failed 3 times in a row')).toBeInTheDocument()
  })

  it('renders per-source pills for an integration with multiple configured flags', async () => {
    api.getDebugMode.mockResolvedValue({ enabled: false })
    api.getDebugDiagnostics.mockResolvedValue({
      ...DIAGNOSTICS,
      integrations: {
        ...DIAGNOSTICS.integrations,
        threat_intel: { virustotal_configured: true, abuseipdb_configured: false, abusech_configured: false },
      },
    })

    renderPanel()

    expect(await screen.findByText('virustotal: yes')).toBeInTheDocument()
    expect(screen.getByText('abuseipdb: no')).toBeInTheDocument()
  })
})

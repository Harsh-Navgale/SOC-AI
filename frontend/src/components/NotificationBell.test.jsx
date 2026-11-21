import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import NotificationBell from './NotificationBell.jsx'
import * as api from '../api.js'

vi.mock('../api.js')

describe('NotificationBell', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows the unread count badge', async () => {
    api.getNotifications.mockResolvedValue({
      items: [{ _id: '1', message: 'Assigned to you', created_at: new Date().toISOString(), read: false }],
      unread: 1,
    })

    render(<NotificationBell />)

    expect(await screen.findByText('1')).toBeInTheDocument()
  })

  it('shows no badge when nothing is unread', async () => {
    api.getNotifications.mockResolvedValue({ items: [], unread: 0 })

    render(<NotificationBell />)
    await waitFor(() => expect(api.getNotifications).toHaveBeenCalled())

    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })

  it('opens the dropdown, marks a clicked notification read, and opens its incident', async () => {
    api.getNotifications.mockResolvedValue({
      items: [{ _id: '1', message: 'Case assigned to you', created_at: new Date().toISOString(), read: false, incident_id: 'inc-1' }],
      unread: 1,
    })
    api.markNotificationRead.mockResolvedValue({ ok: true })
    const onOpenIncident = vi.fn()

    render(<NotificationBell onOpenIncident={onOpenIncident} />)
    await screen.findByText('1')

    fireEvent.click(screen.getByTitle('Notifications'))
    fireEvent.click(await screen.findByText('Case assigned to you'))

    await waitFor(() => expect(api.markNotificationRead).toHaveBeenCalledWith('1'))
    expect(onOpenIncident).toHaveBeenCalledWith('inc-1')
  })

  it('marks all notifications read', async () => {
    api.getNotifications.mockResolvedValue({
      items: [{ _id: '1', message: 'x', created_at: new Date().toISOString(), read: false }],
      unread: 1,
    })
    api.markAllNotificationsRead.mockResolvedValue({ ok: true })

    render(<NotificationBell />)
    await screen.findByText('1')
    fireEvent.click(screen.getByTitle('Notifications'))

    fireEvent.click(await screen.findByText('Mark all read'))

    await waitFor(() => expect(api.markAllNotificationsRead).toHaveBeenCalled())
  })

  it('shows an empty state when there are no notifications', async () => {
    api.getNotifications.mockResolvedValue({ items: [], unread: 0 })

    render(<NotificationBell />)
    await waitFor(() => expect(api.getNotifications).toHaveBeenCalled())
    fireEvent.click(screen.getByTitle('Notifications'))

    expect(await screen.findByText('No notifications yet.')).toBeInTheDocument()
  })
})

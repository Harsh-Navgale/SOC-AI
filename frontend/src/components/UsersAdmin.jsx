import { useEffect, useState } from 'react'
import { listUsers, createUser, deleteUser } from '../api.js'
import { useToast } from '../ToastContext.jsx'
import { SkeletonRows } from './Skeleton.jsx'
import EmptyState from './EmptyState.jsx'
import { IconUsers, IconTrash } from './icons.jsx'

export default function UsersAdmin() {
  const [users, setUsers] = useState(null)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('analyst')
  const [creating, setCreating] = useState(false)
  const { showToast } = useToast()

  const load = () => listUsers().then(setUsers).catch((e) => showToast(e.message))

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const handleCreate = async (e) => {
    e.preventDefault()
    setCreating(true)
    try {
      await createUser(username, password, role)
      showToast(`User "${username}" created.`, 'success')
      setUsername('')
      setPassword('')
      setRole('analyst')
      load()
    } catch (err) {
      showToast(err.message)
    } finally {
      setCreating(false)
    }
  }

  const handleDelete = async (name) => {
    try {
      await deleteUser(name)
      showToast(`User "${name}" deleted.`, 'success')
      load()
    } catch (err) {
      showToast(err.message)
    }
  }

  const loading = users === null

  return (
    <div className="content-fade-in">
      <div className="page-header">
        <h2>{loading ? 'Loading accounts...' : `${users.length} account${users.length === 1 ? '' : 's'}`}</h2>
      </div>
      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Role</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && <SkeletonRows rows={3} columns={4} />}
            {!loading && users.map((u) => (
              <tr key={u._id}>
                <td className="mono">{u._id}</td>
                <td><span className="role-pill">{u.role}</span></td>
                <td className="mono muted">{u.created_at}</td>
                <td>
                  <button className="icon-btn" onClick={() => handleDelete(u._id)} title={`Delete ${u._id}`}>
                    <IconTrash width={14} height={14} />
                  </button>
                </td>
              </tr>
            ))}
            {!loading && users.length === 0 && (
              <tr>
                <td colSpan={4}>
                  <EmptyState icon={IconUsers} title="No accounts" />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="card" style={{ marginTop: 18, maxWidth: 520 }}>
        <h3 style={{ margin: '0 0 10px' }}>Add user</h3>
        <form onSubmit={handleCreate} className="user-form">
          <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" />
          <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" />
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="analyst">analyst</option>
            <option value="admin">admin</option>
          </select>
          <button type="submit" className="ask" disabled={creating}>{creating ? 'Adding...' : 'Add'}</button>
        </form>
      </div>
    </div>
  )
}

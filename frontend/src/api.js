const API_BASE = import.meta.env.VITE_API_BASE || '/api'
const TOKEN_KEY = 'soc_token'
const ROLE_KEY = 'soc_role'
const USERNAME_KEY = 'soc_username'

function authHeaders() {
  const token = localStorage.getItem(TOKEN_KEY)
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(options.headers || {}),
    },
  })

  if (res.status === 401) {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(ROLE_KEY)
    localStorage.removeItem(USERNAME_KEY)
    window.dispatchEvent(new Event('soc-auth-expired'))
    throw new Error('Unauthorized')
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail || `Request to ${path} failed with ${res.status}`)
  }
  if (res.status === 204) return null
  return res.json()
}

async function requestMultipart(path, formData) {
  // Deliberately does NOT go through request()'s JSON Content-Type header — the browser
  // must set its own multipart boundary, so only the auth header is attached here.
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { ...authHeaders() },
    body: formData,
  })

  if (res.status === 401) {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(ROLE_KEY)
    localStorage.removeItem(USERNAME_KEY)
    window.dispatchEvent(new Event('soc-auth-expired'))
    throw new Error('Unauthorized')
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail || `Request to ${path} failed with ${res.status}`)
  }
  return res.json()
}

function requestMultipartWithProgress(path, formData, onProgress) {
  // XMLHttpRequest, not fetch — fetch's Response has no upload-progress event at all, and an
  // XHR's upload.onprogress is the only way to show real bytes-sent/total during a large (this
  // is specifically for multi-GB alert file imports) transfer instead of an indefinite spinner.
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${API_BASE}${path}`)
    const headers = authHeaders()
    for (const [key, value] of Object.entries(headers)) xhr.setRequestHeader(key, value)

    if (onProgress) {
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) onProgress(e.loaded, e.total)
      }
    }

    xhr.onload = () => {
      if (xhr.status === 401) {
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(ROLE_KEY)
        localStorage.removeItem(USERNAME_KEY)
        window.dispatchEvent(new Event('soc-auth-expired'))
        reject(new Error('Unauthorized'))
        return
      }
      let body = {}
      try {
        body = JSON.parse(xhr.responseText)
      } catch {
        // non-JSON error body (e.g. nginx's own 413 page) — body.detail below just stays absent
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body)
      } else {
        reject(new Error(body.detail || `Request to ${path} failed with ${xhr.status}`))
      }
    }
    xhr.onerror = () => reject(new Error(`Network error while uploading to ${path}`))
    xhr.send(formData)
  })
}

function uploadChunkWithProgress(path, blob, offset, onProgress) {
  // A raw binary PUT, not multipart — the resumable-upload chunk endpoint takes the chunk's
  // bytes directly as the request body, with the offset it starts at in a header (the server
  // checks this against what it's actually received so far, and rejects a mismatch rather than
  // silently writing to the wrong place in the file).
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('PUT', `${API_BASE}${path}`)
    const headers = authHeaders()
    for (const [key, value] of Object.entries(headers)) xhr.setRequestHeader(key, value)
    xhr.setRequestHeader('X-Upload-Offset', String(offset))
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')

    if (onProgress) {
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) onProgress(e.loaded, e.total)
      }
    }

    xhr.onload = () => {
      if (xhr.status === 401) {
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(ROLE_KEY)
        localStorage.removeItem(USERNAME_KEY)
        window.dispatchEvent(new Event('soc-auth-expired'))
        reject(new Error('Unauthorized'))
        return
      }
      let body = {}
      try {
        body = JSON.parse(xhr.responseText)
      } catch {
        // non-JSON error body — body.detail below just stays absent
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(body)
      } else {
        const err = new Error(body.detail || `Chunk upload failed with ${xhr.status}`)
        err.status = xhr.status
        err.body = body
        reject(err)
      }
    }
    xhr.onerror = () => reject(new Error(`Network error while uploading to ${path}`))
    xhr.send(blob)
  })
}

export async function login(username, password) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!res.ok) {
    throw new Error('Invalid username or password')
  }
  const data = await res.json()
  localStorage.setItem(TOKEN_KEY, data.access_token)
  localStorage.setItem(ROLE_KEY, data.role)
  localStorage.setItem(USERNAME_KEY, username)
  return data
}

// Silently extends a still-open session before its 12h token would expire mid-shift. Reuses
// request()'s existing 401 handling — if the current token already lapsed before this fires,
// the refresh call itself 401s and the normal soc-auth-expired flow kicks the user to login,
// same as any other API call would.
export async function refreshToken() {
  const data = await request('/auth/refresh', { method: 'POST' })
  localStorage.setItem(TOKEN_KEY, data.access_token)
  localStorage.setItem(ROLE_KEY, data.role)
  return data
}

export function logout() {
  // Best-effort server-side revocation so the token can't be reused after logout — fire and
  // forget, since local state must clear immediately either way (a network blip shouldn't
  // trap the user in a "logged in" UI).
  request('/auth/logout', { method: 'POST' }).catch(() => {})
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(ROLE_KEY)
  localStorage.removeItem(USERNAME_KEY)
}

export function isAuthenticated() {
  return Boolean(localStorage.getItem(TOKEN_KEY))
}

// Only for building a URL a browser navigates to directly (the live log tail) — everywhere
// else, auth goes through authHeaders()/request() instead of touching the token by hand.
export function getAuthToken() {
  return localStorage.getItem(TOKEN_KEY)
}

export function getRole() {
  return localStorage.getItem(ROLE_KEY)
}

export function getUsername() {
  return localStorage.getItem(USERNAME_KEY)
}

export const getAlerts = ({ limit = 100, skip = 0, severity = '', search = '' } = {}) => {
  const params = new URLSearchParams({ limit, skip })
  if (severity) params.set('severity', severity)
  if (search) params.set('search', search)
  return request(`/alerts?${params.toString()}`)
}
export const promoteAlert = (alertId) => request(`/alerts/${alertId}/promote`, { method: 'POST' })
export const uploadAlertsJson = (file, onProgress) => {
  const formData = new FormData()
  formData.append('file', file)
  return requestMultipartWithProgress('/alerts/upload', formData, onProgress)
}
export const getAlertUploadStatus = (jobId) => request(`/alerts/upload/status/${jobId}`)
export const initAlertUpload = (filename, totalBytes) =>
  request('/alerts/upload/init', { method: 'POST', body: JSON.stringify({ filename, total_bytes: totalBytes }) })
export const getAlertUploadSessionStatus = (sessionId) => request(`/alerts/upload/session/${sessionId}/status`)
export const uploadAlertChunk = (sessionId, blob, offset, onProgress) =>
  uploadChunkWithProgress(`/alerts/upload/session/${sessionId}/chunk`, blob, offset, onProgress)
export const completeAlertUpload = (sessionId) =>
  request(`/alerts/upload/session/${sessionId}/complete`, { method: 'POST' })
export const deleteAlert = (alertId) => request(`/alerts/${alertId}`, { method: 'DELETE' })
export const deleteAlertsBulk = (ids) =>
  request('/alerts/delete-bulk', { method: 'POST', body: JSON.stringify({ ids }) })
export const getIncidents = ({ limit = 100, skip = 0, severity = '', caseStatus = '', search = '', reviewed = '', campaignId = '' } = {}) => {
  const params = new URLSearchParams({ limit, skip })
  if (severity) params.set('severity', severity)
  if (caseStatus) params.set('case_status', caseStatus)
  if (search) params.set('search', search)
  if (reviewed) params.set('reviewed', reviewed)
  if (campaignId) params.set('campaign_id', campaignId)
  return request(`/incidents?${params.toString()}`)
}
export const getInvestigationQueue = () => request('/incidents/queue')
export const requeueIncident = (id) => request(`/incidents/${id}/requeue`, { method: 'POST' })
export const getIncident = (id) => request(`/incidents/${id}`)
export const getRelatedIncidents = (id) => request(`/incidents/${id}/related`)
export const updateIncident = (id, payload) =>
  request(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(payload) })
export const addNote = (id, text) =>
  request(`/incidents/${id}/notes`, { method: 'POST', body: JSON.stringify({ text }) })
export const closeIncident = (id, resolution, disposition) =>
  request(`/incidents/${id}/close`, { method: 'POST', body: JSON.stringify({ resolution, disposition }) })
export const investigateIncident = (id) =>
  request(`/incidents/${id}/investigate`, { method: 'POST' })
export const deleteIncident = (id) => request(`/incidents/${id}`, { method: 'DELETE' })
export const deleteIncidentsBulk = (ids) =>
  request('/incidents/delete-bulk', { method: 'POST', body: JSON.stringify({ ids }) })

export const getExclusionRules = () => request('/exclusion-rules')
export const createExclusionRule = (fields) =>
  request('/exclusion-rules', { method: 'POST', body: JSON.stringify(fields) })
export const updateExclusionRule = (id, payload) =>
  request(`/exclusion-rules/${id}`, { method: 'PATCH', body: JSON.stringify(payload) })
export const deleteExclusionRule = (id) => request(`/exclusion-rules/${id}`, { method: 'DELETE' })

export const getRuleHealth = () => request('/rule-health')

export const askAI = (question, { model, conversationId } = {}) =>
  request('/ask', {
    method: 'POST',
    body: JSON.stringify({
      question,
      model: model || null,
      conversation_id: conversationId || null,
    }),
  })

export const getAiModels = () => request('/ai/models')

export const getDefaultAiModelSetting = () => request('/settings/default-ai-model')
export const setDefaultAiModelSetting = (modelId) =>
  request('/settings/default-ai-model', { method: 'POST', body: JSON.stringify({ model_id: modelId }) })

export const getFallbackAiModelSetting = () => request('/settings/fallback-ai-model')
export const setFallbackAiModelSetting = (modelId) =>
  request('/settings/fallback-ai-model', { method: 'POST', body: JSON.stringify({ model_id: modelId }) })

export const getAiEmbeddingModels = () => request('/ai/embedding-models')
export const getDefaultEmbeddingModelSetting = () => request('/settings/default-embedding-model')
export const setDefaultEmbeddingModelSetting = (modelId) =>
  request('/settings/default-embedding-model', { method: 'POST', body: JSON.stringify({ model_id: modelId }) })

export const getMultiAgentInvestigationSetting = () => request('/settings/multi-agent-investigation')
export const setMultiAgentInvestigationSetting = (enabled) =>
  request('/settings/multi-agent-investigation', { method: 'POST', body: JSON.stringify({ enabled }) })

export const getStructuredOutputSetting = () => request('/settings/structured-output')
export const setStructuredOutputSetting = (enabled) =>
  request('/settings/structured-output', { method: 'POST', body: JSON.stringify({ enabled }) })

export const getCheapAiModelSetting = () => request('/settings/cheap-ai-model')
export const setCheapAiModelSetting = (modelId) =>
  request('/settings/cheap-ai-model', { method: 'POST', body: JSON.stringify({ model_id: modelId }) })

export const getMonthlyBudgetCapSetting = () => request('/settings/monthly-budget-cap')
export const setMonthlyBudgetCapSetting = (amount) =>
  request('/settings/monthly-budget-cap', { method: 'POST', body: JSON.stringify({ amount }) })

export const runEval = (sampleSize) => request('/eval/run', { method: 'POST', body: JSON.stringify({ sample_size: sampleSize }) })
export const getLatestEvalReport = () => request('/eval/latest')

export const listConversations = () => request('/conversations')
export const getConversation = (id) => request(`/conversations/${id}`)
export const renameConversation = (id, title) =>
  request(`/conversations/${id}`, { method: 'PATCH', body: JSON.stringify({ title }) })
export const deleteConversation = (id) => request(`/conversations/${id}`, { method: 'DELETE' })

export const getSystemHealth = () => request('/system/health')

export const getAWSStatus = () => request('/integrations/aws/status')
export const setAWSCredentials = (accessKeyId, secretAccessKey, sessionToken, region) =>
  request('/integrations/aws/credentials', {
    method: 'POST',
    body: JSON.stringify({
      access_key_id: accessKeyId,
      secret_access_key: secretAccessKey,
      session_token: sessionToken || null,
      region: region || null,
    }),
  })
export const clearAWSCredentials = () => request('/integrations/aws/credentials', { method: 'DELETE' })

export const getBedrockStatus = () => request('/integrations/bedrock/status')
export const setBedrockCredentials = (accessKeyId, secretAccessKey, sessionToken, region) =>
  request('/integrations/bedrock/credentials', {
    method: 'POST',
    body: JSON.stringify({
      access_key_id: accessKeyId,
      secret_access_key: secretAccessKey,
      session_token: sessionToken || null,
      region: region || null,
    }),
  })
export const clearBedrockCredentials = () => request('/integrations/bedrock/credentials', { method: 'DELETE' })
export const setBedrockApiKey = (apiKey, region) =>
  request('/integrations/bedrock/api-key', {
    method: 'POST',
    body: JSON.stringify({ api_key: apiKey, region: region || null }),
  })
export const getAssetCoverage = () => request('/assets/coverage')
export const getS3Inventory = () => request('/assets/s3-inventory')
export const getWazuhAgents = () => request('/assets/wazuh-agents')
export const refreshAssetCache = () => request('/assets/refresh-cache', { method: 'POST' })
export const getAssetCacheStatus = () => request('/assets/cache-status')

export const getWazuhManagerStatus = () => request('/integrations/wazuh/status')
export const setWazuhCredentials = (host, user, password, verifySsl) =>
  request('/integrations/wazuh/credentials', {
    method: 'POST',
    body: JSON.stringify({ host, user, password, verify_ssl: verifySsl }),
  })
export const clearWazuhCredentials = () => request('/integrations/wazuh/credentials', { method: 'DELETE' })

export const getAgentSheetStatus = () => request('/integrations/wazuh/agents-sheet/status')
export const uploadAgentSheet = (file) => {
  const formData = new FormData()
  formData.append('file', file)
  return requestMultipart('/integrations/wazuh/agents-sheet', formData)
}
export const clearAgentSheet = () => request('/integrations/wazuh/agents-sheet', { method: 'DELETE' })

export const getThreatIntelStatus = () => request('/integrations/threat-intel/status')
export const setThreatIntelCredentials = (virustotalApiKey, abuseipdbApiKey, abusechAuthKey) =>
  request('/integrations/threat-intel/credentials', {
    method: 'POST',
    body: JSON.stringify({
      virustotal_api_key: virustotalApiKey || null,
      abuseipdb_api_key: abuseipdbApiKey || null,
      abusech_auth_key: abusechAuthKey || null,
    }),
  })
export const clearThreatIntelCredentials = () => request('/integrations/threat-intel/credentials', { method: 'DELETE' })
export const lookupThreatIntel = (indicator) => request(`/threat-intel/lookup?indicator=${encodeURIComponent(indicator)}`)

export const listUsers = () => request('/users')
export const createUser = (username, password, role) =>
  request('/users', { method: 'POST', body: JSON.stringify({ username, password, role }) })
export const deleteUser = (username) =>
  request(`/users/${username}`, { method: 'DELETE' })

export const getAuditLog = (limit = 100) => request(`/audit-log?limit=${limit}`)

export const getWazuhLogs = ({ nodeId = '', level = '', tag = '', search = '', limit = 200 } = {}) => {
  const params = new URLSearchParams({ limit })
  if (nodeId) params.set('node_id', nodeId)
  if (level) params.set('level', level)
  if (tag) params.set('tag', tag)
  if (search) params.set('search', search)
  return request(`/wazuh/logs?${params.toString()}`)
}
export const runWazuhDiagnosticQuery = (target, path) =>
  request('/wazuh/diagnostic-query', { method: 'POST', body: JSON.stringify({ target, path }) })

export const getAlertIngestionSetting = () => request('/settings/alert-ingestion')
export const setAlertIngestionSetting = (enabled) =>
  request('/settings/alert-ingestion', { method: 'POST', body: JSON.stringify({ enabled }) })

export const getCaseCorrelationSetting = () => request('/settings/case-correlation')
export const setCaseCorrelationSetting = (enabled) =>
  request('/settings/case-correlation', { method: 'POST', body: JSON.stringify({ enabled }) })

export const getAutoInvestigateSetting = () => request('/settings/auto-investigate')
export const setAutoInvestigateSetting = (enabled) =>
  request('/settings/auto-investigate', { method: 'POST', body: JSON.stringify({ enabled }) })

export const getCaseEnrichmentSetting = () => request('/settings/case-enrichment')
export const setCaseEnrichmentSetting = (enabled) =>
  request('/settings/case-enrichment', { method: 'POST', body: JSON.stringify({ enabled }) })

export const getCampaignCorrelationSetting = () => request('/settings/campaign-correlation')
export const setCampaignCorrelationSetting = (enabled) =>
  request('/settings/campaign-correlation', { method: 'POST', body: JSON.stringify({ enabled }) })

export const getDebugMode = () => request('/debug/mode')
export const setDebugMode = (enabled) =>
  request('/debug/mode', { method: 'POST', body: JSON.stringify({ enabled }) })
export const getDebugDiagnostics = () => request('/debug/diagnostics')
export const wipeAlertData = () => request('/admin/wipe-alert-data', { method: 'POST' })

export const getActiveAlerts = () => request('/alerts/active')

export const getNotifications = () => request('/notifications')
export const markNotificationRead = (id) => request(`/notifications/${id}/read`, { method: 'POST' })
export const markAllNotificationsRead = () => request('/notifications/read-all', { method: 'POST' })

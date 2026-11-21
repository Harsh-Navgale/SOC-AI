import { useEffect, useRef, useState } from 'react'
import {
  askAI, getAiModels, getUsername,
  getBedrockStatus, getDefaultAiModelSetting, setDefaultAiModelSetting,
  getFallbackAiModelSetting, setFallbackAiModelSetting,
  getAiEmbeddingModels, getDefaultEmbeddingModelSetting, setDefaultEmbeddingModelSetting,
  getMultiAgentInvestigationSetting, setMultiAgentInvestigationSetting,
  getStructuredOutputSetting, setStructuredOutputSetting,
  getCheapAiModelSetting, setCheapAiModelSetting,
  getMonthlyBudgetCapSetting, setMonthlyBudgetCapSetting, getDebugDiagnostics,
  listConversations, getConversation, renameConversation, deleteConversation,
} from '../api.js'
import { useToast } from '../ToastContext.jsx'
import { useAuth } from '../AuthContext.jsx'
import { useDebugMode } from '../useDebugMode.js'
import { IconPlus, IconSparkle, IconCopy, IconTrash, IconPencil } from './icons.jsx'
import ConnectBedrockForm from './ConnectBedrockForm.jsx'

function formatBytes(bytes) {
  if (!bytes) return ''
  const gb = bytes / 1024 ** 3
  if (gb >= 1) return `${gb.toFixed(1)} GB`
  return `${Math.round(bytes / 1024 ** 2)} MB`
}

function formatRelativeTime(iso) {
  const diffSeconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (diffSeconds < 60) return 'just now'
  const minutes = Math.floor(diffSeconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 7) return `${days}d ago`
  return new Date(iso).toLocaleDateString()
}

function formatInline(text, keyPrefix) {
  const parts = text.split(/(\*\*[^*]+\*\*)/g)
  return parts.map((part, i) =>
    part.startsWith('**') && part.endsWith('**')
      ? <strong key={`${keyPrefix}-${i}`}>{part.slice(2, -2)}</strong>
      : <span key={`${keyPrefix}-${i}`}>{part}</span>
  )
}

// Lightweight markdown-ish rendering (bold + bullet lists + paragraphs) without pulling in
// a full markdown dependency — the model's plain-text responses only need this much.
function renderTextBlock(text, keyPrefix) {
  const lines = text.split('\n')
  const blocks = []
  let listBuffer = []

  const flushList = () => {
    if (listBuffer.length) {
      blocks.push(
        <ul key={`${keyPrefix}-ul-${blocks.length}`}>
          {listBuffer.map((item, i) => <li key={i}>{formatInline(item, `${keyPrefix}-li-${blocks.length}-${i}`)}</li>)}
        </ul>
      )
      listBuffer = []
    }
  }

  lines.forEach((line, i) => {
    const trimmed = line.trim()
    if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
      listBuffer.push(trimmed.slice(2))
    } else {
      flushList()
      if (trimmed) blocks.push(<p key={`${keyPrefix}-p-${i}`}>{formatInline(trimmed, `${keyPrefix}-p-${i}`)}</p>)
    }
  })
  flushList()
  return blocks
}

function CodeBlock({ raw }) {
  const [copied, setCopied] = useState(false)
  const inner = raw.slice(3, -3)
  const firstNewline = inner.indexOf('\n')
  const firstLine = (firstNewline === -1 ? inner : inner.slice(0, firstNewline)).trim()
  const hasLangTag = firstNewline !== -1 && /^[a-zA-Z0-9_+-]{1,20}$/.test(firstLine)
  const lang = hasLangTag ? firstLine : ''
  const code = (hasLangTag ? inner.slice(firstNewline + 1) : inner).replace(/\n$/, '')

  const handleCopy = () => {
    navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="code-block">
      <div className="code-block-header">
        <span className="mono">{lang || 'text'}</span>
        <button className="code-block-copy" onClick={handleCopy}>
          {copied ? 'Copied' : <><IconCopy width={12} height={12} /> Copy</>}
        </button>
      </div>
      <pre><code>{code}</code></pre>
    </div>
  )
}

function renderAnswer(text) {
  const segments = text.split(/(```[\s\S]*?```)/g)
  return segments.map((segment, i) =>
    segment.startsWith('```') && segment.endsWith('```') && segment.length >= 6
      ? <CodeBlock key={`seg-${i}`} raw={segment} />
      : <div key={`seg-${i}`}>{renderTextBlock(segment, `seg-${i}`)}</div>
  )
}

function Message({ msg, currentUsername, showDebug }) {
  const [showContext, setShowContext] = useState(false)
  const [showPrompt, setShowPrompt] = useState(false)
  const [copied, setCopied] = useState(false)

  const handleCopyAnswer = () => {
    navigator.clipboard.writeText(msg.content)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  if (msg.role === 'user') {
    return (
      <div className="chat-row user">
        <div className="chat-bubble user">
          <div className="msg-author">{!msg.author || msg.author === currentUsername ? 'You' : msg.author}</div>
          {msg.content}
        </div>
        <div className="msg-avatar user-avatar">{(msg.author || currentUsername || '?')[0].toUpperCase()}</div>
      </div>
    )
  }

  return (
    <div className="chat-row assistant">
      <div className="msg-avatar assistant-avatar"><IconSparkle width={14} height={14} /></div>
      <div className={`chat-bubble assistant ${msg.error ? 'is-error' : ''}`}>
        {renderAnswer(msg.content)}
        {!msg.error && (
          <div className="chat-meta">
            <span className="mono">{msg.model}</span>
            <span>&middot;</span>
            <span>{msg.elapsedSeconds}s</span>
            {msg.contextChunks?.length > 0 && (
              <>
                <span>&middot;</span>
                <button className="context-toggle" onClick={() => setShowContext((v) => !v)}>
                  {showContext ? 'Hide' : 'Show'} {msg.contextChunks.length} source{msg.contextChunks.length === 1 ? '' : 's'}
                </button>
              </>
            )}
            {showDebug && msg.prompt && (
              <>
                <span>&middot;</span>
                <button className="context-toggle" onClick={() => setShowPrompt((v) => !v)}>
                  {showPrompt ? 'Hide' : 'Show'} prompt
                </button>
              </>
            )}
            <button className="msg-copy" onClick={handleCopyAnswer} title="Copy answer">
              {copied ? 'Copied' : <IconCopy width={12} height={12} />}
            </button>
          </div>
        )}
      </div>
      {showContext && (
        <div className="context-panel">
          {msg.contextChunks.map((c, i) => (
            <div className="context-chunk" key={i}>
              <div className="context-chunk-source">{c.source}</div>
              {c.text}
            </div>
          ))}
        </div>
      )}
      {showPrompt && (
        <div className="context-panel">
          <p className="muted" style={{ margin: '0 0 8px' }}>
            {msg.promptTokens ?? '—'} prompt tokens &middot; {msg.completionTokens ?? '—'} completion tokens
            {msg.estimatedCost != null && <> &middot; est. ${msg.estimatedCost.toFixed(6)}</>}
          </p>
          <pre className="full-log-line">{msg.prompt}</pre>
        </div>
      )}
    </div>
  )
}

// Admin-only, collapsible — same pattern ThreatIntel.jsx's "Manage API keys" card already uses.
// Reuses the same `models` list the chat's own dropdown already fetched, rather than a second
// API call, since it's exactly the same set of choices.
function BedrockSettingsCard({ models }) {
  const [open, setOpen] = useState(false)
  const [status, setStatus] = useState(null)
  const [defaultModel, setDefaultModelState] = useState('')
  const [saving, setSaving] = useState(false)
  const [fallbackModel, setFallbackModelState] = useState('')
  const [savingFallback, setSavingFallback] = useState(false)
  const [embeddingModels, setEmbeddingModels] = useState([])
  const [defaultEmbeddingModel, setDefaultEmbeddingModelState] = useState('')
  const [savingEmbedding, setSavingEmbedding] = useState(false)
  const [multiAgentEnabled, setMultiAgentEnabledState] = useState(false)
  const [savingMultiAgent, setSavingMultiAgent] = useState(false)
  const [structuredOutputEnabled, setStructuredOutputEnabledState] = useState(false)
  const [savingStructuredOutput, setSavingStructuredOutput] = useState(false)
  const [cheapModel, setCheapModelState] = useState('')
  const [savingCheapModel, setSavingCheapModel] = useState(false)
  const [budgetCap, setBudgetCapState] = useState('')
  const [savingBudgetCap, setSavingBudgetCap] = useState(false)
  const [monthToDateCost, setMonthToDateCost] = useState(null)
  const { showToast } = useToast()

  const load = () => {
    getBedrockStatus().then(setStatus).catch(() => {})
    getDefaultAiModelSetting().then((r) => setDefaultModelState(r.model_id || '')).catch(() => {})
    getFallbackAiModelSetting().then((r) => setFallbackModelState(r.model_id || '')).catch(() => {})
    getAiEmbeddingModels().then(setEmbeddingModels).catch(() => {})
    getDefaultEmbeddingModelSetting().then((r) => setDefaultEmbeddingModelState(r.model_id || '')).catch(() => {})
    getMultiAgentInvestigationSetting().then((r) => setMultiAgentEnabledState(r.enabled)).catch(() => {})
    getStructuredOutputSetting().then((r) => setStructuredOutputEnabledState(r.enabled)).catch(() => {})
    getCheapAiModelSetting().then((r) => setCheapModelState(r.model_id || '')).catch(() => {})
    getMonthlyBudgetCapSetting().then((r) => setBudgetCapState(r.amount ?? '')).catch(() => {})
    getDebugDiagnostics().then((r) => setMonthToDateCost(r.ai_usage?.month_to_date_cost ?? null)).catch(() => {})
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const handleDefaultModelChange = async (e) => {
    const modelId = e.target.value
    setDefaultModelState(modelId)
    setSaving(true)
    try {
      await setDefaultAiModelSetting(modelId)
      showToast('Default model for background AI jobs updated.', 'success')
    } catch (err) {
      showToast(err.message)
    } finally {
      setSaving(false)
    }
  }

  const handleFallbackModelChange = async (e) => {
    const modelId = e.target.value
    setFallbackModelState(modelId)
    setSavingFallback(true)
    try {
      await setFallbackAiModelSetting(modelId)
      showToast('Fallback model for background AI jobs updated.', 'success')
    } catch (err) {
      showToast(err.message)
    } finally {
      setSavingFallback(false)
    }
  }

  const handleDefaultEmbeddingModelChange = async (e) => {
    const modelId = e.target.value
    setDefaultEmbeddingModelState(modelId)
    setSavingEmbedding(true)
    try {
      await setDefaultEmbeddingModelSetting(modelId)
      showToast('Default embedding model updated.', 'success')
    } catch (err) {
      showToast(err.message)
    } finally {
      setSavingEmbedding(false)
    }
  }

  const handleMultiAgentToggle = async () => {
    const next = !multiAgentEnabled
    setSavingMultiAgent(true)
    try {
      const r = await setMultiAgentInvestigationSetting(next)
      setMultiAgentEnabledState(r.enabled)
      showToast(`Multi-agent investigation ${r.enabled ? 'enabled' : 'disabled'}.`, 'success')
    } catch (err) {
      showToast(err.message)
    } finally {
      setSavingMultiAgent(false)
    }
  }

  const handleStructuredOutputToggle = async () => {
    const next = !structuredOutputEnabled
    setSavingStructuredOutput(true)
    try {
      const r = await setStructuredOutputSetting(next)
      setStructuredOutputEnabledState(r.enabled)
      showToast(`Structured AI output ${r.enabled ? 'enabled' : 'disabled'}.`, 'success')
    } catch (err) {
      showToast(err.message)
    } finally {
      setSavingStructuredOutput(false)
    }
  }

  const handleCheapModelChange = async (e) => {
    const modelId = e.target.value
    setCheapModelState(modelId)
    setSavingCheapModel(true)
    try {
      await setCheapAiModelSetting(modelId)
      showToast('Cheap model for low-complexity cases updated.', 'success')
    } catch (err) {
      showToast(err.message)
    } finally {
      setSavingCheapModel(false)
    }
  }

  const handleBudgetCapChange = async (e) => {
    const value = e.target.value
    setBudgetCapState(value)
    setSavingBudgetCap(true)
    try {
      const amount = value === '' ? null : Number(value)
      const r = await setMonthlyBudgetCapSetting(amount)
      showToast(r.amount === null ? 'Monthly AI budget cap cleared.' : `Monthly AI budget cap set to $${r.amount}.`, 'success')
    } catch (err) {
      showToast(err.message)
    } finally {
      setSavingBudgetCap(false)
    }
  }

  if (!open) {
    return (
      <button className="btn-outline" onClick={() => setOpen(true)} style={{ marginBottom: 16 }}>
        AI provider settings
      </button>
    )
  }

  return (
    <div style={{ marginBottom: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="card" style={{ maxWidth: 560 }}>
        <h3 style={{ margin: '0 0 10px' }}>Default model for background AI jobs</h3>
        <p className="muted" style={{ marginTop: 0, fontSize: 12, lineHeight: 1.6 }}>
          Used by AI investigation, exclusion-rule structuring, and org-context extraction —
          the jobs that run with nobody present to pick a model per call. The dropdown above
          still lets you pick a different model just for a single Ask AI question.
        </p>
        <select value={defaultModel} onChange={handleDefaultModelChange} disabled={saving} style={{ minWidth: 260 }}>
          <option value="">Built-in default (no model selected)</option>
          {models.map((m) => (
            <option key={m.name} value={m.name}>{m.label || m.name}{m.provider === 'bedrock' ? ' — Bedrock' : ''}</option>
          ))}
        </select>
      </div>
      <div className="card" style={{ maxWidth: 560 }}>
        <h3 style={{ margin: '0 0 10px' }}>Fallback model for background AI jobs</h3>
        <p className="muted" style={{ marginTop: 0, fontSize: 12, lineHeight: 1.6 }}>
          Used only when the default model above fails outright — Bedrock disconnected/expired,
          or that specific model/region having an outage — not when it just gives a bad answer.
          Pick a second model here (a different model, or a different cross-region profile) so
          background jobs keep working instead of failing outright.
        </p>
        <select value={fallbackModel} onChange={handleFallbackModelChange} disabled={savingFallback} style={{ minWidth: 260 }}>
          <option value="">None — fail if the default is unavailable</option>
          {models.map((m) => (
            <option key={m.name} value={m.name}>{m.label || m.name}{m.provider === 'bedrock' ? ' — Bedrock' : ''}</option>
          ))}
        </select>
      </div>
      <div className="card" style={{ maxWidth: 560 }}>
        <h3 style={{ margin: '0 0 10px' }}>Default embedding model</h3>
        <p className="muted" style={{ marginTop: 0, fontSize: 12, lineHeight: 1.6 }}>
          Used for every RAG lookup into the organization knowledge base. Changing this is safe
          while that knowledge base is empty, but once it holds real documents, switching
          providers means everything already in it needs to be re-embedded — different models
          produce vectors of different sizes that can't be mixed.
        </p>
        <select value={defaultEmbeddingModel} onChange={handleDefaultEmbeddingModelChange} disabled={savingEmbedding} style={{ minWidth: 260 }}>
          <option value="">Built-in default (no model selected)</option>
          {embeddingModels.map((m) => (
            <option key={m.name} value={m.name}>{m.label || m.name}{m.provider === 'bedrock' ? ' — Bedrock' : ''}</option>
          ))}
        </select>
      </div>
      <div className="card" style={{ maxWidth: 560 }}>
        <h3 style={{ margin: '0 0 10px' }}>Multi-agent investigation (experimental)</h3>
        <p className="muted" style={{ marginTop: 0, fontSize: 12, lineHeight: 1.6 }}>
          Splits each AI investigation into a focused rule-health check followed by a separate
          verdict/report call, instead of one combined prompt. Roughly doubles AI-generation
          cost and latency per incident — leave off unless you want the extra isolation.
        </p>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
          <input type="checkbox" checked={multiAgentEnabled} onChange={handleMultiAgentToggle} disabled={savingMultiAgent} />
          Enabled
        </label>
      </div>
      <div className="card" style={{ maxWidth: 560 }}>
        <h3 style={{ margin: '0 0 10px' }}>Structured AI output (experimental)</h3>
        <p className="muted" style={{ marginTop: 0, fontSize: 12, lineHeight: 1.6 }}>
          When the resolved model is Claude on Bedrock, forces the investigation report through
          a schema-constrained tool call instead of freeform text + regex parsing — no format
          the model can drift from. Falls back to the text path automatically for every other
          model, or if the structured call itself fails. Run an AI-accuracy eval before and
          after enabling to confirm verdict agreement doesn't regress.
        </p>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
          <input type="checkbox" checked={structuredOutputEnabled} onChange={handleStructuredOutputToggle} disabled={savingStructuredOutput} />
          Enabled
        </label>
      </div>
      <div className="card" style={{ maxWidth: 560 }}>
        <h3 style={{ margin: '0 0 10px' }}>Cheap model for low-complexity cases</h3>
        <p className="muted" style={{ marginTop: 0, fontSize: 12, lineHeight: 1.6 }}>
          Routes a mechanically-simple case (a vulnerability/CVE match, or one with a close
          confirmed-disposition precedent for its rule) to this model instead of the default
          above — cuts cost on the cases that don't need the stronger model's judgment.
        </p>
        <select value={cheapModel} onChange={handleCheapModelChange} disabled={savingCheapModel} style={{ minWidth: 260 }}>
          <option value="">No routing — every case uses the default model</option>
          {models.map((m) => (
            <option key={m.name} value={m.name}>{m.label || m.name}{m.provider === 'bedrock' ? ' — Bedrock' : ''}</option>
          ))}
        </select>
      </div>
      <div className="card" style={{ maxWidth: 560 }}>
        <h3 style={{ margin: '0 0 10px' }}>Monthly AI budget cap</h3>
        <p className="muted" style={{ marginTop: 0, fontSize: 12, lineHeight: 1.6 }}>
          When this month's estimated AI spend reaches the cap, auto-investigation pauses until
          next month (with an admin notification) — a human-initiated "Investigate with AI"
          click still works. Leave blank for no cap.
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <input
            type="number" min="0" step="0.01" placeholder="No cap" value={budgetCap}
            onChange={handleBudgetCapChange} disabled={savingBudgetCap} style={{ width: 120 }}
          />
          {monthToDateCost !== null && (
            <span className="muted" style={{ fontSize: 12 }}>
              Spent this month: <span className="mono">${monthToDateCost.toFixed(2)}</span>
            </span>
          )}
        </div>
      </div>
      {status?.configured ? (
        <div className="card" style={{ maxWidth: 560 }}>
          <h3 style={{ margin: '0 0 10px' }}>Bedrock</h3>
          <p className="muted" style={{ marginTop: 0 }}>
            Connected via {status.auth_mode === 'api_key' ? 'API key' : 'IAM access key'}, until {new Date(status.expires_at).toLocaleString()}.
          </p>
        </div>
      ) : (
        <ConnectBedrockForm onConnected={load} />
      )}
      <button className="btn-outline" onClick={() => setOpen(false)} style={{ alignSelf: 'flex-start' }}>Hide</button>
    </div>
  )
}

function storedMessageToLocal(m) {
  if (m.role === 'user') return { role: 'user', content: m.content, author: m.author }
  return {
    role: 'assistant',
    content: m.content,
    model: m.model,
    elapsedSeconds: m.elapsed_seconds,
    contextChunks: m.context_chunks || [],
    prompt: m.prompt,
    promptTokens: m.prompt_tokens,
    completionTokens: m.completion_tokens,
    estimatedCost: m.estimated_cost,
  }
}

function ConversationRow({ conversation, active, editing, editValue, onEditValueChange, onSelect, onStartRename, onCommitRename, onCancelRename, onDelete }) {
  return (
    <div
      className={`chat-sidebar-item ${active ? 'active' : ''}`}
      role="button"
      tabIndex={editing ? -1 : 0}
      aria-current={active ? 'true' : undefined}
      onClick={() => !editing && onSelect(conversation.id)}
      onKeyDown={(e) => {
        if (!editing && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault()
          onSelect(conversation.id)
        }
      }}
    >
      {editing ? (
        <input
          className="chat-sidebar-rename-input"
          value={editValue}
          autoFocus
          onClick={(e) => e.stopPropagation()}
          onChange={(e) => onEditValueChange(e.target.value)}
          onBlur={() => onCommitRename(conversation.id)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') e.currentTarget.blur()
            if (e.key === 'Escape') onCancelRename()
          }}
        />
      ) : (
        <div className="chat-sidebar-title">{conversation.title || 'Untitled'}</div>
      )}
      <div className="chat-sidebar-meta">
        <span>{conversation.author}</span>
        <span>&middot;</span>
        <span>{formatRelativeTime(conversation.updated_at)}</span>
      </div>
      <div className="chat-sidebar-actions">
        <button onClick={(e) => { e.stopPropagation(); onStartRename(conversation) }} title="Rename">
          <IconPencil width={13} height={13} />
        </button>
        <button onClick={(e) => { e.stopPropagation(); onDelete(conversation.id) }} title="Delete" className="chat-sidebar-delete">
          <IconTrash width={13} height={13} />
        </button>
      </div>
    </div>
  )
}

export default function AIChat() {
  const { showToast } = useToast()
  const { isAdmin } = useAuth()
  const debugMode = useDebugMode()
  const showDebug = isAdmin && debugMode
  const currentUsername = getUsername()

  const [models, setModels] = useState([])
  const [modelsError, setModelsError] = useState(null)
  const [selectedModel, setSelectedModel] = useState('')

  const [conversations, setConversations] = useState([])
  const [sidebarLoading, setSidebarLoading] = useState(true)
  const [activeId, setActiveId] = useState(null)
  const [editingId, setEditingId] = useState(null)
  const [editValue, setEditValue] = useState('')

  const [messages, setMessages] = useState([])
  const [chatLoading, setChatLoading] = useState(false)
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const threadRef = useRef(null)

  const loadSidebar = () => {
    listConversations()
      .then(setConversations)
      .catch((err) => showToast(err.message))
      .finally(() => setSidebarLoading(false))
  }

  useEffect(() => {
    getAiModels()
      .then((list) => {
        setModels(list)
        if (list.length > 0) setSelectedModel(list[0].name)
      })
      .catch((err) => setModelsError(err.message))
    loadSidebar()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (threadRef.current) {
      threadRef.current.scrollTop = threadRef.current.scrollHeight
    }
  }, [messages, sending, chatLoading])

  const handleNewChat = () => {
    setActiveId(null)
    setMessages([])
    setInput('')
  }

  const handleSelectConversation = (id) => {
    if (id === activeId) return
    setChatLoading(true)
    getConversation(id)
      .then((convo) => {
        setActiveId(id)
        setMessages(convo.messages.map(storedMessageToLocal))
      })
      .catch((err) => showToast(err.message))
      .finally(() => setChatLoading(false))
  }

  const handleStartRename = (conversation) => {
    setEditingId(conversation.id)
    setEditValue(conversation.title || '')
  }

  const handleCommitRename = (id) => {
    const title = editValue.trim()
    setEditingId(null)
    if (!title) return
    renameConversation(id, title)
      .then(() => setConversations((prev) => prev.map((c) => (c.id === id ? { ...c, title } : c))))
      .catch((err) => showToast(err.message))
  }

  const handleDelete = (id) => {
    deleteConversation(id)
      .then(() => {
        showToast('Conversation deleted.', 'success')
        setConversations((prev) => prev.filter((c) => c.id !== id))
        if (id === activeId) handleNewChat()
      })
      .catch((err) => showToast(err.message))
  }

  const handleSend = async () => {
    const question = input.trim()
    if (!question || sending) return

    setMessages((prev) => [...prev, { role: 'user', content: question, author: currentUsername }])
    setInput('')
    setSending(true)

    try {
      const result = await askAI(question, { model: selectedModel, conversationId: activeId })
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: result.answer,
          model: result.model,
          elapsedSeconds: result.elapsed_seconds,
          contextChunks: result.context_chunks || [],
          prompt: result.prompt,
          promptTokens: result.prompt_tokens,
          completionTokens: result.completion_tokens,
          estimatedCost: result.estimated_cost,
        },
      ])
      if (!activeId) setActiveId(result.conversation_id)
      loadSidebar()
    } catch (err) {
      setMessages((prev) => [...prev, { role: 'assistant', content: err.message, error: true }])
    } finally {
      setSending(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="chat-layout">
      <div className="chat-sidebar">
        <button className="chat-new-btn" onClick={handleNewChat}>
          <IconPlus width={15} height={15} /> New chat
        </button>
        <div className="chat-sidebar-list">
          {sidebarLoading && (
            <div className="chat-sidebar-skeleton">
              {[0, 1, 2].map((i) => (
                <div key={i} className="skeleton skeleton-text" style={{ height: 46, marginBottom: 8, borderRadius: 8 }} />
              ))}
            </div>
          )}
          {!sidebarLoading && conversations.length === 0 && (
            <div className="chat-sidebar-empty">No conversations yet &mdash; ask something to get started.</div>
          )}
          {!sidebarLoading && conversations.map((c) => (
            <ConversationRow
              key={c.id}
              conversation={c}
              active={c.id === activeId}
              editing={editingId === c.id}
              editValue={editValue}
              onEditValueChange={setEditValue}
              onSelect={handleSelectConversation}
              onStartRename={handleStartRename}
              onCommitRename={handleCommitRename}
              onCancelRename={() => setEditingId(null)}
              onDelete={handleDelete}
            />
          ))}
        </div>
      </div>

      <div className="chat-main">
        <div className="chat-toolbar">
          <div className="chat-toolbar-left">
            {models.length > 0 ? (
              <select value={selectedModel} onChange={(e) => setSelectedModel(e.target.value)}>
                {models.map((m) => (
                  <option key={m.name} value={m.name}>
                    {m.label || m.name}{m.size_bytes ? ` (${formatBytes(m.size_bytes)})` : ''}{m.provider === 'bedrock' ? ' — Bedrock' : ''}
                  </option>
                ))}
              </select>
            ) : (
              <span className="muted">{modelsError ? `No AI models available: ${modelsError}` : 'Loading models...'}</span>
            )}
          </div>
        </div>

        {isAdmin && (
          <div style={{ padding: '0 16px' }}>
            <BedrockSettingsCard models={models} />
          </div>
        )}

        <div className="chat-thread" ref={threadRef}>
          {chatLoading && (
            <div className="chat-bubble assistant">
              <div className="thinking"><span /><span /><span /></div>
            </div>
          )}
          {!chatLoading && messages.length === 0 && (
            <div className="chat-empty-hint">
              Ask about an incident, a rule, or your org's playbooks &mdash; e.g. "What should I do
              about repeated SSH brute-force attempts from the same IP?"
            </div>
          )}
          {!chatLoading && messages.map((msg, i) => <Message msg={msg} currentUsername={currentUsername} showDebug={showDebug} key={i} />)}
          {sending && (
            <div className="chat-row assistant">
              <div className="msg-avatar assistant-avatar"><IconSparkle width={14} height={14} /></div>
              <div className="chat-bubble assistant">
                <div className="thinking"><span /><span /><span /></div>
              </div>
            </div>
          )}
        </div>

        <div className="chat-input-bar">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask a question... (Enter to send, Shift+Enter for a new line)"
          />
          <button className="ask" onClick={handleSend} disabled={sending || !input.trim()}>
            {sending ? 'Thinking...' : 'Send'}
          </button>
        </div>
      </div>
    </div>
  )
}

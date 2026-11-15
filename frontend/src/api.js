const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

async function getJson(path) {
  const response = await fetch(`${API_BASE}${path}`)
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || `API request failed (${response.status})`)
  }
  return response.json()
}

async function postJson(path, payload) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || `API request failed (${response.status})`)
  }
  return response.json()
}

export function submitInvestigation(payload) {
  return postJson('/api/investigations', payload)
}

export function getInvestigationStatus(investigationId) {
  return getJson(`/api/investigations/${encodeURIComponent(investigationId)}/status`)
}

function eventTone(source, type) {
  if (source === 'identity') return 'cyan'
  if (type === 'process_create' && source === 'endpoint') return 'amber'
  return 'red'
}

function eventTitle(event) {
  const names = { login_success: 'Authenticated login', process_create: 'Process created', file_create: 'File created', connection: 'HTTPS connection', dns_query: 'Suspicious DNS resolution' }
  return names[event.summary.split(':', 1)[0]] || event.summary.split(':', 1)[0].replaceAll('_', ' ')
}

function parseMappings(text, source) {
  return text.split('\n').flatMap(line => {
    const match = line.replaceAll('**', '').match(/^-\s*(T\d{4}(?:\.\d{3})?)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*(candidate|supported|confirmed)\s*\|\s*(.+)$/i)
    if (!match) return []
    return [{ id: match[1].toUpperCase(), name: match[2].trim(), source, evidence: match[3].split(',').map(item => item.trim().toLowerCase()), status: match[4].toLowerCase(), rationale: match[5].trim() }]
  })
}

export async function fetchDashboard(incidentId) {
  const investigations = await getJson('/api/investigations')
  if (!investigations.length) return { empty: true, investigations: [] }
  const selected = incidentId ? (investigations.find(item => item.incident_id === incidentId) || investigations[0]) : investigations[0]
  const id = selected.incident_id
  const [session, report, evaluation] = await Promise.all([
    getJson(`/api/investigations/${encodeURIComponent(id)}`),
    selected.has_report ? getJson(`/api/investigations/${encodeURIComponent(id)}/report`) : Promise.resolve({ markdown: '' }),
    selected.has_evaluation ? getJson(`/api/investigations/${encodeURIComponent(id)}/evaluation`) : Promise.resolve({ metrics: {} }),
  ])
  const state = session.state || {}
  const evidence = state.crewai_findings?.evidence || []
  const events = evidence.map(item => {
    const summary = item.summary || ''
    const [type, detail = ''] = summary.split(': ', 2)
    return { id: item.event_id, time: item.timestamp?.slice(11, 19) || '—', source: item.source, provenance: item.provenance || 'seeded', verification_status: item.verification_status || 'verified', type, title: eventTitle({ summary }), detail, tone: eventTone(item.source, type) }
  }).sort((a, b) => a.time.localeCompare(b.time))
  const metrics = evaluation.metrics || {}
  const mappings = [...parseMappings(state.network_findings || '', 'NetworkAnalyst'), ...parseMappings(state.endpoint_findings || '', 'EndpointAnalyst')]
  const reportText = report.markdown || ''
  const section = (name, next) => {
    const heading = '(?:#+\\s*|\\*\\*)'
    const closing = next === '__END__' ? '$' : `\\n${heading}${next}`
    const match = reportText.match(new RegExp(`(?:^|\\n)${heading}${name}(?:\\*\\*)?\\s*\\n([\\s\\S]*?)(?=${closing}|$)`, 'i'))
    return match?.[1]?.replaceAll('**', '').trim() || 'Unavailable in saved report.'
  }
  return {
    investigations,
    incidentId: id,
    title: id,
    question: state.ticket_brief || 'No analyst question was saved.',
    window: events.length ? `${events[0].time}–${events.at(-1).time}` : 'No event window',
    source: 'ADK → MCP → A2A → CrewAI',
    severity: null,
    overview: section('What happened', 'Supporting evidence'),
    events,
    mappings,
    metrics: { totalMs: metrics.timing?.total_duration_ms || 0, a2aMs: metrics.timing?.a2a_duration_ms || null, tokens: metrics.llm?.token_usage?.total_token_count || null, spans: metrics.trace?.span_count || 0, grounded: metrics.grounding?.passed ?? null, ragCalls: metrics.timing?.rag_retrieval_durations_ms?.length || 0 },
    findings: { network: state.network_findings || 'Unavailable.', endpoint: state.endpoint_findings || 'Unavailable.', identity: state.identity_findings || 'Unavailable.' },
    report: { happened: section('What happened', 'Supporting evidence'), conflict: section('Where evidence conflicts', 'Most likely explanation'), explanation: section('Most likely explanation', 'Recommended response'), response: section('Recommended response', '__END__') },
  }
}

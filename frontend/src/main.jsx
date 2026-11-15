import React from 'react'
import { createRoot } from 'react-dom/client'
import { Activity, AlertTriangle, ArrowUpRight, Bug, CheckCircle2, Clock3, Cpu, FileSearch, Fingerprint, Gauge, Hexagon, LayoutDashboard, Network, Plus, Search, Send, ShieldAlert, Terminal, UserRound, Wifi } from 'lucide-react'
import { fetchDashboard, getInvestigationStatus, submitInvestigation } from './api'
import { parseIncidentJson } from './incidentValidation'
import './styles.css'

const DashboardContext = React.createContext(null)
const useDashboardData = () => React.useContext(DashboardContext)

const fmt = (value) => new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 }).format(value)

function Sidebar({ active, onSelect, onNew }) {
  const items = [
    ['overview', 'Overview', LayoutDashboard],
    ['timeline', 'Timeline', Activity],
    ['evidence', 'Evidence explorer', FileSearch],
    ['mitre', 'ATT&CK candidates', Hexagon],
    ['report', 'Incident report', ShieldAlert],
  ]
  return <aside className="sidebar">
    <div className="brand"><div className="brand-mark"><Hexagon size={19} /></div><div><div className="brand-name">CYBER<span>RECON</span></div><div className="brand-sub">INVESTIGATION CONSOLE</div></div></div>
    <button className="new-investigation-button" onClick={onNew}><Plus size={16} /><span>New investigation</span></button>
    <div className="side-label">WORKSPACE</div>
    <nav>{items.map(([id, label, Icon]) => <button key={id} className={active === id ? 'nav-item active' : 'nav-item'} onClick={() => onSelect(id)}><Icon size={17} /><span>{label}</span>{active === id && <i />}</button>)}</nav>
    <div className="side-bottom"><div className="live-dot"><span />LOCAL API MODE</div><div className="side-note">Evidence-grounded<br />Read-only results</div></div>
  </aside>
}

function Topbar({ selectedId, onChange }) { const data = useDashboardData(); return <header className="topbar"><div className="crumb"><span>INCIDENTS</span><b>/</b><strong>{data.incidentId.toUpperCase()}</strong></div><div className="top-actions"><label className="incident-picker"><span>INVESTIGATION</span><select value={selectedId} onChange={event => onChange(event.target.value)} aria-label="Select investigation">{data.investigations.map(item => <option key={item.incident_id} value={item.incident_id}>{item.incident_id}</option>)}</select></label><span className="source-pill"><span className="green-dot" /> API ARTIFACT</span><button className="icon-button"><Search size={17} /></button><div className="avatar">AS</div></div></header> }

function StatCard({ label, value, detail, icon: Icon, accent = 'cyan' }) { return <div className={`stat-card ${accent}`}><div className="stat-icon"><Icon size={17} /></div><div className="stat-label">{label}</div><div className="stat-value">{value}</div><div className="stat-detail">{detail}</div></div> }

function Overview({ jump }) { const data = useDashboardData(); return <section id="overview" className="section"><div className="hero-row"><div><div className="eyebrow">INCIDENT OVERVIEW <span className="live-line" /></div><h1>{data.title}</h1><p className="hero-copy">{data.overview}</p><div className="tag-row"><span className="tag red"><span /> Suspicious behavior</span><span className="tag">{data.incidentId}</span><span className="tag">{data.window}</span></div></div><div className="severity"><div className="severity-ring"><ShieldAlert size={30} /><span>—</span></div><div className="severity-value">NOT SCORED</div><div className="severity-note">No severity value in artifact</div></div></div><div className="stats-grid"><StatCard label="EVIDENCE EVENTS" value={String(data.events.length).padStart(2, '0')} detail="network · endpoint · identity" icon={Activity} /><StatCard label="ATT&CK CANDIDATES" value={String(data.mappings.length).padStart(2, '0')} detail="all remain unconfirmed" icon={Hexagon} accent="lime" /><StatCard label="INVESTIGATION TIME" value={data.metrics.totalMs !== null ? `${(data.metrics.totalMs / 1000).toFixed(1)}s` : 'Unavailable'} detail="ADK measured runtime" icon={Clock3} accent="amber" /><StatCard label="GROUNDING CHECK" value={data.metrics.grounded === true ? 'PASS' : data.metrics.grounded === false ? 'FAIL' : 'Unavailable'} detail={`${data.metrics.spans ?? 'Unavailable'} trace spans captured`} icon={CheckCircle2} accent="green" /></div><div className="grid-two"><FindingCard type="network" title="Network findings" icon={Network} text={data.findings.network} onClick={() => jump('evidence')} /><FindingCard type="endpoint" title="Endpoint findings" icon={Terminal} text={data.findings.endpoint} onClick={() => jump('evidence')} /><FindingCard type="identity" title="Identity findings" icon={Fingerprint} text={data.findings.identity} onClick={() => jump('evidence')} /><div className="question-card"><div className="card-kicker">ANALYST QUESTION</div><p>{data.question}</p><div className="question-foot"><span>Source</span><b>{data.source}</b></div></div></div></section> }

function FindingCard({ title, icon: Icon, text, type, onClick }) { return <button className={`finding-card ${type}`} onClick={onClick}><div className="finding-head"><span className="finding-icon"><Icon size={17} /></span><span>{title}</span><ArrowUpRight size={15} /></div><p>{text}</p><div className="read-more">VIEW EVIDENCE <ArrowUpRight size={12} /></div></button> }

function Timeline() { const data = useDashboardData(); return <section id="timeline" className="section"><SectionHeading eyebrow="SEQUENCE OF EVENTS" title="Investigation timeline" copy="The local evidence sequence, ordered by event timestamp." /><div className="timeline-card">{data.events.length ? data.events.map((event, index) => <div className="timeline-event" key={event.id}><div className={`timeline-node ${event.tone}`}><span /></div><div className="timeline-time">{event.time}<small>SEP 09</small></div><div className="timeline-body"><div className="event-title"><span className="event-id">{event.id}</span>{event.title}<span className={`source-chip ${event.source}`}>{event.source}</span><span className={`source-chip ${event.verification_status}`}>{event.verification_status}</span></div><p>{event.detail}</p></div>{index < data.events.length - 1 && <div className="timeline-line" />}</div>) : <EmptyPanel text="No event references are available for this investigation." />}</div></section> }

function Evidence() { const data = useDashboardData(); return <section id="evidence" className="section"><SectionHeading eyebrow="LOCAL EVIDENCE STORE" title="Evidence explorer" copy={`${data.events.length} read-only event references received from the investigation.`} /><div className="filter-row"><div className="filter active">ALL <b>{String(data.events.length).padStart(2, '0')}</b></div><div className="filter">NETWORK <b>{data.events.filter(e => e.source === 'network').length}</b></div><div className="filter">ENDPOINT <b>{data.events.filter(e => e.source === 'endpoint').length}</b></div><div className="filter">IDENTITY <b>{data.events.filter(e => e.source === 'identity').length}</b></div></div><div className="evidence-table">{data.events.length ? <><div className="table-head"><span>EVENT ID</span><span>TIME</span><span>SOURCE</span><span>TRUST</span><span>EVENT</span><span>DETAIL</span></div>{data.events.map(event => <div className="table-row" key={event.id}><span className="mono id-cell">{event.id}</span><span className="mono muted">{event.time}</span><span><span className={`source-chip ${event.source}`}>{event.source}</span></span><span><span className={`source-chip ${event.verification_status}`}>{event.provenance} / {event.verification_status}</span></span><span className="type-cell">{event.type}</span><span className="detail-cell">{event.detail}</span></div>)}</> : <EmptyPanel text="No event references have been returned. Narrative text is not evidence." />}</div></section> }

function Mitre() { const data = useDashboardData(); return <section id="mitre" className="section"><SectionHeading eyebrow="MITRE ATT&CK REFERENCE" title="Candidate mappings" copy="Retrieved knowledge is separate from incident evidence. Every mapping cites actual event IDs." /><div className="callout"><Hexagon size={18} /><span><b>Candidate only.</b> Semantic retrieval does not establish a confirmed technique. Review the supporting event IDs and trust status before escalating.</span></div>{data.mappings.length ? <div className="mitre-grid">{data.mappings.map(mapping => <div className="mitre-card" key={`${mapping.id}-${mapping.source}`}><div className="mitre-top"><span className="technique-id">{mapping.id}</span><span className="candidate-pill">{mapping.status}</span></div><h3>{mapping.name}</h3><div className="mapping-source">{mapping.source}</div><p>{mapping.rationale}</p><div className="mapping-evidence"><span>SUPPORTED BY</span><div>{mapping.evidence.map(id => <span className="evidence-token" key={id}>{id}</span>)}</div></div></div>)}</div> : <EmptyPanel text="No ATT&CK candidate mapping was returned for the available event references." />}</section> }

function EmptyPanel({ text }) { return <div className="empty-panel"><FileSearch size={18} /><span>{text}</span></div> }

function Report() { const data = useDashboardData(); return <section id="report" className="section"><SectionHeading eyebrow="ASSESSMENT ARTIFACT" title="Final incident report" copy="Rendered from the selected run's saved Markdown report." /><div className="report-layout"><div className="report-main"><ReportBlock title="What happened" text={data.report.happened} /><ReportBlock title="Where evidence conflicts" text={data.report.conflict} /><ReportBlock title="Most likely explanation" text={data.report.explanation} /><ReportBlock title="Recommended response" text={data.report.response} /></div><div className="run-card"><div className="card-kicker">EVALUATION SNAPSHOT</div><Metric label="Total runtime" value={data.metrics.totalMs !== null ? `${(data.metrics.totalMs / 1000).toFixed(1)} sec` : 'Unavailable'} /><Metric label="A2A call" value={data.metrics.a2aMs !== null ? `${(data.metrics.a2aMs / 1000).toFixed(1)} sec` : 'Unavailable'} /><Metric label="LLM tokens" value={data.metrics.tokens !== null ? fmt(data.metrics.tokens) : 'Unavailable'} /><Metric label="MCP tool calls" value={data.metrics.mcpCalls !== null ? data.metrics.mcpCalls : 'Unavailable'} /><Metric label="RAG calls" value={data.metrics.ragCalls !== null ? data.metrics.ragCalls : 'Unavailable'} /><div className="run-status"><CheckCircle2 size={15} /> Evidence grounding {data.metrics.grounded === true ? 'passed' : data.metrics.grounded === false ? 'failed' : 'unavailable'}</div><div className="run-path">Read from selected run evaluation artifact</div></div></div></section> }
function ReportBlock({ title, text }) { return <div className="report-block"><h3>{title}</h3><p>{text}</p></div> }
function Metric({ label, value }) { return <div className="metric"><span>{label}</span><b>{value}</b></div> }
function SectionHeading({ eyebrow, title, copy }) { return <div className="section-heading"><div><div className="eyebrow">{eyebrow}</div><h2>{title}</h2><p>{copy}</p></div><div className="heading-rule" /></div> }

function NewInvestigation({ onSubmitted, onBack }) {
  const [incidentJson, setIncidentJson] = React.useState('')
  const [error, setError] = React.useState(null)
  const [submitting, setSubmitting] = React.useState(false)
  const submit = async event => {
    event.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const incident = parseIncidentJson(incidentJson)
      onSubmitted(await submitInvestigation({ incident }))
    } catch (submitError) {
      setError(submitError.message)
      setSubmitting(false)
    }
  }
  return <div className="workflow-screen"><div className="workflow-shell"><div className="workflow-brand"><div className="brand-mark"><Hexagon size={19} /></div><div><div className="brand-name">CYBER<span>RECON</span></div><div className="brand-sub">INVESTIGATION CONSOLE</div></div></div><button className="back-button" onClick={onBack}>← Back to investigations</button><div className="workflow-card"><div className="eyebrow">NEW INVESTIGATION <span className="live-line" /></div><h1>Start a new investigation</h1><p className="workflow-copy">Paste a complete incident JSON record. CyberRecon validates and preserves its structured event references before starting the investigation.</p><form onSubmit={submit}><label className="form-label" htmlFor="incident-json">Incident JSON</label><textarea id="incident-json" value={incidentJson} onChange={event => setIncidentJson(event.target.value)} placeholder={'Paste case-b.json or case-c.json here…'} maxLength={100000} disabled={submitting} spellCheck="false" /><div className="form-meta"><span>Required: id, title, time window, ticket_text and events.</span><span>{incidentJson.length.toLocaleString()} characters</span></div>{error && <div className="form-error"><AlertTriangle size={16} />{error}</div>}<button className="start-button" type="submit" disabled={submitting}>{submitting ? <><Gauge size={16} className="spin" />Creating investigation…</> : <><Send size={16} />Start investigation</>}</button></form><div className="narrative-note"><FileSearch size={17} /><span><b>Trust-aware intake.</b> Submitted events are labeled user_submitted / unverified until independently validated. The original incident ID is replaced with a new investigation ID; seeded cases are not modified.</span></div></div></div></div>
}

function InvestigationProgress({ job, onComplete, onBack, resultError }) {
  const [status, setStatus] = React.useState(job.status || 'pending')
  const [statusError, setStatusError] = React.useState(null)
  React.useEffect(() => {
    let cancelled = false
    let timer
    const poll = async () => {
      try {
        const next = await getInvestigationStatus(job.investigation_id)
        if (cancelled) return
        setStatus(next.status)
        if (next.status === 'completed') {
          onComplete(next)
          return
        }
        if (next.status === 'failed') {
          setStatusError(next.error || 'Investigation failed.')
          return
        }
        timer = window.setTimeout(poll, 1500)
      } catch (pollError) {
        if (!cancelled) setStatusError(pollError.message)
      }
    }
    poll()
    return () => { cancelled = true; window.clearTimeout(timer) }
  }, [job.investigation_id])
  const steps = [
    ['Incident received', 'Input validated and investigation created.', 'completed'],
    ['ADK orchestrator', 'Coordinating specialist agents.', status === 'pending' ? 'pending' : 'completed'],
    ['NetworkAnalyst', 'Investigating suspicious network activity.', status === 'running' ? 'running' : status === 'pending' ? 'pending' : 'completed'],
    ['EndpointAnalyst', 'Examining process and file activity.', status === 'running' ? 'running' : 'pending'],
    ['IdentityAnalyst', 'Checking authentication activity.', status === 'running' ? 'running' : 'pending'],
    ['Evidence reconciliation', 'Correlating findings and validating evidence.', status === 'completed' ? 'completed' : 'pending'],
    ['Final incident report', 'Generating investigation results.', status === 'completed' ? 'completed' : 'pending'],
  ]
  const finalStatus = statusError || resultError ? 'failed' : status
  return <div className="workflow-screen"><div className="workflow-shell progress-shell"><div className="workflow-brand"><div className="brand-mark"><Hexagon size={19} /></div><div><div className="brand-name">CYBER<span>RECON</span></div><div className="brand-sub">INVESTIGATION CONSOLE</div></div></div><div className="workflow-card progress-card"><div className="eyebrow">INVESTIGATION {finalStatus.toUpperCase()} <span className="live-line" /></div><h1>Investigation in progress</h1><p className="workflow-copy">The existing ADK, CrewAI, MCP and evidence-grounding workflow is processing this request.</p><div className="job-id"><span>INVESTIGATION ID</span><b>{job.investigation_id}</b></div><div className="progress-list">{steps.map(([title, copy, stepStatus], index) => <div className={`progress-step ${stepStatus}`} key={title}><div className="progress-marker">{stepStatus === 'completed' ? <CheckCircle2 size={16} /> : stepStatus === 'running' ? <Gauge size={16} className="spin" /> : <span>{index + 1}</span>}</div><div><strong>{title}</strong><p>{copy}</p>{stepStatus === 'running' && <small>Running</small>}</div></div>)}</div>{finalStatus === 'failed' && <div className="form-error"><AlertTriangle size={16} />{statusError || resultError}</div>}{finalStatus === 'completed' && <div className="success-note"><CheckCircle2 size={17} />Investigation results are ready. Loading the dashboard…</div>} {(finalStatus === 'failed' || finalStatus === 'completed') && <button className="back-button progress-back" onClick={onBack}>← Back to investigations</button>}</div></div></div>
}

function App() {
  const [active, setActive] = React.useState('overview')
  const [data, setData] = React.useState(null)
  const [error, setError] = React.useState(null)
  const [loading, setLoading] = React.useState(true)
  const [selectedId, setSelectedId] = React.useState('')
  const [view, setView] = React.useState('dashboard')
  const [job, setJob] = React.useState(null)
  const [resultError, setResultError] = React.useState(null)
  React.useEffect(() => { fetchDashboard().then(result => { setData(result); if (!result.empty) setSelectedId(result.incidentId) }).catch(err => setError(err.message)).finally(() => setLoading(false)) }, [])
  const selectInvestigation = id => { setSelectedId(id); setError(null); setLoading(true); fetchDashboard(id).then(result => setData(result)).catch(err => setError(err.message)).finally(() => setLoading(false)) }
  const startNew = () => { setResultError(null); setView('new') }
  const handleSubmitted = submittedJob => { setJob(submittedJob); setView('progress') }
  const handleComplete = async () => {
    try {
      const result = await fetchDashboard(job.investigation_id)
      setData(result)
      setSelectedId(result.incidentId)
      setView('dashboard')
    } catch (loadError) {
      setResultError(loadError.message)
    }
  }
  const jump = id => { setActive(id); document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' }) }
  React.useEffect(() => { const observer = new IntersectionObserver(entries => entries.forEach(entry => entry.isIntersecting && setActive(entry.target.id)), { rootMargin: '-24% 0px -65% 0px' }); ['overview', 'timeline', 'evidence', 'mitre', 'report'].forEach(id => { const node = document.getElementById(id); if (node) observer.observe(node) }); return () => observer.disconnect() }, [])
  if (view === 'new') return <NewInvestigation onSubmitted={handleSubmitted} onBack={() => setView(data?.empty ? 'new' : 'dashboard')} />
  if (view === 'progress' && job) return <InvestigationProgress job={job} onComplete={handleComplete} onBack={() => setView(data?.empty ? 'new' : 'dashboard')} resultError={resultError} />
  if (loading) return <div className="state-screen"><div className="state-mark"><Gauge size={23} /></div><h2>Loading investigation artifacts</h2><p>Connecting to the local CyberRecon API…</p></div>
  if (error) return <div className="state-screen error"><div className="state-mark"><AlertTriangle size={23} /></div><h2>Dashboard unavailable</h2><p>{error}</p><small>Start the FastAPI server and reload this page.</small></div>
  if (data?.empty) return <NewInvestigation onSubmitted={handleSubmitted} onBack={() => setView('new')} />
  return <DashboardContext.Provider value={data}><div className="app-shell"><Sidebar active={active} onSelect={jump} onNew={startNew} /><main className="main"><Topbar selectedId={selectedId} onChange={selectInvestigation} /><div className="content"><Overview jump={jump} /><Timeline /><Evidence /><Mitre /><Report /><footer>CYBERRECON DASHBOARD <span>•</span> API ARTIFACT MODE <span>•</span> {data.incidentId.toUpperCase()}</footer></div></main></div></DashboardContext.Provider>
}

createRoot(document.getElementById('root')).render(<App />)
